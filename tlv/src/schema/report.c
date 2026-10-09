// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/schema/schema.h"
#include "tlv/reader/reader.h"
#include "diagnostic_internal.h"
#include "traversal_internal.h"
#include "tlv/size.h"
#include <string.h>

static int same_tag(const tlv_tag_t* a, const tlv_tag_t* b) {
    return tlv_tag_equal(*a, *b);
}

typedef struct frame {
    const tlv_structure_schema_t* schema;
    size_t start, end;
    tlv_tag_t tag; /* Tag of the enclosing element; unused for the root frame. */
    size_t offset; /* Offset of the enclosing element; unused for the root frame. */
} frame_t;

typedef struct collector {
    tlv_schema_diagnostic_report_t* diag_report;
    const frame_t* frames;
    size_t depth;
} collector_t;

/* Records one violation with its location and path, and returns the stored
 * entry for kind-specific detail, or NULL once storage is full. */
static tlv_schema_diagnostic_t* add_issue(collector_t* c, tlv_schema_issue_kind_t kind,
                                          const tlv_tag_t* tag, const size_t* offset) {
    tlv_schema_diagnostic_report_t* report = c->diag_report;
    tlv_schema_diagnostic_t* diagnostic;
    if (report->count++ >= report->capacity) return NULL;
    diagnostic = &report->diagnostics[report->count - 1];
    memset(diagnostic, 0, sizeof(*diagnostic));
    tlv_diagnostic_init(&diagnostic->diagnostic, TLV_ERR_SCHEMA, TLV_DIAGNOSTIC_SEVERITY_ERROR);
    if (offset)
        tlv_diagnostic_set_location(&diagnostic->diagnostic, TLV_LOCATION_INPUT, TLV_LOCATION_POINT,
                                    *offset, *offset);
    diagnostic->kind = kind;
    diagnostic->diagnostic.location.kind = !offset ? TLV_LOCATION_UNKNOWN
                                           : kind == TLV_SCHEMA_ISSUE_MISSING
                                               ? TLV_LOCATION_SCOPE_END
                                               : TLV_LOCATION_POINT;
    diagnostic->tag = *tag;
    diagnostic->diagnostic.has_path = 1;
    tlv_diagnostic_path_init(&diagnostic->diagnostic.path);
    for (size_t i = 1; i <= c->depth; ++i) {
        if (tlv_diagnostic_path_push(&diagnostic->diagnostic.path, c->frames[i].tag) ==
            TLV_ERR_BUFFER_TOO_SHORT) {
            diagnostic->diagnostic.path.omitted += c->depth - i;
            break;
        }
    }
    return diagnostic;
}

/* Checks the rule table of a scope and its occurrence counts. */
static tlv_result_t check_scope(const uint8_t* data, const tlv_format_t* format, collector_t* c,
                                const frame_t* frame) {
    tlv_schema_diagnostic_t* issue;
    tlv_result_t rc;

    for (size_t i = 0; i < frame->schema->count; ++i) {
        const tlv_structure_rule_t* rule = &frame->schema->rules[i];
        size_t count = 0, pos = frame->start;
        while (pos < frame->end) {
            tlv_element_t element;
            size_t used;
            rc = tlv_read(data + pos, frame->end - pos, format, &element, &used);
            if (rc != TLV_OK) return rc;
            if (same_tag(&rule->entry->tag, &element.tag) && ++count > rule->max_occurs) {
                issue = add_issue(c, TLV_SCHEMA_ISSUE_DUPLICATE, &element.tag, &pos);
                if (issue) schema_issue_occurs(issue, rule, NULL, count);
            }
            pos += used;
        }
        if (count < rule->min_occurs) {
            issue = add_issue(c, TLV_SCHEMA_ISSUE_MISSING, &rule->entry->tag, &frame->end);
            if (issue) schema_issue_occurs(issue, rule, NULL, count);
        }
    }
    for (size_t g = 0; g < frame->schema->group_count; ++g) {
        const tlv_structure_group_t* group = &frame->schema->groups[g];
        size_t count = 0, pos = frame->start;
        const tlv_tag_t* first_tag = NULL;
        for (size_t i = 0; i < frame->schema->count; ++i)
            if (frame->schema->rules[i].group == group->id) {
                first_tag = &frame->schema->rules[i].entry->tag;
                break;
            }
        while (pos < frame->end) {
            tlv_element_t element;
            size_t used;
            rc = tlv_read(data + pos, frame->end - pos, format, &element, &used);
            if (rc != TLV_OK) return rc;
            for (size_t i = 0; i < frame->schema->count; ++i)
                if (frame->schema->rules[i].group == group->id &&
                    same_tag(&frame->schema->rules[i].entry->tag, &element.tag)) {
                    if (++count > group->max_occurs) {
                        issue = add_issue(c, TLV_SCHEMA_ISSUE_DUPLICATE, &element.tag, &pos);
                        if (issue) schema_issue_occurs(issue, NULL, group, count);
                    }
                    break;
                }
            pos += used;
        }
        if (count < group->min_occurs) {
            issue = add_issue(c, TLV_SCHEMA_ISSUE_MISSING, first_tag, &frame->end);
            if (issue) schema_issue_occurs(issue, NULL, group, count);
        }
    }
    if (frame->schema->order == TLV_SCHEMA_ORDER_SEQUENCE) {
        size_t pos = frame->start;
        size_t last_index = 0;
        int have_last = 0;
        while (pos < frame->end) {
            tlv_element_t element;
            size_t used;
            rc = tlv_read(data + pos, frame->end - pos, format, &element, &used);
            if (rc != TLV_OK) return rc;
            for (size_t i = 0; i < frame->schema->count; ++i)
                if (same_tag(&frame->schema->rules[i].entry->tag, &element.tag)) {
                    if (have_last && i < last_index) {
                        issue = add_issue(c, TLV_SCHEMA_ISSUE_ORDER, &element.tag, &pos);
                        if (issue) issue->field = frame->schema->rules[i].entry->name;
                    } else {
                        last_index = i;
                    }
                    have_last = 1;
                    break;
                }
            pos += used;
        }
    }
    return TLV_OK;
}

static tlv_result_t validate_all(const uint8_t* data, size_t size, const tlv_format_t* format,
                                 const tlv_structure_schema_t* schema, size_t max_depth,
                                 size_t max_elements, tlv_schema_unknown_policy_t unknown,
                                 collector_t* c, tlv_diagnostic_t* diagnostic) {
    frame_t stack[TLV_SCHEMA_MAX_DEPTH + 1];
    tlv_tree_frame_t frames[TLV_SCHEMA_MAX_DEPTH];
    tlv_tree_reader_t reader;
    tlv_result_t rc = schema_check_tree(data, size, format, max_depth, max_elements, diagnostic);
    if (rc != TLV_OK) return rc;
    memset(stack, 0, sizeof(stack));
    stack[0].schema = schema;
    stack[0].end = size;
    c->frames = stack;
    c->depth = 0;
    rc = check_scope(data, format, c, &stack[0]);
    if (rc != TLV_OK) return rc;
    rc = tlv_tree_reader_init(&reader, data, size, format, frames, TLV_SCHEMA_MAX_DEPTH, max_depth,
                              max_elements);
    if (rc != TLV_OK) return rc;
    while (!tlv_tree_reader_at_end(&reader)) {
        tlv_tree_item_t item;
        rc = tlv_tree_reader_next(&reader, &item);
        if (rc != TLV_OK) return rc;
        c->depth = item.depth;
        const tlv_structure_schema_t* current = stack[c->depth].schema;
        {
            tlv_element_t element = item.element;
            size_t pos = item.offset, value_length;
            const tlv_structure_rule_t* rule = NULL;
            int constructed, kind_ok;
            for (size_t i = 0; i < current->count; ++i)
                if (same_tag(&current->rules[i].entry->tag, &element.tag)) {
                    rule = &current->rules[i];
                    break;
                }
            if (!rule) {
                if (unknown == TLV_SCHEMA_UNKNOWN_REJECT ||
                    (unknown == TLV_SCHEMA_UNKNOWN_BY_SCHEMA && !current->allow_unknown))
                    (void)add_issue(c, TLV_SCHEMA_ISSUE_UNEXPECTED, &element.tag, &pos);
                if (item.constructed && item.element.value.size)
                    (void)tlv_tree_reader_skip_subtree(&reader);
                continue;
            }
            rc = tlv_size_to_native(element.value.size, &value_length);
            if (rc != TLV_OK) return rc;
            if (tlv_schema_validate_length(rule->entry, value_length) != TLV_OK) {
                tlv_schema_diagnostic_t* issue =
                    add_issue(c, TLV_SCHEMA_ISSUE_LENGTH, &element.tag, &pos);
                if (issue) schema_issue_length(issue, rule, value_length);
            }
            constructed =
                format->is_constructed && format->is_constructed(format->context, &element.tag);
            kind_ok = !((rule->kind == TLV_SCHEMA_PRIMITIVE && constructed) ||
                        (rule->kind == TLV_SCHEMA_CONSTRUCTED && !constructed));
            if (!kind_ok) {
                tlv_schema_diagnostic_t* issue =
                    add_issue(c, TLV_SCHEMA_ISSUE_KIND, &element.tag, &pos);
                if (issue) schema_issue_form(issue, rule, constructed);
            }
            if (kind_ok && rule->children) {
                size_t start = (size_t)(element.value.data - data);
                if (c->depth == TLV_SCHEMA_MAX_DEPTH) {
                    if (diagnostic)
                        tlv_diagnostic_set_location(diagnostic, TLV_LOCATION_INPUT,
                                                    TLV_LOCATION_POINT, pos, pos);
                    return TLV_ERR_LIMIT;
                }
                ++c->depth;
                stack[c->depth] =
                    (frame_t){rule->children, start, start + value_length, element.tag, pos};
                rc = check_scope(data, format, c, &stack[c->depth]);
                if (rc != TLV_OK) return rc;
            } else if (item.constructed && item.element.value.size) {
                (void)tlv_tree_reader_skip_subtree(&reader);
            }
        }
    }
    return c->diag_report->count ? TLV_ERR_SCHEMA : TLV_OK;
}

/* Collects violations against a schema whose definition has already been checked. */
static tlv_result_t report_checked(const uint8_t* data, size_t size, const tlv_format_t* format,
                                   const tlv_structure_schema_t* schema, size_t max_depth,
                                   size_t max_elements, tlv_schema_unknown_policy_t unknown,
                                   tlv_schema_diagnostic_report_t* report,
                                   tlv_schema_diagnostic_t* diagnostic) {
    tlv_result_t rc;
    collector_t c;
    memset(&c, 0, sizeof(c));
    c.diag_report = report;
    rc = validate_all(data, size, format, schema, max_depth, max_elements, unknown, &c,
                      diagnostic ? &diagnostic->diagnostic : NULL);
    if (diagnostic) diagnostic->diagnostic.code = rc;
    if (rc != TLV_OK && rc != TLV_ERR_SCHEMA) report->count = 0;
    return rc;
}

tlv_result_t tlv_schema_validate_all_diag(const uint8_t* data, size_t size,
                                          const tlv_format_t* format,
                                          const tlv_structure_schema_t* schema, size_t max_depth,
                                          size_t max_elements, tlv_schema_unknown_policy_t unknown,
                                          tlv_schema_diagnostic_report_t* report,
                                          tlv_schema_diagnostic_t* diagnostic) {
    tlv_result_t rc;
    if (!report) return TLV_ERR_NULL_ARG;
    report->count = 0;
    if (!schema || (!report->diagnostics && report->capacity)) return TLV_ERR_NULL_ARG;
    if (unknown < TLV_SCHEMA_UNKNOWN_BY_SCHEMA || unknown > TLV_SCHEMA_UNKNOWN_REJECT)
        return TLV_ERR_INVALID_ARG;
    if (diagnostic) tlv_schema_diagnostic_init(diagnostic);
    rc = tlv_schema_check(schema, diagnostic);
    if (rc != TLV_OK) return rc;
    return report_checked(data, size, format, schema, max_depth, max_elements, unknown, report,
                          diagnostic);
}

tlv_result_t tlv_schema_validate_all_checked(const tlv_schema_checked_t* checked,
                                             const uint8_t* data, size_t size,
                                             const tlv_format_t* format, size_t max_depth,
                                             size_t max_elements,
                                             tlv_schema_unknown_policy_t unknown,
                                             tlv_schema_diagnostic_report_t* report,
                                             tlv_schema_diagnostic_t* diagnostic) {
    if (!report) return TLV_ERR_NULL_ARG;
    report->count = 0;
    if (!checked || (!report->diagnostics && report->capacity)) return TLV_ERR_NULL_ARG;
    if (unknown < TLV_SCHEMA_UNKNOWN_BY_SCHEMA || unknown > TLV_SCHEMA_UNKNOWN_REJECT)
        return TLV_ERR_INVALID_ARG;
    if (!checked->schema) return TLV_ERR_INVALID_STATE;
    if (diagnostic) tlv_schema_diagnostic_init(diagnostic);
    return report_checked(data, size, format, checked->schema, max_depth, max_elements, unknown,
                          report, diagnostic);
}
