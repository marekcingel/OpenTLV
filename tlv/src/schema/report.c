#include "tlv/schema/schema.h"
#include "tlv/reader/reader.h"
#include "tlv/reader/walker.h"
#include "tlv/length.h"
#include <string.h>

static int same_tag(const tlv_tag_t* a, const tlv_tag_t* b) {
    return tlv_tag_equal(*a, *b);
}

typedef struct frame {
    const tlv_structure_schema_t* schema;
    size_t start, end, pos;
    tlv_tag_t tag; /* Tag of the enclosing element; unused for the root frame. */
    size_t offset; /* Offset of the enclosing element; unused for the root frame. */
    int checked;
} frame_t;

typedef struct collector {
    tlv_schema_report_t* report;
    tlv_schema_diagnostic_report_t* diag_report;
    const frame_t* frames;
    size_t depth;
    size_t violations;
} collector_t;

/* Expected-versus-actual detail for one violation, filled only for the kinds
 * it applies to; `rule` is the matched rule, or NULL for
 * TLV_SCHEMA_ISSUE_UNEXPECTED, which has none. For a group-level MISSING or
 * DUPLICATE, `group` is set instead of `rule`. */
typedef struct violation_detail {
    const tlv_structure_rule_t* rule;
    int has_occurs;
    size_t occurs;
    int has_length;
    size_t actual_length;
    int has_form;
    int actual_constructed;
    const tlv_structure_group_t* group;
} violation_detail_t;

static tlv_result_t code_for_kind(tlv_schema_issue_kind_t kind) {
    switch (kind) {
        case TLV_SCHEMA_ISSUE_MISSING: return TLV_ERR_SCHEMA_MISSING;
        case TLV_SCHEMA_ISSUE_LENGTH: return TLV_ERR_INVALID_LENGTH;
        default: return TLV_ERR_SCHEMA;
    }
}

static void add_legacy_issue(collector_t* c, tlv_schema_issue_kind_t kind, const tlv_tag_t* tag,
                             const size_t* offset) {
    tlv_schema_report_t* report = c->report;
    tlv_schema_issue_t* issue;
    if (report->count++ >= report->capacity) return;
    issue = &report->issues[report->count - 1];
    memset(issue, 0, sizeof(*issue));
    issue->kind = kind;
    for (size_t i = 1; i <= c->depth; ++i) issue->path[issue->path_length++] = c->frames[i].tag;
    issue->path[issue->path_length++] = *tag;
    if (offset) {
        issue->has_offset = 1;
        issue->offset = *offset;
    }
}

static void add_diagnostic(collector_t* c, tlv_schema_issue_kind_t kind, const tlv_tag_t* tag,
                           const size_t* offset, const violation_detail_t* detail) {
    tlv_schema_diagnostic_report_t* report = c->diag_report;
    tlv_schema_diagnostic_t* diagnostic;
    if (report->count++ >= report->capacity) return;
    diagnostic = &report->diagnostics[report->count - 1];
    memset(diagnostic, 0, sizeof(*diagnostic));
    tlv_diagnostic_init(&diagnostic->diagnostic, code_for_kind(kind),
                        TLV_DIAGNOSTIC_SEVERITY_ERROR);
    if (offset) tlv_diagnostic_set_offset(&diagnostic->diagnostic, *offset);
    diagnostic->kind = kind;
    diagnostic->tag = *tag;
    tlv_diagnostic_path_init(&diagnostic->path);
    for (size_t i = 1; i <= c->depth; ++i)
        (void)tlv_diagnostic_path_push(&diagnostic->path, c->frames[i].tag);
    if (detail && detail->group) {
        const tlv_structure_group_t* group = detail->group;
        diagnostic->field = group->name;
        diagnostic->is_group = 1;
        if (detail->has_occurs) {
            diagnostic->has_occurs = 1;
            diagnostic->min_occurs = group->min_occurs;
            diagnostic->max_occurs = group->max_occurs;
            diagnostic->occurs = detail->occurs;
        }
    } else if (detail && detail->rule) {
        const tlv_structure_rule_t* rule = detail->rule;
        diagnostic->field = rule->entry.name;
        if (detail->has_occurs) {
            diagnostic->has_occurs = 1;
            diagnostic->min_occurs = rule->min_occurs;
            diagnostic->max_occurs = rule->max_occurs;
            diagnostic->occurs = detail->occurs;
        }
        if (detail->has_length) {
            diagnostic->has_length = 1;
            diagnostic->min_length = rule->entry.min_length;
            diagnostic->max_length = rule->entry.max_length;
            diagnostic->actual_length = detail->actual_length;
        }
        if (detail->has_form) {
            diagnostic->has_form = 1;
            diagnostic->expected_form = rule->kind;
            diagnostic->actual_constructed = detail->actual_constructed;
        }
    }
}

/* Records one violation in whichever of the two report styles the caller
 * asked for (`c->report`, `c->diag_report`, or both). `detail` may be NULL
 * for a violation with no expected/actual detail (TLV_SCHEMA_ISSUE_UNEXPECTED). */
static void add_issue(collector_t* c, tlv_schema_issue_kind_t kind, const tlv_tag_t* tag,
                      const size_t* offset, const violation_detail_t* detail) {
    ++c->violations;
    if (c->report) add_legacy_issue(c, kind, tag, offset);
    if (c->diag_report) add_diagnostic(c, kind, tag, offset, detail);
}

static int group_index(const tlv_structure_schema_t* schema, uint32_t id) {
    for (size_t g = 0; g < schema->group_count; ++g)
        if (schema->groups[g].id == id) return (int)g;
    return -1;
}

static tlv_result_t check_table(const tlv_structure_schema_t* schema) {
    if (!schema->rules && schema->count) return TLV_ERR_INVALID_ARG;
    if (!schema->groups && schema->group_count) return TLV_ERR_INVALID_ARG;
    if (schema->order != TLV_SCHEMA_ORDER_ANY && schema->order != TLV_SCHEMA_ORDER_SEQUENCE)
        return TLV_ERR_INVALID_ARG;
    for (size_t g = 0; g < schema->group_count; ++g) {
        const tlv_structure_group_t* group = &schema->groups[g];
        int has_member = 0;
        if (!group->id || group->min_occurs > group->max_occurs) return TLV_ERR_INVALID_ARG;
        for (size_t h = 0; h < g; ++h)
            if (schema->groups[h].id == group->id) return TLV_ERR_INVALID_ARG;
        for (size_t i = 0; i < schema->count; ++i)
            if (schema->rules[i].group == group->id) has_member = 1;
        if (!has_member) return TLV_ERR_INVALID_ARG;
    }
    for (size_t i = 0; i < schema->count; ++i) {
        const tlv_structure_rule_t* rule = &schema->rules[i];
        if (!rule->entry.tag.size || !rule->entry.tag.data ||
            rule->entry.min_length > rule->entry.max_length ||
            rule->min_occurs > rule->max_occurs || rule->kind < TLV_SCHEMA_ANY ||
            rule->kind > TLV_SCHEMA_CONSTRUCTED ||
            (rule->children && rule->kind != TLV_SCHEMA_CONSTRUCTED) ||
            (rule->group && group_index(schema, rule->group) < 0) ||
            (rule->group && rule->min_occurs != 0))
            return TLV_ERR_INVALID_ARG;
        for (size_t j = 0; j < i; ++j)
            if (same_tag(&rule->entry.tag, &schema->rules[j].entry.tag)) return TLV_ERR_INVALID_ARG;
    }
    return TLV_OK;
}

/* Checks the rule table of a scope and its occurrence counts. */
static tlv_result_t check_scope(const uint8_t* data, const tlv_reader_format_t* format,
                                collector_t* c, const frame_t* frame) {
    tlv_result_t rc = check_table(frame->schema);
    if (rc != TLV_OK) return rc;
    for (size_t i = 0; i < frame->schema->count; ++i) {
        const tlv_structure_rule_t* rule = &frame->schema->rules[i];
        size_t count = 0, pos = frame->start;
        while (pos < frame->end) {
            tlv_view_t view;
            size_t used;
            rc = tlv_read(data + pos, frame->end - pos, format, &view, &used);
            if (rc != TLV_OK) return rc;
            if (same_tag(&rule->entry.tag, &view.tag) && ++count > rule->max_occurs) {
                violation_detail_t detail = {rule, 1, count, 0, 0, 0, 0};
                add_issue(c, TLV_SCHEMA_ISSUE_DUPLICATE, &view.tag, &pos, &detail);
            }
            pos += used;
        }
        if (count < rule->min_occurs) {
            violation_detail_t detail = {rule, 1, count, 0, 0, 0, 0};
            add_issue(c, TLV_SCHEMA_ISSUE_MISSING, &rule->entry.tag,
                      c->depth ? &frame->offset : NULL, &detail);
        }
    }
    for (size_t g = 0; g < frame->schema->group_count; ++g) {
        const tlv_structure_group_t* group = &frame->schema->groups[g];
        size_t count = 0, pos = frame->start;
        const tlv_tag_t* first_tag = NULL;
        for (size_t i = 0; i < frame->schema->count; ++i)
            if (frame->schema->rules[i].group == group->id) {
                first_tag = &frame->schema->rules[i].entry.tag;
                break;
            }
        while (pos < frame->end) {
            tlv_view_t view;
            size_t used;
            rc = tlv_read(data + pos, frame->end - pos, format, &view, &used);
            if (rc != TLV_OK) return rc;
            for (size_t i = 0; i < frame->schema->count; ++i)
                if (frame->schema->rules[i].group == group->id &&
                    same_tag(&frame->schema->rules[i].entry.tag, &view.tag)) {
                    if (++count > group->max_occurs) {
                        violation_detail_t detail = {NULL, 1, count, 0, 0, 0, 0, group};
                        add_issue(c, TLV_SCHEMA_ISSUE_DUPLICATE, &view.tag, &pos, &detail);
                    }
                    break;
                }
            pos += used;
        }
        if (count < group->min_occurs) {
            violation_detail_t detail = {NULL, 1, count, 0, 0, 0, 0, group};
            add_issue(c, TLV_SCHEMA_ISSUE_MISSING, first_tag, c->depth ? &frame->offset : NULL,
                      &detail);
        }
    }
    if (frame->schema->order == TLV_SCHEMA_ORDER_SEQUENCE) {
        size_t pos = frame->start;
        size_t last_index = 0;
        int have_last = 0;
        while (pos < frame->end) {
            tlv_view_t view;
            size_t used;
            rc = tlv_read(data + pos, frame->end - pos, format, &view, &used);
            if (rc != TLV_OK) return rc;
            for (size_t i = 0; i < frame->schema->count; ++i)
                if (same_tag(&frame->schema->rules[i].entry.tag, &view.tag)) {
                    if (have_last && i < last_index) {
                        violation_detail_t detail = {&frame->schema->rules[i], 0, 0, 0, 0, 0, 0};
                        add_issue(c, TLV_SCHEMA_ISSUE_ORDER, &view.tag, &pos, &detail);
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

static tlv_result_t validate_all(const uint8_t* data, size_t size,
                                 const tlv_reader_format_t* format,
                                 tlv_is_constructed_fn is_constructed,
                                 const tlv_structure_schema_t* schema, size_t max_depth,
                                 size_t max_elements, tlv_schema_unknown_policy_t unknown,
                                 collector_t* c, size_t* error_offset) {
    frame_t stack[TLV_SCHEMA_PATH_MAX];
    tlv_result_t rc = tlv_walk_tree(data, size, format, is_constructed, max_depth, max_elements,
                                    NULL, NULL, error_offset);
    if (rc != TLV_OK) return rc;
    memset(stack, 0, sizeof(stack));
    stack[0].schema = schema;
    stack[0].end = size;
    c->frames = stack;
    c->depth = 0;
    for (;;) {
        frame_t* frame = &stack[c->depth];
        const tlv_structure_schema_t* current = frame->schema;
        if (!frame->checked) {
            rc = check_scope(data, format, c, frame);
            if (rc != TLV_OK) return rc;
            frame->checked = 1;
        }
        if (frame->pos == frame->end) {
            if (!c->depth) break;
            --c->depth;
            continue;
        }
        {
            tlv_view_t view;
            size_t used, pos = frame->pos, value_length;
            const tlv_structure_rule_t* rule = NULL;
            int constructed, kind_ok;
            rc = tlv_read(data + pos, frame->end - pos, format, &view, &used);
            if (rc != TLV_OK) return rc;
            frame->pos += used;
            for (size_t i = 0; i < current->count; ++i)
                if (same_tag(&current->rules[i].entry.tag, &view.tag)) {
                    rule = &current->rules[i];
                    break;
                }
            if (!rule) {
                if (unknown == TLV_SCHEMA_UNKNOWN_REJECT ||
                    (unknown == TLV_SCHEMA_UNKNOWN_BY_SCHEMA && !current->allow_unknown))
                    add_issue(c, TLV_SCHEMA_ISSUE_UNEXPECTED, &view.tag, &pos, NULL);
                continue;
            }
            rc = tlv_length_to_size(view.value.length, &value_length);
            if (rc != TLV_OK) return rc;
            if (tlv_schema_validate_length(&rule->entry, value_length) != TLV_OK) {
                violation_detail_t detail = {rule, 0, 0, 1, value_length, 0, 0};
                add_issue(c, TLV_SCHEMA_ISSUE_LENGTH, &view.tag, &pos, &detail);
            }
            constructed = is_constructed && is_constructed(format->context, &view.tag);
            kind_ok = !((rule->kind == TLV_SCHEMA_PRIMITIVE && constructed) ||
                        (rule->kind == TLV_SCHEMA_CONSTRUCTED && !constructed));
            if (!kind_ok) {
                violation_detail_t detail = {rule, 0, 0, 0, 0, 1, constructed};
                add_issue(c, TLV_SCHEMA_ISSUE_KIND, &view.tag, &pos, &detail);
            }
            if (kind_ok && rule->children) {
                size_t start = (size_t)(view.value.data - data);
                if (c->depth + 1 >= TLV_SCHEMA_PATH_MAX) {
                    if (error_offset) *error_offset = pos;
                    return TLV_ERR_LIMIT;
                }
                ++c->depth;
                stack[c->depth] =
                    (frame_t){rule->children, start, start + value_length, start, view.tag, pos, 0};
            }
        }
    }
    return c->violations ? TLV_ERR_SCHEMA : TLV_OK;
}

tlv_result_t tlv_schema_validate_all(const uint8_t* data, size_t size,
                                     const tlv_reader_format_t* format,
                                     tlv_is_constructed_fn is_constructed,
                                     const tlv_structure_schema_t* schema, size_t max_depth,
                                     size_t max_elements, tlv_schema_unknown_policy_t unknown,
                                     tlv_schema_report_t* report, size_t* error_offset) {
    tlv_result_t rc;
    collector_t c;
    if (!report) return TLV_ERR_NULL_ARG;
    report->count = 0;
    if (!schema || (!report->issues && report->capacity)) return TLV_ERR_NULL_ARG;
    if (unknown < TLV_SCHEMA_UNKNOWN_BY_SCHEMA || unknown > TLV_SCHEMA_UNKNOWN_REJECT)
        return TLV_ERR_INVALID_ARG;
    memset(&c, 0, sizeof(c));
    c.report = report;
    rc = validate_all(data, size, format, is_constructed, schema, max_depth, max_elements, unknown,
                      &c, error_offset);
    if (rc != TLV_OK && rc != TLV_ERR_SCHEMA) report->count = 0;
    return rc;
}

tlv_result_t tlv_schema_validate_all_diag(const uint8_t* data, size_t size,
                                          const tlv_reader_format_t* format,
                                          tlv_is_constructed_fn is_constructed,
                                          const tlv_structure_schema_t* schema, size_t max_depth,
                                          size_t max_elements, tlv_schema_unknown_policy_t unknown,
                                          tlv_schema_diagnostic_report_t* report,
                                          size_t* error_offset) {
    tlv_result_t rc;
    collector_t c;
    if (!report) return TLV_ERR_NULL_ARG;
    report->count = 0;
    if (!schema || (!report->diagnostics && report->capacity)) return TLV_ERR_NULL_ARG;
    if (unknown < TLV_SCHEMA_UNKNOWN_BY_SCHEMA || unknown > TLV_SCHEMA_UNKNOWN_REJECT)
        return TLV_ERR_INVALID_ARG;
    memset(&c, 0, sizeof(c));
    c.diag_report = report;
    rc = validate_all(data, size, format, is_constructed, schema, max_depth, max_elements, unknown,
                      &c, error_offset);
    if (rc != TLV_OK && rc != TLV_ERR_SCHEMA) report->count = 0;
    return rc;
}

void tlv_schema_diagnostic_init(tlv_schema_diagnostic_t* diagnostic) {
    if (!diagnostic) return;
    memset(diagnostic, 0, sizeof(*diagnostic));
}

const char* tlv_schema_issue_kind_string(tlv_schema_issue_kind_t kind) {
    switch (kind) {
        case TLV_SCHEMA_ISSUE_MISSING: return "missing";
        case TLV_SCHEMA_ISSUE_DUPLICATE: return "duplicate";
        case TLV_SCHEMA_ISSUE_UNEXPECTED: return "unexpected";
        case TLV_SCHEMA_ISSUE_KIND: return "kind";
        case TLV_SCHEMA_ISSUE_LENGTH: return "length";
        case TLV_SCHEMA_ISSUE_ORDER: return "order";
    }
    return "unknown";
}

tlv_result_t tlv_schema_issue_path_string(const tlv_schema_issue_t* issue, char* out,
                                          size_t capacity, size_t* length) {
    static const char hex[] = "0123456789ABCDEF";
    size_t needed = 0;
    if (!issue || (!out && capacity)) return TLV_ERR_NULL_ARG;
    if (!issue->path_length || issue->path_length > TLV_SCHEMA_PATH_MAX) return TLV_ERR_INVALID_ARG;
    for (size_t i = 0; i < issue->path_length; ++i) {
        const tlv_tag_t* tag = &issue->path[i];
        if (!tag->size || !tag->data) return TLV_ERR_INVALID_ARG;
        for (size_t j = 0; j < tag->size; ++j) {
            if (needed + 2 < capacity) {
                out[needed] = hex[tag->data[j] >> 4];
                out[needed + 1] = hex[tag->data[j] & 0x0F];
            }
            needed += 2;
        }
        if (i + 1 < issue->path_length) {
            if (needed + 1 < capacity) out[needed] = '/';
            ++needed;
        }
    }
    if (length) *length = needed;
    if (needed + 1 > capacity) {
        if (capacity) out[0] = '\0';
        return TLV_ERR_BUFFER_TOO_SHORT;
    }
    out[needed] = '\0';
    return TLV_OK;
}
