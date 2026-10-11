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

/* Records a schema violation of `tag` at `offset`. `path` holds the tags of the
 * enclosing modelled elements at indices 1..depth. MISSING anchors at the end
 * of the enclosing scope, not at an element. */
static tlv_result_t violation(tlv_schema_diagnostic_t* diagnostic, tlv_schema_issue_kind_t kind,
                              const tlv_tag_t* tag, size_t offset, const tlv_tag_t* path,
                              size_t depth) {
    if (!diagnostic) return TLV_ERR_SCHEMA;
    tlv_diagnostic_set_location(&diagnostic->diagnostic, TLV_LOCATION_INPUT,
                                kind == TLV_SCHEMA_ISSUE_MISSING ? TLV_LOCATION_SCOPE_END
                                                                 : TLV_LOCATION_POINT,
                                offset, offset);
    diagnostic->detail.kind = kind;
    diagnostic->detail.tag = *tag;
    diagnostic->diagnostic.has_path = 1;
    tlv_diagnostic_path_init(&diagnostic->diagnostic.path);
    /* Pushing past capacity keeps the outer tags and counts the omitted ones. */
    for (size_t i = 1; i <= depth; ++i)
        (void)tlv_diagnostic_path_push(&diagnostic->diagnostic.path, path[i]);
    return TLV_ERR_SCHEMA;
}

static void set_read_location(tlv_diagnostic_t* location, size_t offset) {
    if (location)
        tlv_diagnostic_set_location(location, TLV_LOCATION_INPUT, TLV_LOCATION_POINT, offset,
                                    offset);
}

static tlv_result_t check_scope(const uint8_t* data, const tlv_format_t* format,
                                const tlv_structure_schema_t* current, size_t start, size_t end,
                                const tlv_tag_t* path, size_t depth, tlv_diagnostic_t* location,
                                tlv_schema_diagnostic_t* diagnostic) {
    for (size_t i = 0; i < current->count; ++i) {
        const tlv_structure_rule_t* rule = &current->rules[i];
        size_t count = 0, pos = start;
        while (pos < end) {
            tlv_element_t element;
            size_t used;
            tlv_result_t rc = tlv_read(data + pos, end - pos, format, &element, &used);
            if (rc != TLV_OK) {
                set_read_location(location, pos);
                return rc;
            }
            if (same_tag(&rule->entry->tag, &element.tag)) {
                if (count == rule->max_occurs) {
                    if (diagnostic) schema_issue_occurs(diagnostic, rule, NULL, count + 1);
                    return violation(diagnostic, TLV_SCHEMA_ISSUE_DUPLICATE, &element.tag, pos,
                                     path, depth);
                }
                ++count;
            }
            pos += used;
        }
        if (count < rule->min_occurs) {
            if (diagnostic) schema_issue_occurs(diagnostic, rule, NULL, count);
            return violation(diagnostic, TLV_SCHEMA_ISSUE_MISSING, &rule->entry->tag, end, path,
                             depth);
        }
    }
    for (size_t g = 0; g < current->group_count; ++g) {
        const tlv_structure_group_t* group = &current->groups[g];
        size_t count = 0, pos = start;
        while (pos < end) {
            tlv_element_t element;
            size_t used;
            tlv_result_t rc = tlv_read(data + pos, end - pos, format, &element, &used);
            if (rc != TLV_OK) {
                set_read_location(location, pos);
                return rc;
            }
            for (size_t i = 0; i < current->count; ++i)
                if (current->rules[i].group == group->id &&
                    same_tag(&current->rules[i].entry->tag, &element.tag)) {
                    if (count == group->max_occurs) {
                        if (diagnostic) schema_issue_occurs(diagnostic, NULL, group, count + 1);
                        return violation(diagnostic, TLV_SCHEMA_ISSUE_DUPLICATE, &element.tag, pos,
                                         path, depth);
                    }
                    ++count;
                    break;
                }
            pos += used;
        }
        if (count < group->min_occurs) {
            size_t first = 0;
            while (current->rules[first].group != group->id) ++first;
            if (diagnostic) schema_issue_occurs(diagnostic, NULL, group, count);
            return violation(diagnostic, TLV_SCHEMA_ISSUE_MISSING,
                             &current->rules[first].entry->tag, end, path, depth);
        }
    }
    if (current->order == TLV_SCHEMA_ORDER_SEQUENCE) {
        size_t pos = start;
        size_t last_index = 0;
        int have_last = 0;
        while (pos < end) {
            tlv_element_t element;
            size_t used;
            tlv_result_t rc = tlv_read(data + pos, end - pos, format, &element, &used);
            if (rc != TLV_OK) {
                set_read_location(location, pos);
                return rc;
            }
            for (size_t i = 0; i < current->count; ++i)
                if (same_tag(&current->rules[i].entry->tag, &element.tag)) {
                    if (have_last && i < last_index) {
                        if (diagnostic) diagnostic->detail.field = current->rules[i].entry->name;
                        return violation(diagnostic, TLV_SCHEMA_ISSUE_ORDER, &element.tag, pos,
                                         path, depth);
                    }
                    last_index = i;
                    have_last = 1;
                    break;
                }
            pos += used;
        }
    }
    return TLV_OK;
}

static tlv_result_t validate_input(const uint8_t* data, size_t size, const tlv_format_t* format,
                                   const tlv_structure_schema_t* schema, size_t max_depth,
                                   size_t max_elements, tlv_diagnostic_t* location,
                                   tlv_schema_diagnostic_t* diagnostic) {
    const tlv_structure_schema_t* scopes[TLV_SCHEMA_MAX_DEPTH + 1];
    /* path[d] is the tag enclosing scopes[d]; one extra slot holds the element
     * whose children are checked before the depth limit applies. */
    tlv_tag_t path[TLV_SCHEMA_MAX_DEPTH + 2];
    tlv_tree_frame_t frames[TLV_SCHEMA_MAX_DEPTH];
    tlv_tree_reader_t reader;
    tlv_result_t rc;
    if (!schema) {
        if (location)
            tlv_diagnostic_set_location(location, TLV_LOCATION_INPUT, TLV_LOCATION_POINT, 0, 0);
        return TLV_ERR_NULL_ARG;
    }
    rc = schema_check_tree(data, size, format, max_depth, max_elements, location);
    if (rc != TLV_OK) return rc;
    rc = check_scope(data, format, schema, 0, size, path, 0, location, diagnostic);
    if (rc != TLV_OK) return rc;
    rc = tlv_tree_reader_init(&reader, data, size, format, frames, TLV_SCHEMA_MAX_DEPTH, max_depth,
                              max_elements);
    if (rc != TLV_OK) return rc;
    scopes[0] = schema;
    while (!tlv_tree_reader_at_end(&reader)) {
        tlv_tree_item_t item;
        const tlv_structure_rule_t* rule = NULL;
        const tlv_structure_schema_t* current;
        size_t value_length;
        rc = tlv_tree_reader_next(&reader, &item);
        if (rc != TLV_OK) {
            if (location)
                tlv_diagnostic_set_location(location, TLV_LOCATION_INPUT, TLV_LOCATION_POINT,
                                            tlv_tree_reader_offset(&reader),
                                            tlv_tree_reader_offset(&reader));
            return rc;
        }
        current = scopes[item.depth];
        for (size_t i = 0; i < current->count; ++i)
            if (same_tag(&current->rules[i].entry->tag, &item.element.tag)) {
                rule = &current->rules[i];
                break;
            }
        if (!rule) {
            if (!current->allow_unknown)
                return violation(diagnostic, TLV_SCHEMA_ISSUE_UNEXPECTED, &item.element.tag,
                                 item.offset, path, item.depth);
        } else {
            rc = tlv_size_to_native(item.element.value.size, &value_length);
            if (rc == TLV_OK) rc = tlv_schema_validate_length(rule->entry, value_length);
            if (rc == TLV_ERR_SCHEMA) {
                if (diagnostic) schema_issue_length(diagnostic, rule, value_length);
                return violation(diagnostic, TLV_SCHEMA_ISSUE_LENGTH, &item.element.tag,
                                 item.offset, path, item.depth);
            }
            if (rc != TLV_OK) {
                set_read_location(location, item.offset);
                return rc;
            }
            if ((rule->kind == TLV_SCHEMA_PRIMITIVE && item.constructed) ||
                (rule->kind == TLV_SCHEMA_CONSTRUCTED && !item.constructed)) {
                if (diagnostic) schema_issue_form(diagnostic, rule, item.constructed);
                return violation(diagnostic, TLV_SCHEMA_ISSUE_KIND, &item.element.tag, item.offset,
                                 path, item.depth);
            }
            if (rule->children) {
                size_t start = item.offset + item.source.value.offset;
                path[item.depth + 1] = item.element.tag;
                rc = check_scope(data, format, rule->children, start, start + value_length, path,
                                 item.depth + 1, location, diagnostic);
                if (rc != TLV_OK) return rc;
                if (value_length) {
                    if (item.depth == TLV_SCHEMA_MAX_DEPTH) return TLV_ERR_LIMIT;
                    scopes[item.depth + 1] = rule->children;
                    continue;
                }
            }
        }
        /* Framing has already been validated, including unmodelled descendants. */
        if (item.constructed && item.element.value.size) {
            rc = tlv_tree_reader_skip_subtree(&reader);
            if (rc != TLV_OK) return rc;
        }
    }
    return TLV_OK;
}

/* Validates input against a schema whose definition has already been checked. */
static tlv_result_t validate_checked(const uint8_t* data, size_t size, const tlv_format_t* format,
                                     const tlv_structure_schema_t* schema, size_t max_depth,
                                     size_t max_elements, tlv_schema_diagnostic_t* diagnostic) {
    tlv_result_t rc = validate_input(data, size, format, schema, max_depth, max_elements,
                                     diagnostic ? &diagnostic->diagnostic : NULL, diagnostic);
    if (diagnostic && rc != TLV_OK) {
        diagnostic->diagnostic.code = rc;
        diagnostic->diagnostic.severity = TLV_DIAGNOSTIC_SEVERITY_ERROR;
    }
    return rc;
}

static tlv_result_t argument_failure(tlv_result_t rc, tlv_schema_diagnostic_t* diagnostic) {
    if (diagnostic) {
        diagnostic->diagnostic.code = rc;
        diagnostic->diagnostic.severity = TLV_DIAGNOSTIC_SEVERITY_ERROR;
    }
    return rc;
}

tlv_result_t tlv_schema_validate(const uint8_t* data, size_t size, const tlv_format_t* format,
                                 const tlv_structure_schema_t* schema, size_t max_depth,
                                 size_t max_elements, tlv_schema_diagnostic_t* diagnostic) {
    tlv_result_t rc;
    if (diagnostic) tlv_schema_diagnostic_init(diagnostic);
    if (!schema || !format || (!data && size))
        return argument_failure(TLV_ERR_NULL_ARG, diagnostic);
    rc = tlv_schema_check(schema, diagnostic);
    if (rc != TLV_OK) return rc;
    return validate_checked(data, size, format, schema, max_depth, max_elements, diagnostic);
}

tlv_result_t tlv_schema_validate_checked(const tlv_schema_checked_t* checked, const uint8_t* data,
                                         size_t size, const tlv_format_t* format, size_t max_depth,
                                         size_t max_elements, tlv_schema_diagnostic_t* diagnostic) {
    if (diagnostic) tlv_schema_diagnostic_init(diagnostic);
    if (!checked || !format || (!data && size))
        return argument_failure(TLV_ERR_NULL_ARG, diagnostic);
    if (!checked->schema) return argument_failure(TLV_ERR_INVALID_STATE, diagnostic);
    return validate_checked(data, size, format, checked->schema, max_depth, max_elements,
                            diagnostic);
}
