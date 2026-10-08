// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/schema/schema.h"
#include "tlv/reader/reader.h"
#include "traversal_internal.h"
#include "tlv/size.h"
#include <string.h>

static int same_tag(const tlv_tag_t* a, const tlv_tag_t* b) {
    return tlv_tag_equal(*a, *b);
}

static void occurrence(tlv_schema_diagnostic_t* diagnostic, const tlv_structure_rule_t* rule,
                       const tlv_structure_group_t* group, size_t count,
                       tlv_schema_issue_kind_t kind) {
    if (!diagnostic) return;
    diagnostic->kind = kind;
    if (rule) diagnostic->tag = rule->entry->tag;
    diagnostic->field = group ? group->name : rule->entry->name;
    diagnostic->is_group = group != NULL;
    diagnostic->has_occurs = 1;
    diagnostic->min_occurs = group ? group->min_occurs : rule->min_occurs;
    diagnostic->max_occurs = group ? group->max_occurs : rule->max_occurs;
    diagnostic->occurs = count;
}

static tlv_result_t invalid(size_t offset, size_t* error_offset,
                            tlv_schema_diagnostic_t* diagnostic) {
    if (error_offset) *error_offset = offset;
    if (diagnostic && diagnostic->kind == TLV_SCHEMA_ISSUE_NONE)
        diagnostic->kind = TLV_SCHEMA_ISSUE_UNEXPECTED;
    return TLV_ERR_SCHEMA;
}

/* Distinct from invalid(): offset is the end of the enclosing scope, not an
 * element, so it must not be presented as the location of a tag. */
static tlv_result_t missing(size_t offset, size_t* error_offset,
                            tlv_schema_diagnostic_t* diagnostic) {
    if (error_offset) *error_offset = offset;
    if (diagnostic) {
        diagnostic->kind = TLV_SCHEMA_ISSUE_MISSING;
        diagnostic->anchor = TLV_SCHEMA_ANCHOR_SCOPE_END;
    }
    return TLV_ERR_SCHEMA;
}

static tlv_result_t check_scope(const uint8_t* data, const tlv_format_t* format,
                                const tlv_structure_schema_t* current, size_t start, size_t end,
                                size_t* error_offset, tlv_schema_diagnostic_t* diagnostic) {
    for (size_t i = 0; i < current->count; ++i) {
        const tlv_structure_rule_t* rule = &current->rules[i];
        size_t count = 0, pos = start;
        while (pos < end) {
            tlv_element_t element;
            size_t used;
            tlv_result_t rc = tlv_read(data + pos, end - pos, format, &element, &used);
            if (rc != TLV_OK) {
                if (error_offset) *error_offset = pos;
                return rc;
            }
            if (same_tag(&rule->entry->tag, &element.tag)) {
                if (count == rule->max_occurs) {
                    occurrence(diagnostic, rule, NULL, count + 1, TLV_SCHEMA_ISSUE_DUPLICATE);
                    return invalid(pos, error_offset, diagnostic);
                }
                ++count;
            }
            pos += used;
        }
        if (count < rule->min_occurs) {
            occurrence(diagnostic, rule, NULL, count, TLV_SCHEMA_ISSUE_MISSING);
            return missing(end, error_offset, diagnostic);
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
                if (error_offset) *error_offset = pos;
                return rc;
            }
            for (size_t i = 0; i < current->count; ++i)
                if (current->rules[i].group == group->id &&
                    same_tag(&current->rules[i].entry->tag, &element.tag)) {
                    if (count == group->max_occurs) {
                        occurrence(diagnostic, &current->rules[i], group, count + 1,
                                   TLV_SCHEMA_ISSUE_DUPLICATE);
                        return invalid(pos, error_offset, diagnostic);
                    }
                    ++count;
                    break;
                }
            pos += used;
        }
        if (count < group->min_occurs) {
            occurrence(diagnostic, NULL, group, count, TLV_SCHEMA_ISSUE_MISSING);
            if (diagnostic) {
                for (size_t i = 0; i < current->count; ++i)
                    if (current->rules[i].group == group->id) {
                        diagnostic->tag = current->rules[i].entry->tag;
                        break;
                    }
            }
            return missing(end, error_offset, diagnostic);
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
                if (error_offset) *error_offset = pos;
                return rc;
            }
            for (size_t i = 0; i < current->count; ++i)
                if (same_tag(&current->rules[i].entry->tag, &element.tag)) {
                    if (have_last && i < last_index) {
                        if (diagnostic) diagnostic->kind = TLV_SCHEMA_ISSUE_ORDER;
                        return invalid(pos, error_offset, diagnostic);
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
                                   size_t max_elements, size_t* error_offset,
                                   tlv_schema_diagnostic_t* diagnostic) {
    const tlv_structure_schema_t* scopes[TLV_SCHEMA_MAX_DEPTH + 1];
    tlv_tree_frame_t frames[TLV_SCHEMA_MAX_DEPTH];
    tlv_tree_reader_t reader;
    tlv_result_t rc;
    if (!schema) {
        if (error_offset) *error_offset = 0;
        return TLV_ERR_NULL_ARG;
    }
    rc = schema_check_tree(data, size, format, max_depth, max_elements, error_offset);
    if (rc != TLV_OK) return rc;
    rc = check_scope(data, format, schema, 0, size, error_offset, diagnostic);
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
            if (error_offset) *error_offset = tlv_tree_reader_offset(&reader);
            return rc;
        }
        current = scopes[item.depth];
        for (size_t i = 0; i < current->count; ++i)
            if (same_tag(&current->rules[i].entry->tag, &item.element.tag)) {
                rule = &current->rules[i];
                break;
            }
        if (!rule) {
            if (!current->allow_unknown) return invalid(item.offset, error_offset, diagnostic);
        } else {
            rc = tlv_size_to_native(item.element.value.size, &value_length);
            if (rc == TLV_OK) rc = tlv_schema_validate_length(rule->entry, value_length);
            if (rc != TLV_OK) {
                if (error_offset) *error_offset = item.offset;
                if (diagnostic && rc == TLV_ERR_SCHEMA) {
                    diagnostic->kind = TLV_SCHEMA_ISSUE_LENGTH;
                    diagnostic->tag = rule->entry->tag;
                    diagnostic->has_length = 1;
                    diagnostic->min_length = rule->entry->min_length;
                    diagnostic->max_length = rule->entry->max_length;
                    diagnostic->actual_length = value_length;
                }
                return rc;
            }
            if ((rule->kind == TLV_SCHEMA_PRIMITIVE && item.constructed) ||
                (rule->kind == TLV_SCHEMA_CONSTRUCTED && !item.constructed)) {
                if (diagnostic) diagnostic->kind = TLV_SCHEMA_ISSUE_KIND;
                return invalid(item.offset, error_offset, diagnostic);
            }
            if (rule->children) {
                size_t start = item.offset + item.source.value.offset;
                rc = check_scope(data, format, rule->children, start, start + value_length,
                                 error_offset, diagnostic);
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

tlv_result_t tlv_schema_validate(const uint8_t* data, size_t size, const tlv_format_t* format,
                                 const tlv_structure_schema_t* schema, size_t max_depth,
                                 size_t max_elements, tlv_schema_diagnostic_t* diagnostic) {
    size_t offset = 0;
    tlv_result_t rc;
    if (diagnostic) tlv_schema_diagnostic_init(diagnostic);
    if (!schema || !format || (!data && size)) {
        rc = TLV_ERR_NULL_ARG;
    } else {
        rc = tlv_schema_check(schema, diagnostic);
        if (rc != TLV_OK) return rc;
        rc = validate_input(data, size, format, schema, max_depth, max_elements,
                            diagnostic ? &offset : NULL, diagnostic);
    }
    if (diagnostic && rc != TLV_OK) {
        diagnostic->diagnostic.code = rc;
        diagnostic->diagnostic.severity = TLV_DIAGNOSTIC_SEVERITY_ERROR;
        if (rc != TLV_ERR_NULL_ARG && rc != TLV_ERR_INVALID_ARG) {
            tlv_diagnostic_set_offset(&diagnostic->diagnostic, offset);
            if (diagnostic->anchor == TLV_SCHEMA_ANCHOR_UNKNOWN)
                diagnostic->anchor = TLV_SCHEMA_ANCHOR_ELEMENT;
        }
    }
    return rc;
}
