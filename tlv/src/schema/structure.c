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

static tlv_result_t invalid(size_t offset, size_t* error_offset) {
    if (error_offset) *error_offset = offset;
    return TLV_ERR_SCHEMA;
}

/* Distinct from invalid(): offset is the end of the enclosing scope, not an
 * element, so it must not be presented as the location of a tag. */
static tlv_result_t missing(size_t offset, size_t* error_offset) {
    if (error_offset) *error_offset = offset;
    return TLV_ERR_SCHEMA_MISSING;
}

static int group_index(const tlv_structure_schema_t* schema, uint32_t id) {
    for (size_t g = 0; g < schema->group_count; ++g)
        if (schema->groups[g].id == id) return (int)g;
    return -1;
}

static tlv_result_t check_scope(const uint8_t* data, const tlv_format_t* format,
                                const tlv_structure_schema_t* current, size_t start, size_t end,
                                size_t* error_offset) {
    if (!current->rules && current->count) return invalid(start, error_offset);
    if (!current->groups && current->group_count) return invalid(start, error_offset);
    if (current->order != TLV_SCHEMA_ORDER_ANY && current->order != TLV_SCHEMA_ORDER_SEQUENCE)
        return invalid(start, error_offset);
    for (size_t g = 0; g < current->group_count; ++g) {
        const tlv_structure_group_t* group = &current->groups[g];
        int has_member = 0;
        if (!group->id || group->min_occurs > group->max_occurs)
            return invalid(start, error_offset);
        for (size_t h = 0; h < g; ++h)
            if (current->groups[h].id == group->id) return invalid(start, error_offset);
        for (size_t i = 0; i < current->count; ++i)
            if (current->rules[i].group == group->id) has_member = 1;
        if (!has_member) return invalid(start, error_offset);
    }
    for (size_t i = 0; i < current->count; ++i) {
        const tlv_structure_rule_t* rule = &current->rules[i];
        size_t count = 0, pos = start;
        if (!rule->entry || !rule->entry->tag.size || !rule->entry->tag.data ||
            rule->entry->min_length > rule->entry->max_length ||
            rule->min_occurs > rule->max_occurs || rule->kind < TLV_SCHEMA_ANY ||
            rule->kind > TLV_SCHEMA_CONSTRUCTED ||
            (rule->children && rule->kind != TLV_SCHEMA_CONSTRUCTED) ||
            (rule->group && group_index(current, rule->group) < 0) ||
            (rule->group && rule->min_occurs != 0))
            return invalid(start, error_offset);
        for (size_t j = 0; j < i; ++j)
            if (same_tag(&rule->entry->tag, &current->rules[j].entry->tag))
                return invalid(start, error_offset);
        while (pos < end) {
            tlv_element_t element;
            size_t used;
            tlv_result_t rc = tlv_read(data + pos, end - pos, format, &element, &used);
            if (rc != TLV_OK) {
                if (error_offset) *error_offset = pos;
                return rc;
            }
            if (same_tag(&rule->entry->tag, &element.tag)) {
                if (count == rule->max_occurs) return invalid(pos, error_offset);
                ++count;
            }
            pos += used;
        }
        if (count < rule->min_occurs) return missing(end, error_offset);
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
                    if (count == group->max_occurs) return invalid(pos, error_offset);
                    ++count;
                    break;
                }
            pos += used;
        }
        if (count < group->min_occurs) return missing(end, error_offset);
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
                    if (have_last && i < last_index) return invalid(pos, error_offset);
                    last_index = i;
                    have_last = 1;
                    break;
                }
            pos += used;
        }
    }
    return TLV_OK;
}

tlv_result_t tlv_schema_validate(const uint8_t* data, size_t size, const tlv_format_t* format,
                                 const tlv_structure_schema_t* schema, size_t max_depth,
                                 size_t max_elements, size_t* error_offset) {
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
    rc = check_scope(data, format, schema, 0, size, error_offset);
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
            if (!current->allow_unknown) return invalid(item.offset, error_offset);
        } else {
            rc = tlv_size_to_native(item.element.value.size, &value_length);
            if (rc == TLV_OK) rc = tlv_schema_validate_length(rule->entry, value_length);
            if (rc != TLV_OK) {
                if (error_offset) *error_offset = item.offset;
                return rc;
            }
            if ((rule->kind == TLV_SCHEMA_PRIMITIVE && item.constructed) ||
                (rule->kind == TLV_SCHEMA_CONSTRUCTED && !item.constructed))
                return invalid(item.offset, error_offset);
            if (rule->children) {
                size_t start = item.offset + item.source.value.offset;
                rc = check_scope(data, format, rule->children, start, start + value_length,
                                 error_offset);
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
