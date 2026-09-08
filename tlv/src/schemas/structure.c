#include "tlv/schemas/schema.h"
#include "tlv/reader/reader.h"
#include "tlv/reader/walker.h"
#include <string.h>

static int same_tag(const tlv_tag_t* a, const tlv_tag_t* b) {
    return a->size == b->size && memcmp(a->data, b->data, a->size) == 0;
}

static tlv_result_t invalid(size_t offset, size_t* error_offset) {
    if (error_offset) *error_offset = offset;
    return TLV_ERR_SCHEMA;
}

static tlv_result_t check_scope(const uint8_t* data, const tlv_format_t* format,
                                const tlv_structure_schema_t* current,
                                size_t start, size_t end, size_t* error_offset) {
    tlv_result_t rc;
    if (!current->rules && current->count)
        return invalid(start, error_offset);
    for (size_t i = 0; i < current->count; ++i) {
        const tlv_structure_rule_t* rule = &current->rules[i];
        size_t count = 0, pos = start;
        if (!rule->entry.tag.size || rule->entry.tag.size > TLV_TAG_MAX_SIZE ||
            rule->entry.min_length > rule->entry.max_length ||
            rule->min_occurs > rule->max_occurs ||
            rule->kind < TLV_SCHEMA_ANY || rule->kind > TLV_SCHEMA_CONSTRUCTED ||
            (rule->children && rule->kind != TLV_SCHEMA_CONSTRUCTED))
            return invalid(start, error_offset);
        for (size_t j = 0; j < i; ++j)
            if (same_tag(&rule->entry.tag, &current->rules[j].entry.tag))
                return invalid(start, error_offset);
        while (pos < end) {
            tlv_view_t view;
            size_t used;
            rc = tlv_read(data + pos, end - pos, format, &view, &used);
            if (rc != TLV_OK) {
                if (error_offset) *error_offset = pos;
                return rc;
            }
            if (same_tag(&rule->entry.tag, &view.tag)) {
                if (count == rule->max_occurs) return invalid(pos, error_offset);
                ++count;
            }
            pos += used;
        }
        if (count < rule->min_occurs) return invalid(end, error_offset);
    }
    return TLV_OK;
}

typedef struct scope {
    const tlv_structure_schema_t* schema;
    size_t start, end, pos;
    int checked;
} scope_t;

tlv_result_t tlv_schema_validate(const uint8_t* data, size_t size,
                                 const tlv_format_t* format,
                                 const tlv_structure_schema_t* schema,
                                 size_t max_depth, size_t max_elements,
                                 size_t* error_offset) {
    scope_t stack[TLV_WALK_MAX_DEPTH + 1];
    size_t depth = 0;
    tlv_result_t rc;
    if (!schema) {
        if (error_offset) *error_offset = 0;
        return TLV_ERR_NULL_ARG;
    }
    rc = tlv_walk_tree(data, size, format, max_depth, max_elements,
                       NULL, NULL, error_offset);
    if (rc != TLV_OK) return rc;
    stack[0] = (scope_t){schema, 0, size, 0, 0};
    for (;;) {
        scope_t* frame = &stack[depth];
        const tlv_structure_schema_t* current = frame->schema;
        if (!frame->checked) {
            rc = check_scope(data, format, current, frame->start, frame->end, error_offset);
            if (rc != TLV_OK) return rc;
            frame->checked = 1;
        }
        if (frame->pos == frame->end) {
            if (!depth) return TLV_OK;
            --depth;
            continue;
        }
        {
            tlv_view_t view;
            size_t used, pos = frame->pos;
            const tlv_structure_rule_t* rule = NULL;
            int constructed;
            rc = tlv_read(data + pos, frame->end - pos, format, &view, &used);
            if (rc != TLV_OK) {
                if (error_offset) *error_offset = pos;
                return rc;
            }
            frame->pos += used;
            for (size_t i = 0; i < current->count; ++i)
                if (same_tag(&current->rules[i].entry.tag, &view.tag)) {
                    rule = &current->rules[i]; break;
                }
            if (!rule) {
                if (!current->allow_unknown) return invalid(pos, error_offset);
                continue;
            }
            rc = tlv_schema_validate_length(&rule->entry, view.value.length);
            if (rc != TLV_OK) {
                if (error_offset) *error_offset = pos;
                return rc;
            }
            constructed = format->is_constructed &&
                format->is_constructed(format->context, &view.tag);
            if ((rule->kind == TLV_SCHEMA_PRIMITIVE && constructed) ||
                (rule->kind == TLV_SCHEMA_CONSTRUCTED && !constructed))
                return invalid(pos, error_offset);
            if (rule->children) {
                size_t start = frame->pos - view.value.length;
                /* An empty container still has child-schema requirements. */
                if (!view.value.length) {
                    rc = check_scope(data, format, rule->children, start, start, error_offset);
                    if (rc != TLV_OK) return rc;
                    continue;
                }
                if (depth == TLV_WALK_MAX_DEPTH || depth == max_depth) {
                    if (error_offset) *error_offset = start;
                    return TLV_ERR_LIMIT;
                }
                stack[++depth] = (scope_t){rule->children, start, frame->pos, start, 0};
            }
        }
    }
}
