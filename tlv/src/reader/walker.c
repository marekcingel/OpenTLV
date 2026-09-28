#include "tlv/reader/walker.h"
#include "tlv/reader/reader.h"
#include "tlv/size.h"

static tlv_result_t tree_error(tlv_result_t rc, size_t offset, size_t* out) {
    if (out) *out = offset;
    return rc;
}

static tlv_result_t walk_tree_impl(const uint8_t* data, size_t size, const tlv_format_t* format,
                                   size_t max_depth, size_t max_elements,
                                   tlv_tree_visitor_t visitor, void* context, size_t* error_offset,
                                   tlv_reader_diagnostic_t* diagnostic) {
    if (diagnostic) tlv_reader_diagnostic_init(diagnostic);
    size_t ends[TLV_WALK_MAX_DEPTH + 1];
    size_t resumes[TLV_WALK_MAX_DEPTH + 1];
    size_t depth = 0, pos = 0, count = 0;
    if ((!data && size) || !tlv_format_can_read(format))
        return tree_error(TLV_ERR_NULL_ARG, 0, error_offset);
    if (max_depth > TLV_WALK_MAX_DEPTH) return tree_error(TLV_ERR_LIMIT, 0, error_offset);
    ends[0] = size;
    while (pos < ends[depth] || depth) {
        tlv_element_t element;
        size_t used, end;
        tlv_result_t rc;
        if (pos == ends[depth]) {
            pos = resumes[depth];
            --depth;
            continue;
        }
        if (count == max_elements) return tree_error(TLV_ERR_LIMIT, pos, error_offset);
        rc = tlv_read_diag(data + pos, ends[depth] - pos, format, &element, &used, diagnostic);
        if (rc != TLV_OK) {
            if (diagnostic) {
                if (diagnostic->diagnostic.has_offset) diagnostic->diagnostic.offset += pos;
                if (diagnostic->has_tag_offset) diagnostic->tag_offset += pos;
                if (diagnostic->has_length_offset) diagnostic->length_offset += pos;
                if (diagnostic->has_value_offset) diagnostic->value_offset += pos;
                if (diagnostic->has_enclosing_end) diagnostic->enclosing_end += pos;
            }
            return tree_error(rc, pos, error_offset);
        }
        ++count;
        end = pos + used;
        if (visitor) {
            tlv_visit_result_t result = visitor(&element, depth, pos, context);
            if (result == TLV_VISIT_STOP) return TLV_OK;
            if (result != TLV_VISIT_CONTINUE) return tree_error(TLV_ERR_VISITOR, pos, error_offset);
        }
        if (format->is_constructed && format->is_constructed(format->context, &element.tag) &&
            element.value.size) {
            size_t value_length;
            rc = tlv_size_to_native(element.value.size, &value_length);
            if (rc != TLV_OK) return tree_error(rc, pos, error_offset);
            pos = (size_t)(element.value.data - data);
            if (depth == max_depth) return tree_error(TLV_ERR_LIMIT, pos, error_offset);
            ends[++depth] = pos + value_length;
            resumes[depth] = end;
        } else
            pos = end;
    }
    return TLV_OK;
}

tlv_result_t tlv_walk(const uint8_t* data, size_t size, const tlv_format_t* format,
                      tlv_visitor_t visitor, void* context) {
    tlv_reader_t reader;
    tlv_result_t rc;
    if (!visitor) return TLV_ERR_NULL_ARG;
    rc = tlv_reader_init(&reader, data, size, format);
    if (rc != TLV_OK) return rc;
    while (!tlv_reader_at_end(&reader)) {
        tlv_element_t element;
        rc = tlv_reader_next(&reader, &element);
        if (rc != TLV_OK) return rc;
        switch (visitor(&element, context)) {
            case TLV_VISIT_CONTINUE: break;
            case TLV_VISIT_STOP: return TLV_OK;
            default: return TLV_ERR_VISITOR;
        }
    }
    return TLV_OK;
}

tlv_result_t tlv_walk_tree(const uint8_t* data, size_t size, const tlv_format_t* format,
                           size_t max_depth, size_t max_elements, tlv_tree_visitor_t visitor,
                           void* context, size_t* error_offset) {
    return walk_tree_impl(data, size, format, max_depth, max_elements, visitor, context,
                          error_offset, NULL);
}

tlv_result_t tlv_walk_tree_diag(const uint8_t* data, size_t size, const tlv_format_t* format,
                                size_t max_depth, size_t max_elements, tlv_tree_visitor_t visitor,
                                void* context, size_t* error_offset,
                                tlv_reader_diagnostic_t* diagnostic) {
    return walk_tree_impl(data, size, format, max_depth, max_elements, visitor, context,
                          error_offset, diagnostic);
}
