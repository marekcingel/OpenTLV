#include "tlv/reader/walker.h"
#include "tlv/reader/reader.h"

static tlv_result_t tree_error(tlv_result_t rc, size_t offset, size_t* out) {
    if (out) *out = offset;
    return rc;
}

tlv_result_t tlv_walk_tree(const uint8_t* data, size_t size,
                           const tlv_reader_format_t* format,
                           tlv_is_constructed_fn is_constructed, size_t max_depth,
                           size_t max_elements, tlv_tree_visitor_t visitor,
                           void* context, size_t* error_offset) {
    size_t ends[TLV_WALK_MAX_DEPTH + 1];
    size_t resumes[TLV_WALK_MAX_DEPTH + 1];
    size_t depth = 0, pos = 0, count = 0;
    if ((!data && size) || !format || !format->read_tag || !format->read_length)
        return tree_error(TLV_ERR_NULL_ARG, 0, error_offset);
    if (max_depth > TLV_WALK_MAX_DEPTH)
        return tree_error(TLV_ERR_LIMIT, 0, error_offset);
    ends[0] = size;
    while (pos < ends[depth] || depth) {
        tlv_view_t view;
        size_t used, end;
        tlv_result_t rc;
        if (pos == ends[depth]) { pos = resumes[depth]; --depth; continue; }
        if (count == max_elements)
            return tree_error(TLV_ERR_LIMIT, pos, error_offset);
        rc = tlv_read(data + pos, ends[depth] - pos, format, &view, &used);
        if (rc != TLV_OK) return tree_error(rc, pos, error_offset);
        ++count;
        end = pos + used;
        if (visitor) {
            tlv_visit_result_t result = visitor(&view, depth, pos, context);
            if (result == TLV_VISIT_STOP) return TLV_OK;
            if (result != TLV_VISIT_CONTINUE)
                return tree_error(TLV_ERR_VISITOR, pos, error_offset);
        }
        if (is_constructed &&
            is_constructed(format->context, &view.tag) && view.value.length) {
            pos = (size_t)(view.value.data - data);
            if (depth == max_depth)
                return tree_error(TLV_ERR_LIMIT, pos, error_offset);
            ends[++depth] = pos + view.value.length;
            resumes[depth] = end;
        } else pos = end;
    }
    return TLV_OK;
}

tlv_result_t tlv_walk(const uint8_t* data, size_t size,
                      const tlv_reader_format_t* format, tlv_visitor_t visitor,
                      void* context) {
    tlv_reader_t reader;
    tlv_result_t rc;
    if (!visitor) return TLV_ERR_NULL_ARG;
    rc = tlv_reader_init(&reader, data, size, format);
    if (rc != TLV_OK) return rc;
    while (!tlv_reader_at_end(&reader)) {
        tlv_view_t view;
        rc = tlv_reader_next(&reader, &view);
        if (rc != TLV_OK) return rc;
        switch (visitor(&view, context)) {
            case TLV_VISIT_CONTINUE: break;
            case TLV_VISIT_STOP: return TLV_OK;
            default: return TLV_ERR_VISITOR;
        }
    }
    return TLV_OK;
}
