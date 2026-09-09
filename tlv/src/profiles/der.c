#include "tlv/formats/asn1/der.h"
#include "tlv/profiles/der.h"
#include "tlv/writer/writer.h"
#include <string.h>

const tlv_der_limits_t tlv_der_default_limits = {
    32, 16 * 1024 * 1024, 16 * 1024 * 1024, 100000
};

static tlv_result_t fail(tlv_result_t rc, size_t offset, size_t* error_offset) {
    if (error_offset) *error_offset = offset;
    return rc;
}

/* Parse a bounded header with field offsets. No outputs escape on failure. */
static tlv_result_t read_entry(const uint8_t* data, size_t size, size_t base,
                               const tlv_der_limits_t* limits, tlv_view_t* view,
                               size_t* consumed, size_t* error_offset) {
    size_t tag_size, length_size;
    tlv_result_t rc = tlv_reader_format_der.read_tag(tlv_reader_format_der.context, data, size, &view->tag, &tag_size);
    if (rc != TLV_OK) return fail(rc, base, error_offset);
    rc = tlv_reader_format_der.read_length(tlv_reader_format_der.context, data + tag_size, size - tag_size,
                         &view->value.length, &length_size);
    if (rc != TLV_OK) return fail(rc, base + tag_size, error_offset);
    if (view->value.length > limits->max_value_size)
        return fail(TLV_ERR_LIMIT, base + tag_size, error_offset);
    if (view->value.length > size - tag_size - length_size)
        return fail(TLV_ERR_BUFFER_TOO_SHORT, base + tag_size + length_size, error_offset);
    view->value.data = data + tag_size + length_size;
    *consumed = tag_size + length_size + view->value.length;
    return TLV_OK;
}

/* Iterative depth-first traversal: each stack slot is an enclosing value end.
 * Parent ends also serve as resume positions; descendants cannot escape them.
 */
static tlv_result_t traverse(const uint8_t* data, size_t size, size_t base,
                             size_t initial_depth, size_t initial_count,
                             const tlv_der_limits_t* limits,
                             tlv_der_visitor_t visitor, void* context,
                             int one, tlv_view_t* first, size_t* first_size,
                             size_t* error_offset) {
    size_t ends[TLV_DER_MAX_DEPTH + 1];
    size_t level = 0, pos = 0, count = initial_count;
    ends[0] = size;
    while (pos < ends[level] || level) {
        tlv_view_t view;
        size_t used, end;
        tlv_result_t rc;
        if (pos == ends[level]) { --level; continue; }
        if (initial_depth + level > limits->max_depth || count == limits->max_elements)
            return fail(TLV_ERR_LIMIT, base + pos, error_offset);
        rc = read_entry(data + pos, ends[level] - pos, base + pos,
                         limits, &view, &used, error_offset);
        if (rc != TLV_OK) return rc;
        ++count;
        end = pos + used;
        if (one && pos == 0) {
            *first = view;
            *first_size = used;
            ends[0] = end;
        }
        if (visitor) {
            tlv_visit_result_t visit = visitor(&view, initial_depth + level, base + pos, context);
            if (visit == TLV_VISIT_STOP) return TLV_OK;
            if (visit != TLV_VISIT_CONTINUE) return fail(TLV_ERR_VISITOR, base + pos, error_offset);
        }
        if (tlv_der_tag_is_constructed(&view.tag) && view.value.length) {
            /* Report the first child's tag for a depth-limit failure. */
            pos = end - view.value.length;
            if (initial_depth + level == limits->max_depth)
                return fail(TLV_ERR_LIMIT, base + pos, error_offset);
            ends[++level] = end;
        } else pos = end;
    }
    return TLV_OK;
}

tlv_result_t tlv_der_walk(const uint8_t* data, size_t size,
                          const tlv_der_limits_t* limits,
                          tlv_der_visitor_t visitor, void* context, size_t* error_offset) {
    if (!limits) limits = &tlv_der_default_limits;
    if (!data && size) return fail(TLV_ERR_NULL_ARG, 0, error_offset);
    if (limits->max_depth > TLV_DER_MAX_DEPTH || size > limits->max_input_size)
        return fail(TLV_ERR_LIMIT, 0, error_offset);
    return traverse(data, size, 0, 0, 0, limits, visitor, context, 0, NULL, NULL, error_offset);
}

tlv_result_t tlv_der_read(const uint8_t* data, size_t size,
                          const tlv_der_limits_t* limits, tlv_view_t* view,
                          size_t* consumed, size_t* error_offset) {
    tlv_view_t result;
    size_t used;
    tlv_result_t rc;
    if (!limits) limits = &tlv_der_default_limits;
    if ((!data && size) || !view || !consumed) return fail(TLV_ERR_NULL_ARG, 0, error_offset);
    if (limits->max_depth > TLV_DER_MAX_DEPTH || size > limits->max_input_size)
        return fail(TLV_ERR_LIMIT, 0, error_offset);
    if (!size) return fail(TLV_ERR_END_OF_BUFFER, 0, error_offset);
    rc = traverse(data, size, 0, 0, 0, limits, NULL, NULL, 1, &result, &used, error_offset);
    if (rc == TLV_OK) { *view = result; *consumed = used; }
    return rc;
}

tlv_result_t tlv_der_write(uint8_t* data, size_t capacity, tlv_tag_t tag,
                           const uint8_t* value, size_t length,
                           const tlv_der_limits_t* limits, size_t* written,
                           size_t* error_offset) {
    size_t total;
    tlv_result_t rc;
    if (!limits) limits = &tlv_der_default_limits;
    if ((!data && capacity) || (!value && length) || !written)
        return fail(TLV_ERR_NULL_ARG, 0, error_offset);
    rc = tlv_encoded_size(tag, length, &tlv_writer_format_der, &total);
    if (rc != TLV_OK) return fail(rc, rc == TLV_ERR_INVALID_LENGTH ? tag.size : 0, error_offset);
    if (limits->max_depth > TLV_DER_MAX_DEPTH || total > limits->max_input_size ||
        !limits->max_elements) return fail(TLV_ERR_LIMIT, 0, error_offset);
    if (length > limits->max_value_size) return fail(TLV_ERR_LIMIT, tag.size, error_offset);
    if (tlv_der_tag_is_constructed(&tag)) {
        rc = traverse(value, length, total - length, 1, 1, limits,
                       NULL, NULL, 0, NULL, NULL, error_offset);
        if (rc != TLV_OK) return rc;
    }
    if (!data) { *written = total; return TLV_OK; }
    rc = tlv_write(data, capacity, &tlv_writer_format_der, tag, value, length, written);
    if (rc != TLV_OK) return fail(rc, 0, error_offset);
    return TLV_OK;
}
