#include "tlv/der.h"
#include "tlv/writer.h"
#include <string.h>

const tlv_der_limits_t tlv_der_default_limits = {
    32, 16 * 1024 * 1024, 16 * 1024 * 1024, 100000
};

static tlv_result_t der_read_tag(const void* context, const uint8_t* data,
                                size_t size, tlv_tag_t* tag, size_t* consumed) {
    tlv_tag_t parsed;
    size_t count;
    unsigned number;
    int constructed;
    tlv_result_t rc = tlv_format_ber.read_tag(context, data, size, &parsed, &count);
    if (rc != TLV_OK) return rc;
    if (count == 2 && data[1] < 31) return TLV_ERR_INVALID_TAG;
    /* Only tags up to 36 currently have assigned universal type semantics.
     * Larger numbers remain opaque, without narrowing large raw identifiers.
     */
    number = count == 1 ? (data[0] & 0x1F) : (count == 2 ? data[1] : 127);
    if (!(data[0] & 0xC0)) {
        if (number == 0 || number == 15) return TLV_ERR_INVALID_TAG;
        constructed = number == 8 || number == 11 || number == 16 ||
                      number == 17 || number == 29;
        if (number <= 36 && ((data[0] & 0x20) != 0) != constructed)
            return TLV_ERR_INVALID_TAG;
    }
    *tag = parsed;
    *consumed = count;
    return TLV_OK;
}

static tlv_result_t der_write_tag(const void* context, uint8_t* data,
                                 size_t capacity, const tlv_tag_t* tag,
                                 size_t* written) {
    tlv_tag_t parsed;
    size_t count;
    if (!tag->size || tag->size > TLV_TAG_MAX_SIZE) return TLV_ERR_INVALID_TAG;
    if (der_read_tag(context, tag->data, tag->size, &parsed, &count) != TLV_OK ||
        count != tag->size) return TLV_ERR_INVALID_TAG;
    if (data && capacity < count) return TLV_ERR_BUFFER_TOO_SHORT;
    if (data) memcpy(data, tag->data, count);
    *written = count;
    return TLV_OK;
}

static tlv_result_t der_read_length(const void* context, const uint8_t* data,
                                   size_t size, size_t* length, size_t* consumed) {
    size_t value, count;
    tlv_result_t rc = tlv_format_ber.read_length(context, data, size, &value, &count);
    if (rc != TLV_OK) return rc;
    if (count > 1 && (value < 128 || data[1] == 0)) return TLV_ERR_INVALID_LENGTH;
    *length = value;
    *consumed = count;
    return TLV_OK;
}

static tlv_result_t der_write_length(const void* context, uint8_t* data,
                                    size_t capacity, size_t length, size_t* written) {
    return tlv_format_ber.write_length(context, data, capacity, length, written);
}

static tlv_result_t der_length_size(const void* context, size_t length, size_t* size) {
    return tlv_format_ber.length_size(context, length, size);
}

const tlv_format_t tlv_format_der = {
    NULL, der_read_tag, der_write_tag, der_read_length, der_write_length, der_length_size
};

tlv_result_t tlv_der_tag_make(tlv_asn1_class_t tag_class, int constructed,
                              uint64_t number, tlv_tag_t* tag) {
    tlv_tag_t result = {{0}, 1};
    uint8_t digits[10];
    size_t count = 0, written;
    if (!tag) return TLV_ERR_NULL_ARG;
    if ((unsigned)tag_class > 3 || (constructed != 0 && constructed != 1))
        return TLV_ERR_INVALID_TAG;
    result.data[0] = (uint8_t)(((unsigned)tag_class << 6) | (constructed ? 0x20 : 0));
    if (number < 31) result.data[0] |= (uint8_t)number;
    else {
        result.data[0] |= 0x1F;
        do { digits[count++] = (uint8_t)(number & 0x7F); number >>= 7; } while (number);
        if (count + 1 > TLV_TAG_MAX_SIZE) return TLV_ERR_INVALID_TAG;
        result.size = (uint8_t)(count + 1);
        for (size_t i = 0; i < count; ++i)
            result.data[i + 1] = (uint8_t)(digits[count - i - 1] | (i + 1 < count ? 0x80 : 0));
    }
    if (der_write_tag(NULL, NULL, 0, &result, &written) != TLV_OK)
        return TLV_ERR_INVALID_TAG;
    *tag = result;
    return TLV_OK;
}

tlv_result_t tlv_der_tag_number(const tlv_tag_t* tag, uint64_t* number) {
    uint64_t result;
    size_t written;
    if (!tag || !number) return TLV_ERR_NULL_ARG;
    if (der_write_tag(NULL, NULL, 0, tag, &written) != TLV_OK) return TLV_ERR_INVALID_TAG;
    result = tag->data[0] & 0x1F;
    if (tag->size > 1) {
        result = 0;
        for (size_t i = 1; i < tag->size; ++i) {
            if (result > (UINT64_MAX >> 7)) return TLV_ERR_INVALID_TAG;
            result = (result << 7) | (tag->data[i] & 0x7F);
        }
    }
    *number = result;
    return TLV_OK;
}

static tlv_result_t fail(tlv_result_t rc, size_t offset, size_t* error_offset) {
    if (error_offset) *error_offset = offset;
    return rc;
}

/* Parse a bounded header with field offsets. No outputs escape on failure. */
static tlv_result_t read_entry(const uint8_t* data, size_t size, size_t base,
                               const tlv_der_limits_t* limits, tlv_view_t* view,
                               size_t* consumed, size_t* error_offset) {
    size_t tag_size, length_size;
    tlv_result_t rc = der_read_tag(NULL, data, size, &view->tag, &tag_size);
    if (rc != TLV_OK) return fail(rc, base, error_offset);
    rc = der_read_length(NULL, data + tag_size, size - tag_size,
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
    rc = tlv_encoded_size(tag, length, &tlv_format_der, &total);
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
    rc = tlv_write(data, capacity, &tlv_format_der, tag, value, length, written);
    if (rc != TLV_OK) return fail(rc, 0, error_offset);
    return TLV_OK;
}
