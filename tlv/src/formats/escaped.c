#include "tlv/formats/escaped.h"
#include <string.h>

static tlv_result_t validate_length(const tlv_escaped_length_t* f) {
    if (!f->escape || !f->extended_size || f->extended_size > 8 || f->min_extended > f->escape ||
        f->max_length < f->escape ||
        (f->extended_size < 8 && f->max_length >= (UINT64_C(1) << (8 * f->extended_size))))
        return TLV_ERR_INVALID_ARG;
    if (f->byte_order != TLV_BYTE_ORDER_BIG_ENDIAN && f->byte_order != TLV_BYTE_ORDER_LITTLE_ENDIAN)
        return TLV_ERR_INVALID_BYTE_ORDER;
    return TLV_OK;
}

tlv_result_t tlv_escaped_length_read(const tlv_escaped_length_t* f, const uint8_t* data,
                                     size_t size, tlv_size_t* length, size_t* consumed) {
    uint64_t value;
    size_t width;
    tlv_result_t rc;
    if (!f || !length || !consumed || (!data && size)) return TLV_ERR_NULL_ARG;
    rc = validate_length(f);
    if (rc != TLV_OK) return rc;
    *consumed = 0;
    if (!size) return TLV_ERR_BUFFER_TOO_SHORT;
    *consumed = 1;
    if (data[0] > f->escape) return TLV_ERR_INVALID_LENGTH;
    if (data[0] < f->escape) {
        *length = data[0];
        return TLV_OK;
    }
    width = 1 + f->extended_size;
    *consumed = size < width ? size : width;
    if (size < width) return TLV_ERR_BUFFER_TOO_SHORT;
    rc = tlv_read_uint(data + 1, f->extended_size, f->byte_order, &value);
    if (rc != TLV_OK) return rc;
    if (value < f->min_extended || value > f->max_length) return TLV_ERR_INVALID_LENGTH;
    *length = value;
    return TLV_OK;
}

tlv_result_t tlv_escaped_length_write(const tlv_escaped_length_t* f, tlv_size_t length,
                                      uint8_t* data, size_t capacity, size_t* written) {
    size_t width;
    tlv_result_t rc;
    if (!f || !written || (!data && capacity)) return TLV_ERR_NULL_ARG;
    rc = validate_length(f);
    if (rc != TLV_OK) return rc;
    if (length > f->max_length) return TLV_ERR_INVALID_LENGTH;
    width = length < f->escape ? 1 : 1 + f->extended_size;
    if (data) {
        if (capacity < width) return TLV_ERR_BUFFER_TOO_SHORT;
        if (width > 1) {
            rc = tlv_write_uint(data + 1, f->extended_size, f->byte_order, length);
            if (rc != TLV_OK) return rc;
        }
        data[0] = width == 1 ? (uint8_t)length : f->escape;
    }
    *written = width;
    return TLV_OK;
}

static tlv_result_t read_tag(const void* context, const uint8_t* data, size_t size, tlv_tag_t* tag,
                             size_t* consumed) {
    const tlv_escaped_format_t* f = (const tlv_escaped_format_t*)context;
    if (size < f->tag_size) return TLV_ERR_BUFFER_TOO_SHORT;
    *tag = tlv_tag(data, f->tag_size);
    *consumed = f->tag_size;
    return TLV_OK;
}

static tlv_result_t write_tag(const void* context, uint8_t* data, size_t capacity,
                              const tlv_tag_t* tag, size_t* written) {
    const tlv_escaped_format_t* f = (const tlv_escaped_format_t*)context;
    if (tag->size != f->tag_size) return TLV_ERR_INVALID_TAG_SIZE;
    if (!tag->data) return TLV_ERR_NULL_ARG;
    if (data) {
        if (capacity < f->tag_size) return TLV_ERR_BUFFER_TOO_SHORT;
        memcpy(data, tag->data, f->tag_size);
    }
    *written = f->tag_size;
    return TLV_OK;
}

static tlv_result_t read_length(const void* context, const uint8_t* data, size_t size,
                                tlv_size_t* length, size_t* consumed) {
    const tlv_escaped_format_t* f = (const tlv_escaped_format_t*)context;
    return tlv_escaped_length_read(&f->length, data, size, length, consumed);
}

static tlv_result_t write_length(const void* context, uint8_t* data, size_t capacity,
                                 tlv_size_t length, size_t* written) {
    const tlv_escaped_format_t* f = (const tlv_escaped_format_t*)context;
    return tlv_escaped_length_write(&f->length, length, data, capacity, written);
}

static tlv_result_t length_size(const void* context, tlv_size_t length, size_t* size) {
    return write_length(context, NULL, 0, length, size);
}

static tlv_tagged_fields_layout_t fields(const tlv_escaped_format_t* f) {
    tlv_tagged_fields_layout_t result = {
        {f, read_tag, read_length, NULL, write_tag, write_length, length_size, f->order, f->scope},
        f->tag_only,
        f->count};
    return result;
}

tlv_result_t tlv_escaped_decode(const void* context, const uint8_t* data, size_t size,
                                tlv_decoded_t* result, tlv_format_error_t* error) {
    const tlv_escaped_format_t* f = (const tlv_escaped_format_t*)context;
    tlv_tagged_fields_layout_t layout = fields(f);
    return f->count ? tlv_tagged_fields_decode(&layout, data, size, result, error)
                    : tlv_fields_decode(&layout.fields, data, size, result, error);
}

tlv_result_t tlv_escaped_measure(const void* context, const tlv_element_t* element,
                                 tlv_encoding_t* encoding, tlv_format_error_t* error) {
    const tlv_escaped_format_t* f = (const tlv_escaped_format_t*)context;
    tlv_tagged_fields_layout_t layout = fields(f);
    return f->count ? tlv_tagged_fields_measure(&layout, element, encoding, error)
                    : tlv_fields_measure(&layout.fields, element, encoding, error);
}

tlv_result_t tlv_escaped_encode(const void* context, const tlv_element_t* element, uint8_t* data,
                                size_t capacity, size_t* written, tlv_format_error_t* error) {
    const tlv_escaped_format_t* f = (const tlv_escaped_format_t*)context;
    tlv_tagged_fields_layout_t layout = fields(f);
    return f->count ? tlv_tagged_fields_encode(&layout, element, data, capacity, written, error)
                    : tlv_fields_encode(&layout.fields, element, data, capacity, written, error);
}

tlv_result_t tlv_escaped_format_init(tlv_format_t* format, const tlv_escaped_format_t* f) {
    tlv_result_t rc;
    if (!format || !f) return TLV_ERR_NULL_ARG;
    rc = validate_length(&f->length);
    if (rc != TLV_OK) return rc;
    if (!f->tag_size || (f->order != TLV_ELEMENT_ORDER_TLV && f->order != TLV_ELEMENT_ORDER_LTV) ||
        (f->scope != TLV_LENGTH_SCOPE_VALUE && f->scope != TLV_LENGTH_SCOPE_TAG_AND_VALUE) ||
        (f->count &&
         (!f->tag_only || f->order != TLV_ELEMENT_ORDER_TLV || f->scope != TLV_LENGTH_SCOPE_VALUE)))
        return TLV_ERR_INVALID_ARG;
    for (size_t i = 0; i < f->count; ++i)
        if (!f->tag_only[i].data || f->tag_only[i].size != f->tag_size) return TLV_ERR_INVALID_ARG;
    return tlv_format_init(format, f, tlv_escaped_decode, tlv_escaped_measure, tlv_escaped_encode);
}
