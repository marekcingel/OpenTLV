#include "tlv/layout.h"
#include "tlv/size.h"
#include <string.h>

static tlv_result_t packed_validate(const tlv_packed_field_t* f) {
    if (!f->storage_size || f->storage_size > 8 || !f->bit_width || f->bit_width > 64 ||
        f->bit_offset >= f->storage_size * 8 || f->bit_width > f->storage_size * 8 - f->bit_offset)
        return TLV_ERR_INVALID_ARG;
    if (f->byte_order != TLV_BYTE_ORDER_BIG_ENDIAN && f->byte_order != TLV_BYTE_ORDER_LITTLE_ENDIAN)
        return TLV_ERR_INVALID_BYTE_ORDER;
    return TLV_OK;
}

static uint64_t packed_mask(unsigned int width) {
    return width == 64 ? UINT64_MAX : (UINT64_C(1) << width) - 1;
}

tlv_result_t tlv_packed_field_read(const tlv_packed_field_t* field, const uint8_t* data,
                                   size_t size, uint64_t* value) {
    uint64_t storage;
    tlv_result_t rc;
    if (!field || !data || !value) return TLV_ERR_NULL_ARG;
    rc = packed_validate(field);
    if (rc != TLV_OK) return rc;
    if (size < field->storage_size) return TLV_ERR_BUFFER_TOO_SHORT;
    rc = tlv_read_uint(data, field->storage_size, field->byte_order, &storage);
    if (rc != TLV_OK) return rc;
    *value = (storage >> field->bit_offset) & packed_mask(field->bit_width);
    return TLV_OK;
}

tlv_result_t tlv_packed_field_write(const tlv_packed_field_t* field, uint8_t* data, size_t capacity,
                                    uint64_t value) {
    uint64_t storage, mask;
    tlv_result_t rc;
    if (!field || !data) return TLV_ERR_NULL_ARG;
    rc = packed_validate(field);
    if (rc != TLV_OK) return rc;
    if (capacity < field->storage_size) return TLV_ERR_BUFFER_TOO_SHORT;
    mask = packed_mask(field->bit_width);
    if (value > mask) return TLV_ERR_OVERFLOW;
    rc = tlv_read_uint(data, field->storage_size, field->byte_order, &storage);
    if (rc != TLV_OK) return rc;
    storage = (storage & ~(mask << field->bit_offset)) | (value << field->bit_offset);
    return tlv_write_uint(data, field->storage_size, field->byte_order, storage);
}

static tlv_range_t range(size_t offset, size_t size) {
    tlv_range_t r = {offset, size, 1};
    return r;
}

static void location(tlv_format_error_t* e, tlv_region_t region, size_t offset) {
    e->region = region;
    e->offset = offset;
    e->has_offset = 1;
}

tlv_result_t tlv_fields_decode(const void* context, const uint8_t* data, size_t size,
                               tlv_decoded_t* result, tlv_format_error_t* error) {
    const tlv_field_layout_t* f = (const tlv_field_layout_t*)context;
    tlv_tag_t tag = {0};
    tlv_size_t length = 0;
    size_t pos = 0, tag_size = 0, length_size = 0, trailer = 0, native;
    tlv_result_t rc;
    for (int step = 0; step < 2; ++step) {
        int identifier = (step == 0) == (f->order == TLV_ELEMENT_ORDER_TLV);
        if (identifier) {
            location(error, TLV_REGION_TAG, pos);
            rc = f->read_tag(f->context, data + pos, size - pos, &tag, &tag_size);
            if (rc != TLV_OK) return rc;
            if (!tag_size || tag_size > size - pos || (tag.size && !tag.data))
                return TLV_ERR_INVALID_TAG;
            error->tag = result->source.tag = range(pos, tag_size);
            pos += tag_size;
        } else {
            location(error, TLV_REGION_LENGTH, pos);
            if (f->resolve) {
                tlv_format_error_t resolved = {0};
                rc = f->resolve(f->context, &tag, data + pos, size - pos, &length_size, &length,
                                &trailer, &resolved);
                if (rc != TLV_OK && resolved.has_offset) {
                    error->region = resolved.region;
                    error->offset = pos + resolved.offset;
                    error->required = resolved.required;
                    error->has_required = resolved.has_required;
                }
            } else
                rc = f->read_length(f->context, data + pos, size - pos, &length, &length_size);
            error->length = range(pos, length_size <= size - pos ? length_size : size - pos);
            if (rc != TLV_OK) return rc;
            if (length_size > size - pos) return TLV_ERR_INVALID_LENGTH;
            if (f->scope == TLV_LENGTH_SCOPE_TAG_AND_VALUE && !length)
                return TLV_ERR_INVALID_LENGTH;
            result->source.length = error->length;
            pos += length_size;
        }
    }
    if (f->scope == TLV_LENGTH_SCOPE_TAG_AND_VALUE) {
        if (length < tag_size) {
            location(error, TLV_REGION_LENGTH, result->source.length.offset);
            return TLV_ERR_INVALID_LENGTH;
        }
        length -= tag_size;
    }
    location(error, TLV_REGION_VALUE, pos);
    error->required = length;
    error->has_required = 1;
    if (length > size - pos) return TLV_ERR_BUFFER_TOO_SHORT;
    native = (size_t)length;
    error->value = range(pos, native);
    location(error, TLV_REGION_TRAILER, pos + native);
    error->required = trailer;
    if (trailer > size - pos - native) return TLV_ERR_BUFFER_TOO_SHORT;
    result->element.tag = tag;
    result->element.value = (tlv_value_t){data + pos, length};
    result->source.header = range(0, pos);
    result->source.value = range(pos, native);
    result->source.trailer = range(pos + native, trailer);
    result->source.size = pos + native + trailer;
    return TLV_OK;
}

static tlv_result_t field_sizes(const tlv_field_layout_t* f, const tlv_element_t* element,
                                size_t* tag_size, size_t* length_size, tlv_size_t* count,
                                tlv_format_error_t* error) {
    tlv_result_t rc;
    location(error, TLV_REGION_TAG, 0);
    rc = f->write_tag(f->context, NULL, 0, &element->tag, tag_size);
    if (rc != TLV_OK) return rc;
    if (!*tag_size) return TLV_ERR_INVALID_TAG;
    *count = element->value.size;
    location(error, TLV_REGION_LENGTH, f->order == TLV_ELEMENT_ORDER_TLV ? *tag_size : 0);
    if (f->scope == TLV_LENGTH_SCOPE_TAG_AND_VALUE) {
        rc = tlv_size_add(*count, *tag_size, count);
        if (rc != TLV_OK) return rc;
    }
    return f->length_size(f->context, *count, length_size);
}

tlv_result_t tlv_fields_measure(const void* context, const tlv_element_t* element,
                                tlv_encoding_t* encoding, tlv_format_error_t* error) {
    const tlv_field_layout_t* f = (const tlv_field_layout_t*)context;
    size_t t = 0, l = 0;
    tlv_size_t count;
    tlv_result_t rc = field_sizes(f, element, &t, &l, &count, error);
    if (rc != TLV_OK) return rc;
    rc = tlv_size_add(t, l, &encoding->header);
    if (rc != TLV_OK) return rc;
    encoding->value = element->value.size;
    encoding->trailer = 0;
    return tlv_size_add(encoding->header, encoding->value, &encoding->total);
}

tlv_result_t tlv_fields_encode(const void* context, const tlv_element_t* element, uint8_t* data,
                               size_t capacity, size_t* written, tlv_format_error_t* error) {
    const tlv_field_layout_t* f = (const tlv_field_layout_t*)context;
    size_t t = 0, l = 0, v, used = 0, to, lo;
    tlv_size_t count;
    tlv_result_t rc = field_sizes(f, element, &t, &l, &count, error);
    if (rc != TLV_OK) return rc;
    rc = tlv_size_to_native(element->value.size, &v);
    if (rc != TLV_OK) return rc;
    if (t > capacity || l > capacity - t || v > capacity - t - l) return TLV_ERR_BUFFER_TOO_SHORT;
    to = f->order == TLV_ELEMENT_ORDER_TLV ? 0 : l;
    lo = f->order == TLV_ELEMENT_ORDER_TLV ? t : 0;
    location(error, TLV_REGION_TAG, to);
    rc = f->write_tag(f->context, data + to, t, &element->tag, &used);
    if (rc != TLV_OK) return rc;
    if (used != t) return TLV_ERR_INVALID_TAG;
    location(error, TLV_REGION_LENGTH, lo);
    rc = f->write_length(f->context, data + lo, l, count, &used);
    if (rc != TLV_OK) return rc;
    if (used != l) return TLV_ERR_INVALID_LENGTH;
    if (v) memcpy(data + t + l, element->value.data, v);
    *written = t + l + v;
    return TLV_OK;
}

tlv_result_t tlv_fields_format_init(tlv_format_t* format, const tlv_field_layout_t* f) {
    int read, write;
    if (!f || (f->order != TLV_ELEMENT_ORDER_TLV && f->order != TLV_ELEMENT_ORDER_LTV) ||
        (f->scope != TLV_LENGTH_SCOPE_VALUE && f->scope != TLV_LENGTH_SCOPE_TAG_AND_VALUE) ||
        (f->resolve && (f->order != TLV_ELEMENT_ORDER_TLV || f->scope != TLV_LENGTH_SCOPE_VALUE)))
        return TLV_ERR_INVALID_ARG;
    read = f->read_tag || f->read_length || f->resolve;
    write = f->write_tag || f->write_length || f->length_size;
    if ((read && !(f->read_tag && f->read_length)) ||
        (write && !(f->write_tag && f->write_length && f->length_size)))
        return TLV_ERR_INVALID_ARG;
    return tlv_format_init(format, f, read ? tlv_fields_decode : NULL,
                           write ? tlv_fields_measure : NULL, write ? tlv_fields_encode : NULL);
}

static tlv_result_t binary_tag_read(const void* ctx, const uint8_t* data, size_t size,
                                    tlv_tag_t* tag, size_t* used) {
    const tlv_binary_layout_t* f = (const tlv_binary_layout_t*)ctx;
    if (f->tag_size > size) return TLV_ERR_BUFFER_TOO_SHORT;
    *tag = tlv_tag(data, f->tag_size);
    *used = f->tag_size;
    return TLV_OK;
}

static tlv_result_t binary_tag_write(const void* ctx, uint8_t* data, size_t capacity,
                                     const tlv_tag_t* tag, size_t* used) {
    const tlv_binary_layout_t* f = (const tlv_binary_layout_t*)ctx;
    if (tag->size != f->tag_size) return TLV_ERR_INVALID_TAG_SIZE;
    if (!tag->data) return TLV_ERR_NULL_ARG;
    if (data && capacity < f->tag_size) return TLV_ERR_BUFFER_TOO_SHORT;
    if (data) memcpy(data, tag->data, f->tag_size);
    *used = f->tag_size;
    return TLV_OK;
}

static tlv_result_t binary_length_read(const void* ctx, const uint8_t* data, size_t size,
                                       tlv_size_t* length, size_t* used) {
    const tlv_binary_layout_t* f = (const tlv_binary_layout_t*)ctx;
    *used = size < f->length_size ? size : f->length_size;
    if (size < f->length_size) return TLV_ERR_BUFFER_TOO_SHORT;
    return tlv_read_uint(data, f->length_size, f->length_order, length);
}

static tlv_result_t binary_length_size(const void* ctx, tlv_size_t length, size_t* used) {
    const tlv_binary_layout_t* f = (const tlv_binary_layout_t*)ctx;
    if (f->length_size < 8 && length >= ((uint64_t)1 << (8 * f->length_size)))
        return TLV_ERR_INVALID_LENGTH;
    *used = f->length_size;
    return TLV_OK;
}

static tlv_result_t binary_length_write(const void* ctx, uint8_t* data, size_t capacity,
                                        tlv_size_t length, size_t* used) {
    const tlv_binary_layout_t* f = (const tlv_binary_layout_t*)ctx;
    tlv_result_t rc = binary_length_size(ctx, length, used);
    if (rc != TLV_OK || !data) return rc;
    if (capacity < f->length_size) return TLV_ERR_BUFFER_TOO_SHORT;
    return tlv_write_uint(data, f->length_size, f->length_order, length);
}

static tlv_field_layout_t binary_fields(const void* context) {
    const tlv_binary_layout_t* f = (const tlv_binary_layout_t*)context;
    tlv_field_layout_t fields = {
        context,          binary_tag_read,     binary_length_read, NULL,
        binary_tag_write, binary_length_write, binary_length_size, f->element_order,
        f->length_scope};
    return fields;
}

tlv_result_t tlv_binary_decode(const void* context, const uint8_t* data, size_t size,
                               tlv_decoded_t* result, tlv_format_error_t* error) {
    tlv_field_layout_t f = binary_fields(context);
    return tlv_fields_decode(&f, data, size, result, error);
}

tlv_result_t tlv_binary_measure(const void* context, const tlv_element_t* element,
                                tlv_encoding_t* encoding, tlv_format_error_t* error) {
    tlv_field_layout_t f = binary_fields(context);
    return tlv_fields_measure(&f, element, encoding, error);
}

tlv_result_t tlv_binary_encode(const void* context, const tlv_element_t* element, uint8_t* data,
                               size_t capacity, size_t* written, tlv_format_error_t* error) {
    tlv_field_layout_t f = binary_fields(context);
    return tlv_fields_encode(&f, element, data, capacity, written, error);
}
