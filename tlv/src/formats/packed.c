// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/formats/packed.h"
#include <limits.h>
#include <string.h>

static uint64_t mask(unsigned int width) {
    return width == 64 ? UINT64_MAX : (UINT64_C(1) << width) - 1;
}

static tlv_range_t envelope(const tlv_packed_field_t* field) {
    size_t first = field->bit_offset / 8;
    size_t last = (field->bit_offset + field->bit_width - 1) / 8;
    size_t offset =
        field->byte_order == TLV_BYTE_ORDER_LITTLE_ENDIAN ? first : field->storage_size - last - 1;
    return (tlv_range_t){offset, last - first + 1, 1};
}

tlv_result_t tlv_packed_layout_validate(const tlv_packed_layout_t* f) {
    const uint8_t zero[8] = {0};
    uint64_t ignored;
    size_t entries;
    tlv_result_t rc;
    if (!f || !f->tag_storage) return TLV_ERR_NULL_ARG;
    if (!f->header_size || f->header_size > 8 || f->tag.storage_size != f->header_size ||
        f->length.storage_size != f->header_size)
        return TLV_ERR_INVALID_ARG;
    rc = tlv_packed_field_read(&f->tag, zero, sizeof(zero), &ignored);
    if (rc != TLV_OK) return rc;
    rc = tlv_packed_field_read(&f->length, zero, sizeof(zero), &ignored);
    if (rc != TLV_OK) return rc;
    if (f->tag.byte_order != f->length.byte_order ||
        (f->tag.bit_offset < f->length.bit_offset + f->length.bit_width &&
         f->length.bit_offset < f->tag.bit_offset + f->tag.bit_width) ||
        (f->length_scope != TLV_LENGTH_SCOPE_VALUE &&
         f->length_scope != TLV_LENGTH_SCOPE_TAG_AND_VALUE) ||
        f->tag_size < (f->tag.bit_width + 7) / 8 || f->tag_size > 8)
        return TLV_ERR_INVALID_ARG;
    if (f->tag.bit_width >= sizeof(size_t) * CHAR_BIT) return TLV_ERR_OVERFLOW;
    entries = (size_t)1 << f->tag.bit_width;
    if (entries > SIZE_MAX / f->tag_size) return TLV_ERR_OVERFLOW;
    if (f->tag_storage_size < entries * f->tag_size) return TLV_ERR_INVALID_ARG;
    return TLV_OK;
}

/* Failure detail is published only on failure, from ranges already computed. */
static tlv_result_t packed_failure(tlv_format_error_t* error, tlv_result_t rc, tlv_region_t region,
                                   size_t offset, tlv_size_t required, tlv_range_t tag,
                                   tlv_range_t length, tlv_range_t value) {
    error->region = region;
    error->offset = offset;
    error->has_offset = 1;
    error->required = required;
    error->has_required = 1;
    error->tag = tag;
    error->length = length;
    error->value = value;
    return rc;
}

tlv_result_t tlv_packed_decode(const void* context, const uint8_t* data, size_t size,
                               tlv_decoded_t* result, tlv_format_error_t* error) {
    const tlv_packed_layout_t* f = (const tlv_packed_layout_t*)context;
    const tlv_range_t none = {0};
    tlv_decoded_t decoded = {0};
    tlv_range_t tag, count_field;
    uint64_t type, count, canonical;
    size_t length;
    tlv_result_t rc;
    if ((!data && size) || !result || !error) return TLV_ERR_NULL_ARG;
    rc = tlv_packed_layout_validate(f);
    if (rc != TLV_OK) return rc;
    if (size < f->header_size)
        return packed_failure(error, TLV_ERR_BUFFER_TOO_SHORT, TLV_REGION_HEADER, 0, f->header_size,
                              none, none, none);
    tag = envelope(&f->tag);
    count_field = envelope(&f->length);
    (void)tlv_packed_field_read(&f->tag, data, size, &type);
    (void)tlv_packed_field_read(&f->length, data, size, &count);
    if (f->length_scope == TLV_LENGTH_SCOPE_TAG_AND_VALUE) {
        if (count < tag.size)
            return packed_failure(error, TLV_ERR_INVALID_LENGTH, TLV_REGION_LENGTH,
                                  count_field.offset, f->header_size, tag, count_field, none);
        count -= tag.size;
    }
    if (count > size - f->header_size)
        return packed_failure(error, TLV_ERR_BUFFER_TOO_SHORT, TLV_REGION_VALUE, f->header_size,
                              count, tag, count_field,
                              (tlv_range_t){f->header_size, size - f->header_size, 1});
    length = (size_t)count;
    decoded.element.tag = tlv_tag(f->tag_storage + (size_t)type * f->tag_size, f->tag_size);
    (void)tlv_read_uint(decoded.element.tag.data, f->tag_size, TLV_BYTE_ORDER_BIG_ENDIAN,
                        &canonical);
    if (canonical != type)
        return packed_failure(error, TLV_ERR_INVALID_TAG, TLV_REGION_TAG, tag.offset, count, tag,
                              count_field, (tlv_range_t){f->header_size, length, 1});
    decoded.element.value = (tlv_value_t){data + f->header_size, length};
    decoded.source.header = (tlv_range_t){0, f->header_size, 1};
    decoded.source.tag = tag;
    decoded.source.length = count_field;
    decoded.source.value = (tlv_range_t){f->header_size, length, 1};
    decoded.source.trailer = (tlv_range_t){f->header_size + length, 0, 1};
    decoded.source.size = f->header_size + length;
    decoded.source.tag_binding = TLV_TAG_BINDING_FORMAT;
    *result = decoded;
    return TLV_OK;
}

static tlv_result_t field_failure(tlv_format_error_t* error, tlv_result_t rc, tlv_region_t region,
                                  const tlv_packed_field_t* field) {
    error->region = region;
    error->offset = envelope(field).offset;
    error->has_offset = 1;
    return rc;
}

tlv_result_t tlv_packed_measure(const void* context, const tlv_element_t* element,
                                tlv_encoding_t* result, tlv_format_error_t* error) {
    const tlv_packed_layout_t* f = (const tlv_packed_layout_t*)context;
    uint64_t type, overhead, maximum;
    tlv_result_t rc;
    if (!element || !result || !error) return TLV_ERR_NULL_ARG;
    rc = tlv_packed_layout_validate(f);
    if (rc != TLV_OK) return rc;
    if (!element->tag.data && element->tag.size)
        rc = TLV_ERR_NULL_ARG;
    else if (element->tag.size != f->tag_size)
        rc = TLV_ERR_INVALID_TAG_SIZE;
    else {
        (void)tlv_read_uint(element->tag.data, f->tag_size, TLV_BYTE_ORDER_BIG_ENDIAN, &type);
        if (type > mask(f->tag.bit_width)) rc = TLV_ERR_INVALID_TAG;
    }
    if (rc != TLV_OK) return field_failure(error, rc, TLV_REGION_TAG, &f->tag);
    overhead = f->length_scope == TLV_LENGTH_SCOPE_TAG_AND_VALUE ? envelope(&f->tag).size : 0;
    maximum = mask(f->length.bit_width);
    if (overhead > maximum || element->value.size > maximum - overhead ||
        element->value.size > UINT64_MAX - f->header_size)
        return field_failure(error, TLV_ERR_INVALID_LENGTH, TLV_REGION_LENGTH, &f->length);
    *result = (tlv_encoding_t){f->header_size, element->value.size, 0,
                               f->header_size + element->value.size};
    return TLV_OK;
}

tlv_result_t tlv_packed_encode(const void* context, const tlv_element_t* element, uint8_t* data,
                               size_t capacity, size_t* written, tlv_format_error_t* error) {
    const tlv_packed_layout_t* f = (const tlv_packed_layout_t*)context;
    tlv_encoding_t sizes;
    uint64_t type, count;
    tlv_result_t rc;
    if (!data || !written) return TLV_ERR_NULL_ARG;
    rc = tlv_packed_measure(context, element, &sizes, error);
    if (rc != TLV_OK) return rc;
    if (element->value.size && !element->value.data)
        rc = TLV_ERR_NULL_ARG;
    else if (sizes.total > capacity)
        rc = TLV_ERR_BUFFER_TOO_SHORT;
    if (rc != TLV_OK) return field_failure(error, rc, TLV_REGION_LENGTH, &f->length);
    (void)tlv_read_uint(element->tag.data, f->tag_size, TLV_BYTE_ORDER_BIG_ENDIAN, &type);
    count = element->value.size;
    if (f->length_scope == TLV_LENGTH_SCOPE_TAG_AND_VALUE) count += envelope(&f->tag).size;
    memset(data, 0, f->header_size);
    (void)tlv_packed_field_write(&f->tag, data, capacity, type);
    (void)tlv_packed_field_write(&f->length, data, capacity, count);
    if (element->value.size)
        memcpy(data + f->header_size, element->value.data, (size_t)element->value.size);
    *written = (size_t)sizes.total;
    return TLV_OK;
}
