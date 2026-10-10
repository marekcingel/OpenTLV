// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/field/packed.h"

static tlv_result_t packed_validate(const tlv_packed_field_t* f) {
    if (!f->storage_size || f->storage_size > 8 || !f->bit_width || f->bit_width > 64 ||
        f->bit_offset >= f->storage_size * 8 || f->bit_width > f->storage_size * 8 - f->bit_offset)
        return TLV_ERR_INVALID_ARG;
    if (f->byte_order != TLV_BYTE_ORDER_BIG_ENDIAN && f->byte_order != TLV_BYTE_ORDER_LITTLE_ENDIAN)
        return TLV_ERR_INVALID_ARG;
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
    if (size < field->storage_size) return TLV_ERR_TRUNCATED;
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
