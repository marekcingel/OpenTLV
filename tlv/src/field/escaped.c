// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "escaped_internal.h"

tlv_result_t tlv_escaped_length_read(const tlv_escaped_length_t* f, const uint8_t* data,
                                     size_t size, tlv_size_t* length, size_t* consumed) {
    uint64_t value;
    size_t width;
    tlv_result_t rc;
    if (!f || !length || !consumed || (!data && size)) return TLV_ERR_NULL_ARG;
    rc = validate_length(f);
    if (rc != TLV_OK) return rc;
    *consumed = 0;
    if (!size) return TLV_ERR_TRUNCATED;
    *consumed = 1;
    if (data[0] > f->escape) return TLV_ERR_INVALID_LENGTH;
    if (data[0] < f->escape) {
        *length = data[0];
        return TLV_OK;
    }
    width = 1 + f->extended_size;
    *consumed = size < width ? size : width;
    if (size < width) return TLV_ERR_TRUNCATED;
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
