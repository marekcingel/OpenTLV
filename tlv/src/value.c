// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/value.h"
#include <string.h>

tlv_result_t tlv_value_init(const uint8_t* data, tlv_size_t length, tlv_value_t* value) {
    tlv_result_t rc;
    if (!value || (!data && length)) return TLV_ERR_NULL_ARG;
    rc = tlv_size_validate_native(length);
    if (rc != TLV_OK) return rc;
    value->data = data;
    value->size = length;
    return TLV_OK;
}

tlv_result_t tlv_value_validate(const tlv_value_t* value) {
    if (!value || (!value->data && value->size)) return TLV_ERR_NULL_ARG;
    return tlv_size_validate_native(value->size);
}

bool tlv_value_equal(tlv_value_t lhs, tlv_value_t rhs) {
    if (lhs.size != rhs.size) return false;
    if (lhs.size == 0) return true;
    return memcmp(lhs.data, rhs.data, (size_t)lhs.size) == 0;
}

int tlv_value_compare(tlv_value_t lhs, tlv_value_t rhs) {
    size_t common;
    int order;
    common = (size_t)(lhs.size < rhs.size ? lhs.size : rhs.size);
    order = common == 0 ? 0 : memcmp(lhs.data, rhs.data, common);
    if (order != 0) return order < 0 ? -1 : 1;
    if (lhs.size == rhs.size) return 0;
    return lhs.size < rhs.size ? -1 : 1;
}

bool tlv_value_is_empty(tlv_value_t value) {
    return value.size == 0;
}

tlv_result_t tlv_value_slice(tlv_value_t value, tlv_size_t offset, tlv_size_t length,
                             tlv_value_t* out) {
    tlv_size_t end;
    tlv_result_t rc;
    if (!out) return TLV_ERR_NULL_ARG;
    rc = tlv_value_validate(&value);
    if (rc != TLV_OK) return rc;
    rc = tlv_size_add(offset, length, &end);
    if (rc != TLV_OK) return rc;
    if (end > value.size) return TLV_ERR_INVALID_LENGTH;
    out->data = length == 0 ? NULL : value.data + (size_t)offset;
    out->size = length;
    return TLV_OK;
}

tlv_result_t tlv_value_copy(tlv_value_t value, uint8_t* data, size_t capacity, size_t* written) {
    size_t length;
    tlv_result_t rc;
    if (!written) return TLV_ERR_NULL_ARG;
    rc = tlv_size_to_native(value.size, &length);
    if (rc != TLV_OK) return rc;
    if (!data && capacity) return TLV_ERR_NULL_ARG;
    if (!value.data && length) return TLV_ERR_NULL_ARG;
    if (!data) {
        *written = length;
        return TLV_OK;
    }
    if (capacity < length) return TLV_ERR_BUFFER_TOO_SHORT;
    if (length) memmove(data, value.data, length);
    *written = length;
    return TLV_OK;
}
