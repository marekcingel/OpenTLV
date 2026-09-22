#include "tlv/value.h"
#include <string.h>

tlv_result_t tlv_value_init(const uint8_t* data, tlv_length_t length, tlv_value_t* value) {
    tlv_result_t rc;
    if (!value || (!data && length)) return TLV_ERR_NULL_ARG;
    rc = tlv_length_validate_native(length);
    if (rc != TLV_OK) return rc;
    value->data = data;
    value->length = length;
    return TLV_OK;
}

tlv_result_t tlv_value_validate(const tlv_value_t* value) {
    if (!value || (!value->data && value->length)) return TLV_ERR_NULL_ARG;
    return tlv_length_validate_native(value->length);
}

bool tlv_value_equal(tlv_value_t lhs, tlv_value_t rhs) {
    if (lhs.length != rhs.length) return false;
    if (lhs.length == 0) return true;
    return memcmp(lhs.data, rhs.data, (size_t)lhs.length) == 0;
}

int tlv_value_compare(tlv_value_t lhs, tlv_value_t rhs) {
    size_t common;
    int order;
    common = (size_t)(lhs.length < rhs.length ? lhs.length : rhs.length);
    order = common == 0 ? 0 : memcmp(lhs.data, rhs.data, common);
    if (order != 0) return order < 0 ? -1 : 1;
    if (lhs.length == rhs.length) return 0;
    return lhs.length < rhs.length ? -1 : 1;
}

bool tlv_value_is_empty(tlv_value_t value) {
    return value.length == 0;
}

tlv_result_t tlv_value_slice(tlv_value_t value, tlv_length_t offset, tlv_length_t length,
                             tlv_value_t* out) {
    tlv_length_t end;
    tlv_result_t rc;
    if (!out) return TLV_ERR_NULL_ARG;
    rc = tlv_value_validate(&value);
    if (rc != TLV_OK) return rc;
    rc = tlv_length_add(offset, length, &end);
    if (rc != TLV_OK) return rc;
    if (end > value.length) return TLV_ERR_INVALID_LENGTH;
    out->data = length == 0 ? NULL : value.data + (size_t)offset;
    out->length = length;
    return TLV_OK;
}

tlv_result_t tlv_value_copy(tlv_value_t value, uint8_t* data, size_t capacity, size_t* written) {
    size_t length;
    tlv_result_t rc;
    if (!written) return TLV_ERR_NULL_ARG;
    rc = tlv_length_to_size(value.length, &length);
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
