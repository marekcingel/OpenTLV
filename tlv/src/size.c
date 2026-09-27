#include "tlv/size.h"

tlv_result_t tlv_size_from_native(size_t size, tlv_size_t* length) {
    if (!length) return TLV_ERR_NULL_ARG;
    *length = (tlv_size_t)size;
    return TLV_OK;
}

tlv_result_t tlv_size_to_native(tlv_size_t length, size_t* size) {
    if (!size) return TLV_ERR_NULL_ARG;
    if (length > (tlv_size_t)SIZE_MAX) return TLV_ERR_INVALID_LENGTH;
    *size = (size_t)length;
    return TLV_OK;
}

tlv_result_t tlv_size_validate_native(tlv_size_t length) {
    if (length > (tlv_size_t)SIZE_MAX) return TLV_ERR_INVALID_LENGTH;
    return TLV_OK;
}

tlv_result_t tlv_size_add(tlv_size_t a, tlv_size_t b, tlv_size_t* sum) {
    if (!sum) return TLV_ERR_NULL_ARG;
    if (b > TLV_SIZE_MAX - a) return TLV_ERR_OVERFLOW;
    *sum = a + b;
    return TLV_OK;
}
