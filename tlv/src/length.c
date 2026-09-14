#include "tlv/length.h"

tlv_result_t tlv_length_from_size(size_t size, tlv_length_t* length) {
    if (!length) return TLV_ERR_NULL_ARG;
    *length = (tlv_length_t)size;
    return TLV_OK;
}

tlv_result_t tlv_length_to_size(tlv_length_t length, size_t* size) {
    if (!size) return TLV_ERR_NULL_ARG;
    if (length > (tlv_length_t)SIZE_MAX) return TLV_ERR_INVALID_LENGTH;
    *size = (size_t)length;
    return TLV_OK;
}

tlv_result_t tlv_length_validate_native(tlv_length_t length) {
    if (length > (tlv_length_t)SIZE_MAX) return TLV_ERR_INVALID_LENGTH;
    return TLV_OK;
}
