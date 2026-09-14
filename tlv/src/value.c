#include "tlv/value.h"

tlv_result_t tlv_value_init(const uint8_t* data, tlv_length_t length,
                            tlv_value_t* value) {
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
