// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/formats/fixed.h"
tlv_result_t tlv_fixed_format_init(tlv_format_t* format, const tlv_fixed_format_t* config) {
    if (!format || !config || !config->tag_size || !config->length_size ||
        config->length_size > 8 ||
        (config->element_order != TLV_ELEMENT_ORDER_TLV &&
         config->element_order != TLV_ELEMENT_ORDER_LTV) ||
        (config->length_scope != TLV_LENGTH_SCOPE_VALUE &&
         config->length_scope != TLV_LENGTH_SCOPE_TAG_AND_VALUE))
        return TLV_ERR_INVALID_ARG;
    if (config->length_order != TLV_BYTE_ORDER_BIG_ENDIAN &&
        config->length_order != TLV_BYTE_ORDER_LITTLE_ENDIAN)
        return TLV_ERR_INVALID_BYTE_ORDER;
    return tlv_format_init(format, config, tlv_binary_decode, tlv_binary_measure,
                           tlv_binary_encode);
}
