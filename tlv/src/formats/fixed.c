// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/formats/fixed.h"
#include "../field/fixed_internal.h"

tlv_result_t tlv_fixed_format_init(tlv_format_t* format, const tlv_fixed_format_t* config) {
    tlv_result_t rc;
    if (!format || !config) return TLV_ERR_NULL_ARG;
    rc = fixed_identifier_validate(&config->identifier);
    if (rc != TLV_OK) return rc;
    rc = fixed_length_validate(&config->length);
    if (rc != TLV_OK) return rc;
    if ((config->element_order != TLV_ELEMENT_ORDER_TLV &&
         config->element_order != TLV_ELEMENT_ORDER_LTV) ||
        (config->length_scope != TLV_LENGTH_SCOPE_VALUE &&
         config->length_scope != TLV_LENGTH_SCOPE_TAG_AND_VALUE))
        return TLV_ERR_INVALID_ARG;
    return tlv_format_init(format, config, tlv_binary_decode, tlv_binary_measure,
                           tlv_binary_encode);
}
