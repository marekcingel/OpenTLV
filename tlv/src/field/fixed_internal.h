// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_FIELD_FIXED_INTERNAL_H
#define OPENTLV_FIELD_FIXED_INTERNAL_H

#include "tlv/field/fixed.h"

static inline tlv_result_t fixed_identifier_validate(const tlv_fixed_identifier_t* config) {
    return config->size ? TLV_OK : TLV_ERR_INVALID_ARG;
}

static inline tlv_result_t fixed_length_validate(const tlv_fixed_length_t* config) {
    if (!config->size || config->size > 8) return TLV_ERR_INVALID_ARG;
    if (config->byte_order != TLV_BYTE_ORDER_BIG_ENDIAN &&
        config->byte_order != TLV_BYTE_ORDER_LITTLE_ENDIAN)
        return TLV_ERR_INVALID_ARG;
    return TLV_OK;
}

#endif
