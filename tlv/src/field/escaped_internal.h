// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_FIELD_ESCAPED_INTERNAL_H
#define OPENTLV_FIELD_ESCAPED_INTERNAL_H

#include "tlv/field/escaped.h"

static inline tlv_result_t validate_length(const tlv_escaped_length_t* f) {
    if (!f->escape || !f->extended_size || f->extended_size > 8 || f->min_extended > f->escape ||
        f->max_length < f->escape ||
        (f->extended_size < 8 && f->max_length >= (UINT64_C(1) << (8 * f->extended_size))))
        return TLV_ERR_INVALID_ARG;
    if (f->byte_order != TLV_BYTE_ORDER_BIG_ENDIAN && f->byte_order != TLV_BYTE_ORDER_LITTLE_ENDIAN)
        return TLV_ERR_INVALID_ARG;
    return TLV_OK;
}

#endif
