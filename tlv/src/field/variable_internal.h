// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_FIELD_VARIABLE_INTERNAL_H
#define OPENTLV_FIELD_VARIABLE_INTERNAL_H

#include "tlv/field/variable.h"

static inline int single_bit(uint8_t bit) {
    return bit && !(bit & (bit - 1));
}

static inline tlv_result_t identifier_validate(const tlv_variable_identifier_t* c) {
    if (!c->inline_mask || (c->escape & ~c->inline_mask) || !single_bit(c->continuation_bit) ||
        !c->payload_mask || (c->continuation_bit & c->payload_mask) || !c->max_size)
        return TLV_ERR_INVALID_ARG;
    if (c->policy && ((!c->policy->forbidden_leading && c->policy->forbidden_leading_count) ||
                      c->policy->reject_zero_first_payload > 1 || c->policy->require_minimal > 1))
        return TLV_ERR_INVALID_ARG;
    return TLV_OK;
}

static inline tlv_result_t length_validate(const tlv_variable_length_t* c) {
    if (!single_bit(c->long_form_bit) || !c->payload_mask || (c->long_form_bit & c->payload_mask))
        return TLV_ERR_INVALID_ARG;
    if (c->byte_order != TLV_BYTE_ORDER_BIG_ENDIAN && c->byte_order != TLV_BYTE_ORDER_LITTLE_ENDIAN)
        return TLV_ERR_INVALID_BYTE_ORDER;
    if (c->policy &&
        (c->policy->allow_short > 1 || c->policy->allow_long > 1 ||
         c->policy->require_minimal > 1 || (!c->policy->allow_short && !c->policy->allow_long) ||
         (c->policy->allow_long && !c->policy->max_long_octets)))
        return TLV_ERR_INVALID_ARG;
    return TLV_OK;
}

#endif
