// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/builtins/emv/format.h"
#include "tlv/formats/variable.h"

/* Book 3 v4.4 Annex B: raw EMV identifiers, not ASN.1 number semantics. */
static const uint8_t forbidden[] = {0};
static const tlv_identifier_policy_t tag_policy = {forbidden, sizeof(forbidden), 1, 0};
static const tlv_length_policy_t length_policy = {1, 1, 0, 2, 65535};
static const tlv_constructed_bit_t constructed = {0, 0x20, 0x20};
static const tlv_variable_format_t config = {
    {0x1F, 0x1F, 0x80, 0x7F, 2, &tag_policy},
    {0x80, 0x7F, TLV_BYTE_ORDER_BIG_ENDIAN, &length_policy},
    TLV_ELEMENT_ORDER_TLV,
    TLV_LENGTH_SCOPE_VALUE,
    &constructed};

const tlv_format_t tlv_format_emv = {&config, tlv_variable_decode, tlv_variable_measure,
                                     tlv_variable_encode, tlv_variable_is_constructed};
