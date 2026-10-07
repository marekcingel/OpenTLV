// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/builtins/bluetooth/bluetooth_ltv.h"
#include "tlv/formats/compose.h"

/* Bluetooth LTV is the configurable Fixed format with the length field
 * before the tag, counting the tag as well as the value: length = tag_size(1)
 * + value_size, so a structure occupies length + 1 bytes and carries at most
 * 254 value bytes. */
static const tlv_binary_composition_t bluetooth_ltv_config = {
    {/* tag_size */ 1},
    {/* length_size */ 1, /* length_order */ TLV_BYTE_ORDER_BIG_ENDIAN},
    /* element_order */ TLV_ELEMENT_ORDER_LTV,
    /* length_scope */ TLV_LENGTH_SCOPE_TAG_AND_VALUE};

const tlv_format_t tlv_format_bluetooth_ltv = {&bluetooth_ltv_config, tlv_binary_decode,
                                               tlv_binary_measure, tlv_binary_encode, NULL};
