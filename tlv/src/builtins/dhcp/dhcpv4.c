// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/builtins/dhcp/dhcpv4.h"
#include "tlv/formats/compose.h"

static const uint8_t codes[] = {0, 255};
static const tlv_tag_t tag_only[] = {{&codes[0], 1}, {&codes[1], 1}};
static const tlv_tagged_binary_composition_t options = {
    {{1}, {1, TLV_BYTE_ORDER_BIG_ENDIAN}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE},
    tag_only,
    2};

const tlv_format_t tlv_format_dhcpv4 = {&options, tlv_tagged_binary_decode,
                                        tlv_tagged_binary_measure, tlv_tagged_binary_encode, NULL};
