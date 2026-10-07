// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/builtins/lldp/lldp.h"
#include "tlv/formats/packed.h"

/* Canonical Type bytes must survive subsequent decodes and shallow copies. */
static const uint8_t identifiers[128] = {
    0,   1,   2,   3,   4,   5,   6,   7,   8,   9,   10,  11,  12,  13,  14,  15,  16,  17,  18,
    19,  20,  21,  22,  23,  24,  25,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,  37,
    38,  39,  40,  41,  42,  43,  44,  45,  46,  47,  48,  49,  50,  51,  52,  53,  54,  55,  56,
    57,  58,  59,  60,  61,  62,  63,  64,  65,  66,  67,  68,  69,  70,  71,  72,  73,  74,  75,
    76,  77,  78,  79,  80,  81,  82,  83,  84,  85,  86,  87,  88,  89,  90,  91,  92,  93,  94,
    95,  96,  97,  98,  99,  100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113,
    114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127};

static const tlv_packed_layout_t lldp_layout = {2,
                                                {2, 9, 7, TLV_BYTE_ORDER_BIG_ENDIAN},
                                                {2, 0, 9, TLV_BYTE_ORDER_BIG_ENDIAN},
                                                TLV_LENGTH_SCOPE_VALUE,
                                                identifiers,
                                                1,
                                                sizeof(identifiers)};

const tlv_format_t tlv_format_lldp = {&lldp_layout, tlv_packed_decode, tlv_packed_measure,
                                      tlv_packed_encode, NULL};

static const tlv_definition_t types[] = {{{identifiers + 0, 1}, "End of LLDPDU"},
                                         {{identifiers + 1, 1}, "Chassis ID"},
                                         {{identifiers + 2, 1}, "Port ID"},
                                         {{identifiers + 3, 1}, "Time To Live"},
                                         {{identifiers + 4, 1}, "Port Description"},
                                         {{identifiers + 5, 1}, "System Name"},
                                         {{identifiers + 6, 1}, "System Description"},
                                         {{identifiers + 7, 1}, "System Capabilities"},
                                         {{identifiers + 8, 1}, "Management Address"},
                                         {{identifiers + 127, 1}, "Organisationally Specific"}};
const tlv_definition_registry_t tlv_lldp_types = {types, sizeof(types) / sizeof(types[0])};
