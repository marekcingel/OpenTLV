// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/builtins/bluetooth/ad_schema.h"

static const uint8_t identifiers[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                      0x08, 0x09, 0x0A, 0x16, 0x20, 0x21, 0xFF};

/* CSS Part A, Table 1.1 and sections 1.1-1.5, 1.11. Occurrences apply
 * to one AD block, without requiring external advertising context.
 * Local Name is bounded by Core Vol 3, Part C, section 3.2.2.3 (248 bytes). */
static const tlv_schema_entry_t fields[] = {
    {{identifiers + 0, 1}, 0, SIZE_MAX, 0, "Flags", 0},
    {{identifiers + 1, 1}, 0, SIZE_MAX, 0, "Incomplete 16-bit Service UUID List", 2},
    {{identifiers + 2, 1}, 0, SIZE_MAX, 0, "Complete 16-bit Service UUID List", 2},
    {{identifiers + 3, 1}, 0, SIZE_MAX, 0, "Incomplete 32-bit Service UUID List", 4},
    {{identifiers + 4, 1}, 0, SIZE_MAX, 0, "Complete 32-bit Service UUID List", 4},
    {{identifiers + 5, 1}, 0, SIZE_MAX, 0, "Incomplete 128-bit Service UUID List", 16},
    {{identifiers + 6, 1}, 0, SIZE_MAX, 0, "Complete 128-bit Service UUID List", 16},
    {{identifiers + 7, 1}, 0, 248, 0, "Shortened Local Name", 0},
    {{identifiers + 8, 1}, 0, 248, 0, "Complete Local Name", 0},
    {{identifiers + 9, 1}, 1, 1, 0, "Tx Power Level", 0},
    {{identifiers + 10, 1}, 2, SIZE_MAX, 0, "Service Data - 16-bit UUID", 0},
    {{identifiers + 11, 1}, 4, SIZE_MAX, 0, "Service Data - 32-bit UUID", 0},
    {{identifiers + 12, 1}, 16, SIZE_MAX, 0, "Service Data - 128-bit UUID", 0},
    {{identifiers + 13, 1}, 2, SIZE_MAX, 0, "Manufacturer Specific Data", 0}};

static const tlv_structure_rule_t rules[] = {
    {&fields[0], 0, 1, TLV_SCHEMA_PRIMITIVE, NULL, 0},
    {&fields[1], 0, 1, TLV_SCHEMA_PRIMITIVE, NULL, 1},
    {&fields[2], 0, 1, TLV_SCHEMA_PRIMITIVE, NULL, 1},
    {&fields[3], 0, 1, TLV_SCHEMA_PRIMITIVE, NULL, 2},
    {&fields[4], 0, 1, TLV_SCHEMA_PRIMITIVE, NULL, 2},
    {&fields[5], 0, 1, TLV_SCHEMA_PRIMITIVE, NULL, 3},
    {&fields[6], 0, 1, TLV_SCHEMA_PRIMITIVE, NULL, 3},
    {&fields[7], 0, 1, TLV_SCHEMA_PRIMITIVE, NULL, 4},
    {&fields[8], 0, 1, TLV_SCHEMA_PRIMITIVE, NULL, 4},
    {&fields[9], 0, SIZE_MAX, TLV_SCHEMA_PRIMITIVE, NULL, 0},
    {&fields[10], 0, SIZE_MAX, TLV_SCHEMA_PRIMITIVE, NULL, 0},
    {&fields[11], 0, SIZE_MAX, TLV_SCHEMA_PRIMITIVE, NULL, 0},
    {&fields[12], 0, SIZE_MAX, TLV_SCHEMA_PRIMITIVE, NULL, 0},
    {&fields[13], 0, SIZE_MAX, TLV_SCHEMA_PRIMITIVE, NULL, 0}};

static const tlv_structure_group_t groups[] = {
    {1, 0, 1, "16-bit Service UUID List"},
    {2, 0, 1, "32-bit Service UUID List"},
    {3, 0, 1, "128-bit Service UUID List"},
    {4, 0, 1, "Local Name"},
};

const tlv_structure_schema_t tlv_bluetooth_ad_schema = {
    rules,  sizeof(rules) / sizeof(rules[0]),   1,
    groups, sizeof(groups) / sizeof(groups[0]), TLV_SCHEMA_ORDER_ANY};
