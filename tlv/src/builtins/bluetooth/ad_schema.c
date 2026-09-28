#include "tlv/builtins/bluetooth/ad_schema.h"

static const uint8_t identifiers[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                      0x08, 0x09, 0x0A, 0x16, 0x20, 0x21, 0xFF};

/* CSS Part A, Table 1.1 and sections 1.1-1.5, 1.11. Occurrences apply
 * to one AD block, without requiring external advertising context.
 * Local Name is bounded by Core Vol 3, Part C, section 3.2.2.3 (248 bytes). */
#define AD_RULE(index, min, max, multiple, occurs, group, name)                                    \
    {{{identifiers + index, 1}, min, max, 0, name, multiple},                                      \
     0,                                                                                            \
     occurs,                                                                                       \
     TLV_SCHEMA_PRIMITIVE,                                                                         \
     NULL,                                                                                         \
     group}

static const tlv_structure_rule_t rules[] = {
    AD_RULE(0, 0, SIZE_MAX, 0, 1, 0, "Flags"),
    AD_RULE(1, 0, SIZE_MAX, 2, 1, 1, "Incomplete 16-bit Service UUID List"),
    AD_RULE(2, 0, SIZE_MAX, 2, 1, 1, "Complete 16-bit Service UUID List"),
    AD_RULE(3, 0, SIZE_MAX, 4, 1, 2, "Incomplete 32-bit Service UUID List"),
    AD_RULE(4, 0, SIZE_MAX, 4, 1, 2, "Complete 32-bit Service UUID List"),
    AD_RULE(5, 0, SIZE_MAX, 16, 1, 3, "Incomplete 128-bit Service UUID List"),
    AD_RULE(6, 0, SIZE_MAX, 16, 1, 3, "Complete 128-bit Service UUID List"),
    AD_RULE(7, 0, 248, 0, 1, 4, "Shortened Local Name"),
    AD_RULE(8, 0, 248, 0, 1, 4, "Complete Local Name"),
    AD_RULE(9, 1, 1, 0, SIZE_MAX, 0, "Tx Power Level"),
    AD_RULE(10, 2, SIZE_MAX, 0, SIZE_MAX, 0, "Service Data - 16-bit UUID"),
    AD_RULE(11, 4, SIZE_MAX, 0, SIZE_MAX, 0, "Service Data - 32-bit UUID"),
    AD_RULE(12, 16, SIZE_MAX, 0, SIZE_MAX, 0, "Service Data - 128-bit UUID"),
    AD_RULE(13, 2, SIZE_MAX, 0, SIZE_MAX, 0, "Manufacturer Specific Data"),
};
#undef AD_RULE

static const tlv_structure_group_t groups[] = {
    {1, 0, 1, "16-bit Service UUID List"},
    {2, 0, 1, "32-bit Service UUID List"},
    {3, 0, 1, "128-bit Service UUID List"},
    {4, 0, 1, "Local Name"},
};

const tlv_structure_schema_t tlv_bluetooth_ad_schema = {
    rules,  sizeof(rules) / sizeof(rules[0]),   1,
    groups, sizeof(groups) / sizeof(groups[0]), TLV_SCHEMA_ORDER_ANY};
