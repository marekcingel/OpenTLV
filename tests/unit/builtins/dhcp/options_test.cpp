#include "tlv/builtins/dhcp/options.h"
#include <gtest/gtest.h>

TEST(Unit_Tlv_Dhcpv4, OptionDefinitionsMapUniqueOneByteCodes) {
    const struct {
        uint8_t     code;
        const char* name;
    } expected[] = {
        {0, "Pad"},
        {1, "Subnet Mask"},
        {3, "Router"},
        {6, "Domain Name Server"},
        {12, "Host Name"},
        {15, "Domain Name"},
        {50, "Requested IP Address"},
        {51, "IP Address Lease Time"},
        {53, "DHCP Message Type"},
        {54, "Server Identifier"},
        {55, "Parameter Request List"},
        {57, "Maximum DHCP Message Size"},
        {58, "Renewal Time Value"},
        {59, "Rebinding Time Value"},
        {60, "Vendor Class Identifier"},
        {61, "Client Identifier"},
        {255, "End"},
    };
    ASSERT_EQ(sizeof(expected) / sizeof(expected[0]), tlv_dhcpv4_options.count);
    for (const auto& entry : expected) {
        SCOPED_TRACE(entry.code);
        const auto  tag = tlv_tag(&entry.code, 1);
        const auto* definition = tlv_definition_find(&tlv_dhcpv4_options, &tag);
        ASSERT_NE(nullptr, definition);
        EXPECT_STREQ(entry.name, definition->name);
        EXPECT_EQ(1u, definition->tag.size);
        EXPECT_EQ(entry.code, definition->tag.data[0]);
    }
    for (size_t i = 0; i < tlv_dhcpv4_options.count; ++i) {
        for (size_t j = i + 1; j < tlv_dhcpv4_options.count; ++j) {
            EXPECT_FALSE(tlv_tag_equal(tlv_dhcpv4_options.entries[i].tag,
                                       tlv_dhcpv4_options.entries[j].tag));
        }
    }
    const uint8_t unknown = 0xE0;
    const auto    tag = tlv_tag(&unknown, 1);
    EXPECT_EQ(nullptr, tlv_definition_find(&tlv_dhcpv4_options, &tag));
    const uint8_t extended[] = {0, 53};
    const auto    wide_tag = tlv_tag(extended, sizeof(extended));
    EXPECT_EQ(nullptr, tlv_definition_find(&tlv_dhcpv4_options, &wide_tag));
}
