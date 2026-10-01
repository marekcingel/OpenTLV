#include "tlv++/tlv.hpp"
#include <gtest/gtest.h>
#include <cstring>

TEST(Integration_Tlvpp_Dhcpv4, ContainerUsesSharedRulesAndDiagnostics) {
    const uint8_t    wire[] = {0, 53, 1, 3, 0, 255, 0};
    size_t           significant = 999;
    tlv_diagnostic_t diagnostic{};
    ASSERT_EQ(TLV_OK, tlv::dhcpv4_options_validate(wire, sizeof(wire), nullptr, 4, significant));
    EXPECT_EQ(6u, significant);
    const tlv_dhcpv4_options_rules_t rules{1, TLV_DHCPV4_OPTIONS_TAIL_EMPTY};
    EXPECT_EQ(TLV_ERR_SCHEMA, tlv::dhcpv4_options_validate(wire, sizeof(wire), &rules, 4,
                                                           significant, &diagnostic));
    EXPECT_EQ(6u, significant);
    EXPECT_EQ(6u, diagnostic.offset);
}

TEST(Integration_Tlvpp_Dhcpv4, SharedPresetReaderWriterRoundTrip) {
    EXPECT_EQ(&tlv_format_dhcpv4, &tlv::dhcpv4_format());
    const uint8_t wire[] = {0, 53, 1, 1, 255, 0};
    tlv::byte     output[sizeof(wire)]{};
    tlv::reader   reader(tlv::bytes(reinterpret_cast<const tlv::byte*>(wire), sizeof(wire)),
                         tlv::dhcpv4_format());
    tlv::writer   writer(output, sizeof(output), tlv::dhcpv4_format());
    size_t        count = 0;
    while (!reader.at_end()) {
        auto element = reader.next();
        ASSERT_TRUE(element);
        ASSERT_TRUE(writer.write(*element));
        ++count;
    }
    EXPECT_EQ(4u, count);
    EXPECT_EQ(0, std::memcmp(wire, output, sizeof(wire)));
}
