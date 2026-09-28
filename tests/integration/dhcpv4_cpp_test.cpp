#include "tlv++/tlv.hpp"
#include <gtest/gtest.h>
#include <cstring>

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
        auto value = tlv::as_bytes(element->value);
        ASSERT_TRUE(value);
        ASSERT_TRUE(writer.write(element->tag, *value));
        ++count;
    }
    EXPECT_EQ(4u, count);
    EXPECT_EQ(0, std::memcmp(wire, output, sizeof(wire)));
}
