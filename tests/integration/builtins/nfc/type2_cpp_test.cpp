// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv++/tlv.hpp"
#include <gtest/gtest.h>
#include <cstring>

TEST(Integration_Tlvpp_NfcType2, SharedPresetReaderWriterRoundTrip) {
    EXPECT_EQ(&tlv_format_nfc_type2, &tlv::native::nfc_type2_format());
    const uint8_t wire[] = {0, 3, 3, 0xD1, 1, 0, 0xFE};
    tlv::byte     output[sizeof(wire)]{};
    tlv::reader<> reader(tlv::bytes(reinterpret_cast<const tlv::byte*>(wire), sizeof(wire)),
                         tlv::nfc::format{});
    tlv::writer<> writer(output, sizeof(output), tlv::nfc::format{});
    size_t        count = 0;
    while (!reader.at_end()) {
        auto element = reader.next();
        ASSERT_TRUE(element);
        ASSERT_TRUE(writer.write(*element));
        ++count;
    }
    EXPECT_EQ(3u, count);
    EXPECT_EQ(0, std::memcmp(wire, output, sizeof(wire)));
}
