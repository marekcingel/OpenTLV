// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "controlled_format.h"
#include "tlv/builtins/asn1/ber.h"
#include "tlv/copy.h"
#include "tlv/reader/reader.h"
#include <gtest/gtest.h>
#include <cstring>
#include <limits>

TEST(Integration_Tlv_Copy, ValueOutlivesInputWhileReaderRemainsZeroCopy) {
    uint8_t       input[] = {1, 2, 0xAB, 0xCD};
    tlv_element_t element{};
    size_t        consumed = 0, written = 99;
    ASSERT_EQ(TLV_OK, tlv_read(input, sizeof(input), &controlled::format, &element, &consumed));
    EXPECT_EQ(input + 2, element.value.data);
    ASSERT_EQ(TLV_OK, tlv_copy_value(&element, nullptr, 0, &written));
    EXPECT_EQ(2u, written);
    uint8_t owned[3] = {};
    ASSERT_EQ(TLV_OK, tlv_copy_value(&element, owned, sizeof(owned), &written));
    EXPECT_EQ(2u, written);
    std::memset(input, 0, sizeof(input));
    EXPECT_EQ(0u, element.value.data[0]);
    EXPECT_EQ(0xAB, owned[0]);
    EXPECT_EQ(0xCD, owned[1]);
    EXPECT_EQ(0, owned[2]);
}

TEST(Integration_Tlv_Copy, EncodedRangePreservesHeaderWhileElementUsesSelectedFormat) {
    uint8_t       input[] = {0x5A, 0x81, 1, 0xAB}; // Nonminimal BER length.
    tlv_element_t element{};
    size_t        consumed = 0, written = 99;
    ASSERT_EQ(TLV_OK, tlv_read(input, sizeof(input), &tlv_format_ber, &element, &consumed));
    ASSERT_EQ(TLV_OK, tlv_copy_encoded(input, consumed, nullptr, 0, &written));
    EXPECT_EQ(sizeof(input), written);
    uint8_t exact[4] = {}, encoded[3] = {};
    ASSERT_EQ(TLV_OK, tlv_copy_encoded(input, consumed, exact, sizeof(exact), &written));
    EXPECT_EQ(0, std::memcmp(input, exact, sizeof(input)));
    ASSERT_EQ(TLV_OK, tlv_copy_element(&element, &tlv_format_ber, nullptr, 0, &written));
    EXPECT_EQ(sizeof(encoded), written);
    ASSERT_EQ(TLV_OK,
              tlv_copy_element(&element, &tlv_format_ber, encoded, sizeof(encoded), &written));
    EXPECT_EQ(sizeof(encoded), written);
    const uint8_t expected[] = {0x5A, 1, 0xAB};
    EXPECT_EQ(0, std::memcmp(expected, encoded, sizeof(expected)));
    std::memset(input, 0, sizeof(input));
    EXPECT_EQ(0xAB, exact[3]);
    EXPECT_EQ(0xAB, encoded[2]);
}
