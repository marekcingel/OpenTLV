// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/codec/digits.h"
#include <gtest/gtest.h>
#include <cstring>

TEST(Unit_Tlv_Digits, LeadingZerosOddDigitsAndFixedWidthPadding) {
    const tlv_digits_codec_config_t config = {4};
    const tlv_codec_t               codec = tlv_digits_codec(&config);
    const uint8_t                   expected[] = {0x00, 0x12, 0x3F, 0xFF};
    uint8_t                         wire[4] = {};
    size_t                          written = 0;
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_encode(&codec, "00123", 5, wire, sizeof(wire), &written));
    EXPECT_EQ(4u, written);
    EXPECT_EQ(0, std::memcmp(expected, wire, sizeof(wire)));
    char decoded[6] = {};
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_decode(&codec, wire, sizeof(wire), decoded, sizeof(decoded)));
    EXPECT_STREQ("00123", decoded);
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_encode(&codec, "00123", 5, nullptr, 0, &written));
    EXPECT_EQ(4u, written);
}

TEST(Unit_Tlv_Digits, RejectsInvalidNibblesAndDigitsFollowingPaddingWithoutWrites) {
    const tlv_digits_codec_config_t config = {0};
    char                            output[5] = "keep";
    for (unsigned byte = 0; byte < 256; ++byte) {
        const uint8_t wire = static_cast<uint8_t>(byte);
        const bool    valid =
            byte == 255 || ((byte >> 4) <= 9 && ((byte & 15) <= 9 || (byte & 15) == 15));
        std::memcpy(output, "keep", sizeof(output));
        EXPECT_EQ(valid ? TLV_CODEC_OK : TLV_CODEC_ERR_INVALID_VALUE,
                  tlv_digits_decode(&config, &wire, 1, output, sizeof(output)));
        if (!valid) EXPECT_STREQ("keep", output);
    }
    const uint8_t interrupted[] = {0x1F, 0x23};
    std::memcpy(output, "keep", sizeof(output));
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_digits_decode(&config, interrupted, 2, output, sizeof(output)));
    EXPECT_STREQ("keep", output);
    const uint8_t valid[] = {0x12, 0x3F};
    EXPECT_EQ(TLV_CODEC_ERR_BUFFER_TOO_SHORT, tlv_digits_decode(&config, valid, 2, output, 3));
    EXPECT_STREQ("keep", output);
}

TEST(Unit_Tlv_Digits, EmptyAndNoncanonicalPaddingAreExplicit) {
    const tlv_digits_codec_config_t config = {0};
    const uint8_t                   padding[] = {0xFF, 0xFF};
    char                            decoded[1] = {'x'};
    ASSERT_EQ(TLV_CODEC_OK, tlv_digits_decode(&config, padding, 2, decoded, 1));
    EXPECT_EQ('\0', decoded[0]);
    size_t written = 9;
    EXPECT_EQ(TLV_CODEC_OK, tlv_digits_encode(&config, "", 0, nullptr, 0, &written));
    EXPECT_EQ(0u, written);
    EXPECT_EQ(TLV_CODEC_OK, tlv_digits_decode(&config, nullptr, 0, decoded, 1));
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_digits_decode(&config, padding, SIZE_MAX, decoded, 1));
}

TEST(Unit_Tlv_Digits, InvalidConfigurationBoundsAndInputsDoNotWrite) {
    tlv_digits_codec_config_t config = {2};
    uint8_t                   output[] = {0xA5, 0xA5};
    size_t                    written = 9;
    for (const char* invalid : {"12345", "1F", "-1"}) {
        EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
                  tlv_digits_encode(&config, invalid, std::strlen(invalid), output, 2, &written));
        EXPECT_EQ(0u, written);
        EXPECT_EQ(0xA5, output[0]);
        EXPECT_EQ(0xA5, output[1]);
    }
    EXPECT_EQ(TLV_CODEC_ERR_BUFFER_TOO_SHORT,
              tlv_digits_encode(&config, "123", 3, output, 1, &written));
    EXPECT_EQ(0u, written);
    EXPECT_EQ(0xA5, output[0]);
    EXPECT_EQ(TLV_CODEC_ERR_NULL_ARG, tlv_digits_encode(&config, "1", 1, nullptr, 1, &written));
    EXPECT_EQ(TLV_CODEC_ERR_NULL_ARG,
              tlv_digits_decode(nullptr, output, 1, &written, sizeof(written)));
    config.width = 1;
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_digits_encode(&config, "123", 3, nullptr, 0, &written));
    config = {SIZE_MAX};
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_digits_encode(&config, "1", 1, nullptr, 0, &written));
    config = {2};
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_digits_decode(&config, output, 1, &written, sizeof(written)));
}
