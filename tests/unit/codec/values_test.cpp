// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/codec/values.h"
#include "tlv/codec/number.h"
#include <vector>
#include <gtest/gtest.h>
#include <cstring>
#include "fixed_value_checks.h"

TEST(Unit_Tlv_ValueCodecs, FixedValuesAndBounds) {
    const uint8_t u8[] = {0xFF};
    const uint8_t u16[] = {0x12, 0xAB};
    const uint8_t u32[] = {0x89, 0xAB, 0xCD, 0xEF};
    check_fixed(&tlv_codec_uint8, uint8_t{255}, u8, sizeof(u8));
    check_fixed(&tlv_codec_uint16_be, uint16_t{0x12AB}, u16, sizeof(u16));
    check_fixed(&tlv_codec_uint32_be, uint32_t{0x89ABCDEF}, u32, sizeof(u32));
    check_fixed(&tlv_codec_uint16_le, uint16_t{0xAB12}, u16, sizeof(u16));
    check_fixed(&tlv_codec_uint32_le, uint32_t{0xEFCDAB89}, u32, sizeof(u32));
    const uint8_t zero[4] = {};
    const uint8_t maximum[4] = {255, 255, 255, 255};
    check_fixed(&tlv_codec_uint8, uint8_t{0}, zero, 1);
    check_fixed(&tlv_codec_uint16_be, uint16_t{0}, zero, 2);
    check_fixed(&tlv_codec_uint32_be, uint32_t{0}, zero, 4);
    check_fixed(&tlv_codec_uint16_be, uint16_t{UINT16_MAX}, maximum, 2);
    check_fixed(&tlv_codec_uint32_be, uint32_t{UINT32_MAX}, maximum, 4);
}

TEST(Unit_Tlv_ValueCodecs, BytesBorrowAndPreserveEveryOctet) {
    const uint8_t wire[] = {1, 0, 255, 1, 224};
    tlv_value_t   value{};
    ASSERT_EQ(TLV_CODEC_OK,
              tlv_codec_decode(&tlv_codec_bytes, wire, sizeof(wire), &value, sizeof(value)));
    EXPECT_EQ(wire, value.data);
    EXPECT_EQ(sizeof(wire), value.size);
    uint8_t output[sizeof(wire)] = {};
    size_t  written = 0;
    ASSERT_EQ(TLV_CODEC_OK,
              tlv_codec_encode(&tlv_codec_bytes, &value, sizeof(value), nullptr, 0, &written));
    EXPECT_EQ(sizeof(wire), written);
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_encode(&tlv_codec_bytes, &value, sizeof(value), output,
                                             sizeof(output), &written));
    EXPECT_EQ(0, std::memcmp(wire, output, sizeof(wire)));
    EXPECT_EQ(TLV_CODEC_ERR_BUFFER_TOO_SHORT,
              tlv_codec_encode(&tlv_codec_bytes, &value, sizeof(value), output, sizeof(output) - 1,
                               &written));
    EXPECT_EQ(0u, written);
    EXPECT_EQ(TLV_CODEC_ERR_BUFFER_TOO_SHORT,
              tlv_codec_decode(&tlv_codec_bytes, wire, sizeof(wire), &value, sizeof(value) - 1));
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_encode(&tlv_codec_bytes, &value, sizeof(value) - 1, nullptr, 0, &written));
    value = {nullptr, 1};
    EXPECT_EQ(TLV_CODEC_ERR_NULL_ARG,
              tlv_codec_encode(&tlv_codec_bytes, &value, sizeof(value), nullptr, 0, &written));
    EXPECT_EQ(0u, written);
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_decode(&tlv_codec_bytes, nullptr, 0, &value, sizeof(value)));
    EXPECT_EQ(nullptr, value.data);
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_encode(&tlv_codec_bytes, &value, sizeof(value), output,
                                             sizeof(output), &written));
    EXPECT_EQ(0u, written);
}

TEST(Unit_Tlv_ValueCodecs, NonNativeViewsFailBeforeAccess) {
    if (sizeof(size_t) >= sizeof(tlv_size_t)) return;
    const uint8_t    byte = 0;
    const tlv_size_t too_large = static_cast<tlv_size_t>(SIZE_MAX) + 1;
    tlv_value_t      bytes{&byte, too_large};
    size_t           written = 99;
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_encode(&tlv_codec_bytes, &bytes, sizeof(bytes), nullptr, 0, &written));
    EXPECT_EQ(0u, written);
}

TEST(Unit_Tlv_NumberCodecs, RuntimeConfigurationAndEncodingBoundaries) {
    for (auto encoding : {TLV_NUMBER_BINARY_BE, TLV_NUMBER_BINARY_LE, TLV_NUMBER_BCD}) {
        const size_t max_width = encoding == TLV_NUMBER_BCD ? 9 : 8;
        for (size_t width = 1; width <= max_width; ++width) {
            const tlv_number_codec_config_t config{encoding, width,
                                                   encoding == TLV_NUMBER_BCD ? 18u : 0u};
            const auto                      codec = tlv_number_codec(&config);
            uint64_t                        maximum = 0;
            for (size_t i = 0; i < width; ++i)
                maximum = maximum * (encoding == TLV_NUMBER_BCD ? 100 : 256) +
                          (encoding == TLV_NUMBER_BCD ? 99 : 255);
            for (uint64_t input : {UINT64_C(0), UINT64_C(1), maximum}) {
                uint8_t wire[9] = {};
                size_t  written = 0;
                ASSERT_EQ(TLV_CODEC_OK,
                          tlv_codec_encode(&codec, &input, sizeof(input), nullptr, 0, &written));
                EXPECT_EQ(width, written);
                ASSERT_EQ(TLV_CODEC_OK,
                          tlv_codec_encode(&codec, &input, sizeof(input), wire, width, &written));
                uint64_t decoded = 99;
                ASSERT_EQ(TLV_CODEC_OK,
                          tlv_codec_decode(&codec, wire, written, &decoded, sizeof(decoded)));
                EXPECT_EQ(input, decoded);
                if (input == maximum)
                    for (size_t i = 0; i < width; ++i)
                        EXPECT_EQ(encoding == TLV_NUMBER_BCD ? 0x99 : 0xFF, wire[i]);
                EXPECT_EQ(
                    TLV_CODEC_ERR_BUFFER_TOO_SHORT,
                    tlv_codec_encode(&codec, &input, sizeof(input), wire, width - 1, &written));
                EXPECT_EQ(0u, written);
            }
            if (maximum != UINT64_MAX) {
                const uint64_t overflow = maximum + 1;
                size_t         written = 99;
                EXPECT_EQ(
                    TLV_CODEC_ERR_INVALID_VALUE,
                    tlv_codec_encode(&codec, &overflow, sizeof(overflow), nullptr, 0, &written));
                EXPECT_EQ(0u, written);
            }
        }
    }
}

TEST(Unit_Tlv_NumberCodecs, WireVectorsFixedWidthsAndInvalidInputs) {
    const tlv_number_codec_config_t config{TLV_NUMBER_BINARY_LE, 3, 0};
    const auto                      codec = tlv_number_codec(&config);
    const uint64_t                  input = 0x1234;
    uint8_t                         wire[3] = {0xAA, 0xAA, 0xAA};
    size_t                          written = 99;
    ASSERT_EQ(TLV_CODEC_OK,
              tlv_codec_encode(&codec, &input, sizeof(input), wire, sizeof(wire), &written));
    EXPECT_EQ(3u, written);
    EXPECT_EQ(0x34, wire[0]);
    EXPECT_EQ(0x12, wire[1]);
    EXPECT_EQ(0, wire[2]);
    uint64_t output = 77;
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_decode(&codec, wire, 2, &output, sizeof(output)));
    EXPECT_EQ(77u, output);
    const tlv_number_codec_config_t decimal{TLV_NUMBER_BCD, 2, 3};
    const auto                      bcd = tlv_number_codec(&decimal);
    const uint8_t                   valid[] = {0x01, 0x23};
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_decode(&bcd, valid, 2, &output, sizeof(output)));
    EXPECT_EQ(123u, output);
    for (unsigned byte = 0; byte < 256; ++byte) {
        const uint8_t value[] = {0, static_cast<uint8_t>(byte)};
        EXPECT_EQ((byte >> 4) <= 9 && (byte & 15) <= 9 ? TLV_CODEC_OK : TLV_CODEC_ERR_INVALID_VALUE,
                  tlv_codec_decode(&bcd, value, 2, &output, sizeof(output)));
    }
    const uint8_t too_many_digits[] = {0x10, 0};
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_decode(&bcd, too_many_digits, 2, &output, sizeof(output)));
    EXPECT_EQ(TLV_CODEC_ERR_BUFFER_TOO_SHORT,
              tlv_codec_decode(&bcd, valid, 2, &output, sizeof(output) - 1));
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_encode(&bcd, &input, sizeof(input) - 1, nullptr, 0, &written));
    const tlv_number_codec_config_t invalid[] = {
        {TLV_NUMBER_BINARY_BE, 9, 0}, {TLV_NUMBER_BINARY_BE, 8, 1},
        {TLV_NUMBER_BCD, 10, 18},     {TLV_NUMBER_BCD, 9, 0},
        {TLV_NUMBER_BCD, 9, 19},      {static_cast<tlv_number_encoding_t>(99), 1, 0}};
    for (const auto& bad : invalid) {
        const auto rejected = tlv_number_codec(&bad);
        output = 77;
        EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
                  tlv_codec_decode(&rejected, valid, 2, &output, sizeof(output)));
        EXPECT_EQ(77u, output);
        EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
                  tlv_codec_encode(&rejected, &input, sizeof(input), wire, sizeof(wire), &written));
        EXPECT_EQ(0u, written);
    }
    const auto missing = tlv_number_codec(nullptr);
    EXPECT_EQ(TLV_CODEC_ERR_NULL_ARG,
              tlv_codec_decode(&missing, valid, 2, &output, sizeof(output)));
    EXPECT_EQ(TLV_CODEC_ERR_NULL_ARG,
              tlv_codec_encode(&missing, &input, sizeof(input), nullptr, 0, &written));
    EXPECT_EQ(TLV_CODEC_ERR_NULL_ARG,
              tlv_number_decode(&config, nullptr, 1, &output, sizeof(output)));
    EXPECT_EQ(TLV_CODEC_ERR_NULL_ARG, tlv_number_decode(&config, valid, 1, nullptr, 0));
    EXPECT_EQ(TLV_CODEC_ERR_NULL_ARG,
              tlv_number_encode(&config, nullptr, sizeof(input), nullptr, 0, &written));
    EXPECT_EQ(TLV_CODEC_ERR_NULL_ARG,
              tlv_number_encode(&config, &input, sizeof(input), nullptr, 1, &written));
    EXPECT_EQ(TLV_CODEC_ERR_NULL_ARG,
              tlv_number_encode(&config, &input, sizeof(input), nullptr, 0, nullptr));
}

TEST(Unit_Tlv_NumberCodecs, MinimalRepresentationDoesNotImposeFieldLengthPolicy) {
    const tlv_number_codec_config_t config{TLV_NUMBER_BINARY_BE, 0, 0};
    const auto                      codec = tlv_number_codec(&config);
    const uint64_t                  number = 256;
    uint8_t                         wire[3] = {};
    size_t                          written = 0;
    ASSERT_EQ(TLV_CODEC_OK,
              tlv_codec_encode(&codec, &number, sizeof(number), wire, sizeof(wire), &written));
    EXPECT_EQ(2u, written);
    EXPECT_EQ(1, wire[0]);
    EXPECT_EQ(0, wire[1]);
    const uint8_t padded[] = {0, 1, 0};
    uint64_t      decoded = 0;
    ASSERT_EQ(TLV_CODEC_OK,
              tlv_codec_decode(&codec, padded, sizeof(padded), &decoded, sizeof(decoded)));
    EXPECT_EQ(number, decoded);
}

TEST(Unit_Tlv_ValueCodecs, MinimalSignedIntegerWithoutAsn1) {
    const struct {
        int64_t              value;
        std::vector<uint8_t> wire;
    } cases[] = {{0, {0}},
                 {127, {0x7F}},
                 {128, {0, 0x80}},
                 {-1, {0xFF}},
                 {-128, {0x80}},
                 {-129, {0xFF, 0x7F}},
                 {INT64_MIN, {0x80, 0, 0, 0, 0, 0, 0, 0}},
                 {INT64_MAX, {0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}}};
    for (const auto& c : cases) {
        uint8_t wire[8] = {};
        size_t  written = 0;
        int64_t decoded = 0;
        ASSERT_EQ(TLV_CODEC_OK, tlv_codec_decode(&tlv_codec_int64_minimal_be, c.wire.data(),
                                                 c.wire.size(), &decoded, sizeof(decoded)));
        EXPECT_EQ(c.value, decoded);
        ASSERT_EQ(TLV_CODEC_OK, tlv_codec_encode(&tlv_codec_int64_minimal_be, &c.value,
                                                 sizeof(c.value), wire, sizeof(wire), &written));
        ASSERT_EQ(c.wire.size(), written);
        EXPECT_EQ(0, std::memcmp(wire, c.wire.data(), written));
    }
    const std::vector<std::vector<uint8_t>> invalid{
        {}, {0, 1}, {0xFF, 0x80}, {0, 0x80, 0, 0, 0, 0, 0, 0, 0}};
    for (const auto& wire : invalid) {
        int64_t decoded = 99;
        EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
                  tlv_codec_decode(&tlv_codec_int64_minimal_be, wire.data(), wire.size(), &decoded,
                                   sizeof(decoded)));
        EXPECT_EQ(99, decoded);
    }
}
