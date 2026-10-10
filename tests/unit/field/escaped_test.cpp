// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/field/escaped.h"
#include <gtest/gtest.h>
#include <algorithm>
#include <array>

TEST(Unit_Tlv_Escaped, CountsWidthsByteOrdersAndTransactionalErrors) {
    for (auto order : {TLV_BYTE_ORDER_BIG_ENDIAN, TLV_BYTE_ORDER_LITTLE_ENDIAN}) {
        for (size_t width = 1; width <= 8; ++width) {
            const uint64_t maximum = width == 8 ? UINT64_MAX : (UINT64_C(1) << (8 * width)) - 1;
            const tlv_escaped_length_t config{0x80, width, order, 0x80, maximum};
            for (uint64_t count : {UINT64_C(0), UINT64_C(127), UINT64_C(128), maximum}) {
                std::array<uint8_t, 10> wire;
                wire.fill(0xCC);
                size_t measured = 0, written = 0, consumed = 0;
                ASSERT_EQ(TLV_OK, tlv_escaped_length_write(&config, count, nullptr, 0, &measured));
                ASSERT_EQ(TLV_OK, tlv_escaped_length_write(&config, count, wire.data(), wire.size(),
                                                           &written));
                EXPECT_EQ(count < 128 ? 1u : 1 + width, measured);
                EXPECT_EQ(measured, written);
                EXPECT_EQ(0xCC, wire[written]);
                uint64_t decoded = 17;
                ASSERT_EQ(TLV_OK, tlv_escaped_length_read(&config, wire.data(), written, &decoded,
                                                          &consumed));
                EXPECT_EQ(count, decoded);
                EXPECT_EQ(written, consumed);
                for (size_t available = 0; available < written; ++available) {
                    decoded = 17;
                    EXPECT_EQ(TLV_ERR_TRUNCATED,
                              tlv_escaped_length_read(&config, wire.data(), available, &decoded,
                                                      &consumed));
                    EXPECT_EQ(17u, decoded);
                    EXPECT_EQ(available, consumed);
                }
                wire.fill(0xCC);
                size_t unchanged = 99;
                EXPECT_EQ(
                    TLV_ERR_BUFFER_TOO_SHORT,
                    tlv_escaped_length_write(&config, count, wire.data(), written - 1, &unchanged));
                EXPECT_EQ(99u, unchanged);
                EXPECT_TRUE(
                    std::all_of(wire.begin(), wire.end(), [](uint8_t b) { return b == 0xCC; }));
            }
            const uint8_t reserved[] = {0x81};
            uint64_t      decoded = 17;
            size_t        consumed = 0;
            EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
                      tlv_escaped_length_read(&config, reserved, 1, &decoded, &consumed));
            EXPECT_EQ(17u, decoded);
        }
    }
    const tlv_escaped_length_t little{0x80, 2, TLV_BYTE_ORDER_LITTLE_ENDIAN, 0x80, 65535};
    uint8_t                    bytes[3]{};
    size_t                     written = 0;
    ASSERT_EQ(TLV_OK, tlv_escaped_length_write(&little, 0x1234, bytes, sizeof(bytes), &written));
    EXPECT_EQ(0x80, bytes[0]);
    EXPECT_EQ(0x34, bytes[1]);
    EXPECT_EQ(0x12, bytes[2]);
}

TEST(Unit_Tlv_EscapedField, AcceptedNonminimalCountIsWrittenInCanonicalForm) {
    const tlv_escaped_length_t config{0x80, 2, TLV_BYTE_ORDER_BIG_ENDIAN, 0, 65535};
    const uint8_t              input[] = {0x80, 0, 3};
    tlv_size_t                 count = 0;
    size_t                     used = 0;
    ASSERT_EQ(TLV_OK, tlv_escaped_length_read(&config, input, sizeof(input), &count, &used));
    EXPECT_EQ(3u, count);
    EXPECT_EQ(sizeof(input), used);
    uint8_t output[] = {0xCC, 0xCC, 0xCC};
    ASSERT_EQ(TLV_OK, tlv_escaped_length_write(&config, count, output, sizeof(output), &used));
    EXPECT_EQ(1u, used);
    EXPECT_EQ(3, output[0]);
    EXPECT_EQ(0xCC, output[1]);
    EXPECT_EQ(0xCC, output[2]);
}

TEST(Unit_Tlv_EscapedField, InvalidConfigurationPreservesOutputs) {
    const uint8_t              input[] = {0};
    uint8_t                    output = 0xCC;
    tlv_size_t                 count = 42;
    size_t                     used = 99;
    const tlv_escaped_length_t invalid{0x80, 2, TLV_BYTE_ORDER_BIG_ENDIAN, 0x81, 65535};
    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              tlv_escaped_length_read(&invalid, input, sizeof(input), &count, &used));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_escaped_length_write(&invalid, 0, &output, 1, &used));
    auto bad_order = invalid;
    bad_order.min_extended = 0;
    bad_order.byte_order = TLV_BYTE_ORDER_UNKNOWN;
    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              tlv_escaped_length_read(&bad_order, input, sizeof(input), &count, &used));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_escaped_length_write(&bad_order, 0, &output, 1, &used));
    EXPECT_EQ(42u, count);
    EXPECT_EQ(99u, used);
    EXPECT_EQ(0xCC, output);
}
