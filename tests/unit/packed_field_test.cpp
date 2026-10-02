// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/layout.h"
#include <gtest/gtest.h>
#include <array>
#include <climits>

TEST(Unit_Tlv_PackedField, KnownWireBytesAndSharedFields) {
    for (auto order : {TLV_BYTE_ORDER_BIG_ENDIAN, TLV_BYTE_ORDER_LITTLE_ENDIAN}) {
        const tlv_packed_field_t high = {3, 13, 11, order};
        const tlv_packed_field_t low = {3, 0, 13, order};
        std::array<uint8_t, 5>   bytes = {{0xCC, 0xAB, 0xCD, 0xEF, 0xDD}};
        if (order == TLV_BYTE_ORDER_LITTLE_ENDIAN) {
            bytes[1] = 0xEF;
            bytes[3] = 0xAB;
        }
        uint64_t value = 0;
        ASSERT_EQ(TLV_OK, tlv_packed_field_read(&high, bytes.data() + 1, 3, &value));
        EXPECT_EQ(UINT64_C(0x55E), value);
        ASSERT_EQ(TLV_OK, tlv_packed_field_read(&low, bytes.data() + 1, 3, &value));
        EXPECT_EQ(UINT64_C(0xDEF), value);
        ASSERT_EQ(TLV_OK, tlv_packed_field_write(&high, bytes.data() + 1, 3, 0));
        ASSERT_EQ(TLV_OK, tlv_packed_field_read(&low, bytes.data() + 1, 3, &value));
        EXPECT_EQ(UINT64_C(0xDEF), value);
        ASSERT_EQ(TLV_OK, tlv_packed_field_write(&low, bytes.data() + 1, 3, 0x1234));
        const std::array<uint8_t, 5> expected =
            order == TLV_BYTE_ORDER_BIG_ENDIAN
                ? std::array<uint8_t, 5>{{0xCC, 0, 0x12, 0x34, 0xDD}}
                : std::array<uint8_t, 5>{{0xCC, 0x34, 0x12, 0, 0xDD}};
        EXPECT_EQ(expected, bytes);
    }
}

TEST(Unit_Tlv_PackedField, EveryWidthOffsetAndStorageBoundary) {
    for (auto order : {TLV_BYTE_ORDER_BIG_ENDIAN, TLV_BYTE_ORDER_LITTLE_ENDIAN}) {
        for (size_t storage = 1; storage <= 8; ++storage) {
            for (unsigned offset = 0; offset < storage * 8; ++offset) {
                for (unsigned width = 1; width <= storage * 8 - offset; ++width) {
                    const tlv_packed_field_t field = {storage, offset, width, order};
                    const uint64_t           maximum = UINT64_MAX >> (64 - width);
                    for (uint64_t input : {UINT64_C(0), UINT64_C(1), maximum}) {
                        std::array<uint8_t, 10> bytes;
                        bytes.fill(0xA5);
                        ASSERT_EQ(TLV_OK,
                                  tlv_packed_field_write(&field, bytes.data() + 1, storage, input));
                        uint64_t output = 0;
                        ASSERT_EQ(TLV_OK, tlv_packed_field_read(&field, bytes.data() + 1, storage,
                                                                &output));
                        ASSERT_EQ(input, output);
                        // Independent per-bit oracle checks endian, bit numbering and preservation.
                        for (size_t bit = 0; bit < storage * 8; ++bit) {
                            const size_t   index = order == TLV_BYTE_ORDER_LITTLE_ENDIAN
                                                       ? bit / 8
                                                       : storage - 1 - bit / 8;
                            const unsigned expected =
                                bit >= offset && bit - offset < width
                                    ? static_cast<unsigned>((input >> (bit - offset)) & 1)
                                    : (0xA5u >> (bit % 8)) & 1u;
                            ASSERT_EQ(expected, (bytes[1 + index] >> (bit % 8)) & 1u);
                        }
                        EXPECT_EQ(0xA5, bytes.front());
                        EXPECT_EQ(0xA5, bytes[storage + 1]);
                    }
                    if (width < 64) {
                        std::array<uint8_t, 8> bytes = {{0xAB}};
                        const auto             before = bytes;
                        EXPECT_EQ(TLV_ERR_OVERFLOW, tlv_packed_field_write(&field, bytes.data(),
                                                                           storage, maximum + 1));
                        EXPECT_EQ(before, bytes);
                    }
                }
            }
        }
    }
}

TEST(Unit_Tlv_PackedField, TruncationLeavesOutputsUnchanged) {
    for (size_t storage = 1; storage <= 8; ++storage) {
        const tlv_packed_field_t field = {storage, 0, 1, TLV_BYTE_ORDER_BIG_ENDIAN};
        for (size_t size = 0; size < storage; ++size) {
            std::array<uint8_t, 8> bytes = {{0xAB}};
            const auto             before = bytes;
            uint64_t               output = 42;
            EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
                      tlv_packed_field_read(&field, bytes.data(), size, &output));
            EXPECT_EQ(42u, output);
            EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
                      tlv_packed_field_write(&field, bytes.data(), size, 1));
            EXPECT_EQ(before, bytes);
        }
    }
}

TEST(Unit_Tlv_PackedField, InvalidConfigurationAndPointers) {
    const tlv_packed_field_t invalid[] = {{0, 0, 1, TLV_BYTE_ORDER_BIG_ENDIAN},
                                          {9, 0, 1, TLV_BYTE_ORDER_BIG_ENDIAN},
                                          {SIZE_MAX, 0, 1, TLV_BYTE_ORDER_BIG_ENDIAN},
                                          {8, 0, 0, TLV_BYTE_ORDER_BIG_ENDIAN},
                                          {8, 0, 65, TLV_BYTE_ORDER_BIG_ENDIAN},
                                          {8, 64, 1, TLV_BYTE_ORDER_BIG_ENDIAN},
                                          {8, 1, 64, TLV_BYTE_ORDER_BIG_ENDIAN},
                                          {2, 9, 8, TLV_BYTE_ORDER_BIG_ENDIAN},
                                          {8, UINT_MAX, UINT_MAX, TLV_BYTE_ORDER_BIG_ENDIAN}};
    std::array<uint8_t, 8>   bytes = {{0xAB}};
    const auto               before = bytes;
    uint64_t                 output = 42;
    for (const auto& field : invalid) {
        EXPECT_EQ(TLV_ERR_INVALID_ARG,
                  tlv_packed_field_read(&field, bytes.data(), bytes.size(), &output));
        EXPECT_EQ(TLV_ERR_INVALID_ARG,
                  tlv_packed_field_write(&field, bytes.data(), bytes.size(), 0));
    }
    tlv_packed_field_t field = {8, 0, 64, TLV_BYTE_ORDER_UNKNOWN};
    EXPECT_EQ(TLV_ERR_INVALID_BYTE_ORDER,
              tlv_packed_field_read(&field, bytes.data(), bytes.size(), &output));
    EXPECT_EQ(TLV_ERR_INVALID_BYTE_ORDER,
              tlv_packed_field_write(&field, bytes.data(), bytes.size(), 0));
    field.byte_order = TLV_BYTE_ORDER_BIG_ENDIAN;
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_packed_field_read(nullptr, bytes.data(), 8, &output));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_packed_field_read(&field, nullptr, 8, &output));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_packed_field_read(&field, bytes.data(), 8, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_packed_field_write(nullptr, bytes.data(), 8, 0));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_packed_field_write(&field, nullptr, 8, 0));
    EXPECT_EQ(before, bytes);
    EXPECT_EQ(42u, output);
}
