// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/field/fixed.h"
#if defined(OPENTLV_FORMAT_H) || defined(OPENTLV_FORMATS_COMPOSE_H)
#error Standalone Field Encoding must not import Format
#endif
#include <gtest/gtest.h>
#include <array>
#include <vector>

TEST(Unit_Tlv_FixedField, IdentifierWidthsPreserveExactBytesAndBorrowInput) {
    for (size_t width : {size_t{1}, size_t{2}, size_t{3}, size_t{8}, size_t{17}, size_t{256}}) {
        SCOPED_TRACE(width);
        const tlv_fixed_identifier_t config{width};
        std::vector<uint8_t>         input(width + 2, 0xCC);
        for (size_t i = 0; i < width; ++i) input[i + 1] = static_cast<uint8_t>(i * 53 + 0x9F);
        tlv_tag_t tag{};
        size_t    consumed = 99;
        ASSERT_EQ(TLV_OK,
                  tlv_fixed_identifier_read(&config, input.data() + 1, width + 1, &tag, &consumed));
        EXPECT_EQ(input.data() + 1, tag.data);
        EXPECT_EQ(width, tag.size);
        EXPECT_EQ(width, consumed);
        size_t written = 99;
        ASSERT_EQ(TLV_OK, tlv_fixed_identifier_write(&config, &tag, nullptr, 0, &written));
        EXPECT_EQ(width, written);
        std::vector<uint8_t> output(width + 2, 0xCC);
        ASSERT_EQ(TLV_OK,
                  tlv_fixed_identifier_write(&config, &tag, output.data() + 1, width, &written));
        EXPECT_EQ(width, written);
        EXPECT_EQ(input, output);
    }
}

TEST(Unit_Tlv_FixedField, IdentifierFailuresPreserveOutputsAndBuffer) {
    const tlv_fixed_identifier_t config{3};
    const uint8_t                input[] = {0x9F, 0, 0xFF};
    tlv_tag_t                    tag = tlv_tag(input + 1, 2);
    size_t                       consumed = 99;
    for (size_t available = 0; available < config.size; ++available) {
        EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
                  tlv_fixed_identifier_read(&config, input, available, &tag, &consumed));
        EXPECT_EQ(input + 1, tag.data);
        EXPECT_EQ(2u, tag.size);
        EXPECT_EQ(available, consumed);
    }
    tag = tlv_tag(input, sizeof(input));
    std::array<uint8_t, 5> output{{0xCC, 0xCC, 0xCC, 0xCC, 0xCC}};
    const auto             before = output;
    size_t                 written = 99;
    for (size_t capacity = 0; capacity < config.size; ++capacity) {
        EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
                  tlv_fixed_identifier_write(&config, &tag, output.data() + 1, capacity, &written));
        EXPECT_EQ(before, output);
        EXPECT_EQ(99u, written);
    }
    for (size_t width : {size_t{0}, size_t{1}, size_t{2}, size_t{4}}) {
        tag = tlv_tag(input, width);
        EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE, tlv_fixed_identifier_write(&config, &tag, output.data(),
                                                                       output.size(), &written));
        EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE,
                  tlv_fixed_identifier_write(&config, &tag, nullptr, 0, &written));
    }
    tag = tlv_tag(nullptr, 0);
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE,
              tlv_fixed_identifier_write(&config, &tag, nullptr, 0, &written));
    EXPECT_EQ(before, output);
    EXPECT_EQ(99u, written);
}

TEST(Unit_Tlv_FixedField, IdentifierValidatesConfigurationAndRequiredArguments) {
    const tlv_fixed_identifier_t valid{1}, invalid{0};
    const uint8_t                input[] = {0xAB};
    uint8_t                      output = 0xCC;
    tlv_tag_t                    tag = tlv_tag(input, 1);
    size_t                       used = 99;
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_fixed_identifier_read(&invalid, input, 1, &tag, &used));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_fixed_identifier_write(&invalid, &tag, &output, 1, &used));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_fixed_identifier_read(nullptr, input, 1, &tag, &used));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_fixed_identifier_read(&valid, nullptr, 1, &tag, &used));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_fixed_identifier_read(&valid, input, 1, nullptr, &used));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_fixed_identifier_read(&valid, input, 1, &tag, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_fixed_identifier_write(nullptr, &tag, &output, 1, &used));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_fixed_identifier_write(&valid, nullptr, &output, 1, &used));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_fixed_identifier_write(&valid, &tag, nullptr, 1, &used));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_fixed_identifier_write(&valid, &tag, &output, 1, nullptr));
    const tlv_tag_t missing_bytes = tlv_tag(nullptr, 2);
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              tlv_fixed_identifier_write(&valid, &missing_bytes, &output, 1, &used));
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_fixed_identifier_read(&valid, nullptr, 0, &tag, &used));
    EXPECT_EQ(input, tag.data);
    EXPECT_EQ(1u, tag.size);
    EXPECT_EQ(0u, used);
    EXPECT_EQ(0xCC, output);
}

TEST(Unit_Tlv_FixedField, LengthKnownWireBytesForEveryWidthAndByteOrder) {
    const uint8_t significant[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    for (auto order : {TLV_BYTE_ORDER_BIG_ENDIAN, TLV_BYTE_ORDER_LITTLE_ENDIAN}) {
        for (size_t width = 1; width <= 8; ++width) {
            SCOPED_TRACE(::testing::Message() << "width=" << width << " order=" << order);
            const tlv_fixed_length_t config{width, order};
            const uint64_t           maximum = UINT64_MAX >> (64 - width * 8);
            const uint64_t           pattern = UINT64_C(0x0123456789ABCDEF) & maximum;
            for (uint64_t count : {UINT64_C(0), maximum, pattern}) {
                std::array<uint8_t, 10> expected;
                expected.fill(0xCC);
                for (size_t i = 0; i < width; ++i) {
                    expected[i + 1] =
                        count == 0 ? 0
                        : count == maximum
                            ? 0xFF
                            : significant[order == TLV_BYTE_ORDER_BIG_ENDIAN ? 8 - width + i
                                                                             : 7 - i];
                }
                size_t written = 99;
                ASSERT_EQ(TLV_OK, tlv_fixed_length_write(&config, count, nullptr, 0, &written));
                EXPECT_EQ(width, written);
                std::array<uint8_t, 10> output;
                output.fill(0xCC);
                ASSERT_EQ(TLV_OK, tlv_fixed_length_write(&config, count, output.data() + 1, width,
                                                         &written));
                EXPECT_EQ(width, written);
                EXPECT_EQ(expected, output);
                tlv_size_t decoded = 99;
                size_t     consumed = 99;
                ASSERT_EQ(TLV_OK, tlv_fixed_length_read(&config, expected.data() + 1, width + 1,
                                                        &decoded, &consumed));
                EXPECT_EQ(count, decoded);
                EXPECT_EQ(width, consumed);
                decoded = 99;
                ASSERT_EQ(TLV_OK, tlv_fixed_length_read(&config, output.data() + 1, width, &decoded,
                                                        &consumed));
                EXPECT_EQ(count, decoded);
            }
        }
    }
}

TEST(Unit_Tlv_FixedField, LengthTruncationReportsPrefixAndWritesRemainAtomic) {
    const uint8_t input[8] = {};
    for (size_t width = 1; width <= 8; ++width) {
        const tlv_fixed_length_t config{width, TLV_BYTE_ORDER_BIG_ENDIAN};
        for (size_t available = 0; available < width; ++available) {
            tlv_size_t value = 42;
            size_t     consumed = 99;
            EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
                      tlv_fixed_length_read(&config, input, available, &value, &consumed));
            EXPECT_EQ(42u, value);
            EXPECT_EQ(available, consumed);
            std::array<uint8_t, 10> output;
            output.fill(0xCC);
            const auto before = output;
            size_t     written = 99;
            EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
                      tlv_fixed_length_write(&config, 0, output.data() + 1, available, &written));
            EXPECT_EQ(99u, written);
            EXPECT_EQ(before, output);
        }
    }
}

TEST(Unit_Tlv_FixedField, LengthOverflowDoesNotWriteOrPublishWidth) {
    for (size_t width = 1; width < 8; ++width) {
        for (auto order : {TLV_BYTE_ORDER_BIG_ENDIAN, TLV_BYTE_ORDER_LITTLE_ENDIAN}) {
            const tlv_fixed_length_t config{width, order};
            const tlv_size_t         oversized = UINT64_C(1) << (width * 8);
            std::array<uint8_t, 8>   output;
            output.fill(0xCC);
            const auto before = output;
            size_t     written = 99;
            EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
                      tlv_fixed_length_write(&config, oversized, nullptr, 0, &written));
            EXPECT_EQ(
                TLV_ERR_INVALID_LENGTH,
                tlv_fixed_length_write(&config, oversized, output.data(), output.size(), &written));
            EXPECT_EQ(99u, written);
            EXPECT_EQ(before, output);
        }
    }
}

TEST(Unit_Tlv_FixedField, LengthConfigurationErrorsPreserveBothOutputs) {
    const uint8_t          input[8] = {};
    std::array<uint8_t, 8> output;
    output.fill(0xCC);
    const auto before = output;
    tlv_size_t value = 42;
    size_t     used = 99;
    for (size_t width : {size_t{0}, size_t{9}, SIZE_MAX}) {
        const tlv_fixed_length_t invalid{width, TLV_BYTE_ORDER_UNKNOWN};
        EXPECT_EQ(TLV_ERR_INVALID_ARG,
                  tlv_fixed_length_read(&invalid, input, sizeof(input), &value, &used));
        EXPECT_EQ(TLV_ERR_INVALID_ARG,
                  tlv_fixed_length_write(&invalid, 0, output.data(), output.size(), &used));
    }
    for (auto order : {TLV_BYTE_ORDER_UNKNOWN, static_cast<tlv_byte_order_t>(99)}) {
        const tlv_fixed_length_t invalid{2, order};
        EXPECT_EQ(TLV_ERR_INVALID_BYTE_ORDER,
                  tlv_fixed_length_read(&invalid, input, sizeof(input), &value, &used));
        EXPECT_EQ(TLV_ERR_INVALID_BYTE_ORDER,
                  tlv_fixed_length_read(&invalid, nullptr, 0, &value, &used));
        EXPECT_EQ(TLV_ERR_INVALID_BYTE_ORDER,
                  tlv_fixed_length_write(&invalid, 0, output.data(), output.size(), &used));
        EXPECT_EQ(TLV_ERR_INVALID_BYTE_ORDER,
                  tlv_fixed_length_write(&invalid, 0, nullptr, 0, &used));
    }
    EXPECT_EQ(42u, value);
    EXPECT_EQ(99u, used);
    EXPECT_EQ(before, output);
}

TEST(Unit_Tlv_FixedField, LengthValidatesRequiredArgumentsBeforeConfiguration) {
    const tlv_fixed_length_t valid{2, TLV_BYTE_ORDER_BIG_ENDIAN};
    const tlv_fixed_length_t invalid{0, TLV_BYTE_ORDER_UNKNOWN};
    const uint8_t            input[] = {0, 1};
    uint8_t                  output[] = {0xCC, 0xCC};
    tlv_size_t               value = 42;
    size_t                   used = 99;
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_fixed_length_read(nullptr, input, 2, &value, &used));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_fixed_length_read(&valid, nullptr, 1, &value, &used));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_fixed_length_read(&valid, input, 2, nullptr, &used));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_fixed_length_read(&valid, input, 2, &value, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_fixed_length_write(nullptr, 1, output, 2, &used));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_fixed_length_write(&valid, 1, nullptr, 1, &used));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_fixed_length_write(&valid, 1, output, 2, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_fixed_length_read(&invalid, input, 2, nullptr, &used));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_fixed_length_write(&invalid, 1, output, 2, nullptr));
    EXPECT_EQ(42u, value);
    EXPECT_EQ(99u, used);
    EXPECT_EQ(0xCC, output[0]);
    EXPECT_EQ(0xCC, output[1]);
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_fixed_length_read(&valid, nullptr, 0, &value, &used));
    EXPECT_EQ(42u, value);
    EXPECT_EQ(0u, used);
}
