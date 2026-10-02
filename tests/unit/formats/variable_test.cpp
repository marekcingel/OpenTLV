// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/formats/variable.h"
#include <gtest/gtest.h>
#include <array>
#include <cstring>
#include <vector>

namespace {
const tlv_variable_identifier_t identifier = {0x1F, 0x1F, 0x80, 0x7F, 16};
const tlv_variable_length_t     count = {0x80, 0x7F, TLV_BYTE_ORDER_BIG_ENDIAN};
const tlv_variable_format_t     config = {identifier, count, TLV_ELEMENT_ORDER_TLV,
                                          TLV_LENGTH_SCOPE_VALUE};
} // namespace

TEST(Unit_Tlv_Variable, IdentifierPreservesRawIdentityWithoutStandardRules) {
    const std::vector<std::vector<uint8_t>> tags = {
        {0},
        {0x20},
        {0xFF, 0},
        {0x9F, 0x1C},
        {0x1F, 0x80, 0},
        {0xDF, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x7F}};
    for (const auto& bytes : tags) {
        tlv_tag_t tag = {};
        size_t    used = 0;
        ASSERT_EQ(TLV_OK, tlv_variable_identifier_read(&identifier, bytes.data(), bytes.size(),
                                                       &tag, &used));
        EXPECT_EQ(bytes.data(), tag.data);
        EXPECT_EQ(bytes.size(), tag.size);
        EXPECT_EQ(bytes.size(), used);
        ASSERT_EQ(TLV_OK, tlv_variable_identifier_write(&identifier, &tag, nullptr, 0, &used));
        std::vector<uint8_t> out(used);
        ASSERT_EQ(TLV_OK,
                  tlv_variable_identifier_write(&identifier, &tag, out.data(), out.size(), &used));
        EXPECT_EQ(bytes, out);
    }
}

TEST(Unit_Tlv_Variable, DifferentInlineEscapeContinuationAndPayloadBits) {
    const tlv_variable_identifier_t alternate = {0x70, 0x20, 0x01, 0xF0, 4};
    const uint8_t                   bytes[] = {0xA5, 0xB1, 0xC0, 0xDD};
    tlv_tag_t                       tag = {};
    size_t                          used = 0;
    ASSERT_EQ(TLV_OK, tlv_variable_identifier_read(&alternate, bytes, sizeof(bytes), &tag, &used));
    EXPECT_EQ(3u, used);
    EXPECT_EQ(bytes, tag.data);
    const uint8_t inline_bytes[] = {0xB5, 0xFF};
    ASSERT_EQ(TLV_OK, tlv_variable_identifier_read(&alternate, inline_bytes, 2, &tag, &used));
    EXPECT_EQ(1u, used);
    const uint8_t invalid[] = {0x20, 0x02};
    EXPECT_EQ(TLV_ERR_INVALID_TAG,
              tlv_variable_identifier_read(&alternate, invalid, 2, &tag, &used));
    EXPECT_EQ(inline_bytes, tag.data);
    EXPECT_EQ(1u, used);
}

TEST(Unit_Tlv_Variable, IdentifierBoundsAndAtomicWrites) {
    auto limited = identifier;
    limited.max_size = 3;
    const uint8_t bytes[] = {0x1F, 0x81, 0x81, 0};
    tlv_tag_t     tag = tlv_tag(bytes, sizeof(bytes));
    size_t        used = 99;
    for (size_t size = 0; size < 3; ++size) {
        EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
                  tlv_variable_identifier_read(&limited, bytes, size, &tag, &used));
        EXPECT_EQ(99u, used);
        EXPECT_EQ(sizeof(bytes), tag.size);
    }
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE,
              tlv_variable_identifier_read(&limited, bytes, sizeof(bytes), &tag, &used));
    auto truncated = tlv_tag(bytes, 2);
    EXPECT_EQ(TLV_ERR_INVALID_TAG,
              tlv_variable_identifier_write(&limited, &truncated, nullptr, 0, &used));
    const uint8_t extra[] = {0x01, 0x02};
    auto          extra_tag = tlv_tag(extra, 2);
    EXPECT_EQ(TLV_ERR_INVALID_TAG,
              tlv_variable_identifier_write(&limited, &extra_tag, nullptr, 0, &used));
    std::array<uint8_t, 4> out = {{0xCC, 0xCC, 0xCC, 0xCC}};
    const auto             before = out;
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              tlv_variable_identifier_write(&identifier, &tag, out.data(), 3, &used));
    EXPECT_EQ(before, out);
    EXPECT_EQ(99u, used);
    // Overlap is explicitly supported by the identifier primitive.
    std::array<uint8_t, 4> overlap = {{0x1F, 0x81, 0, 0}};
    auto                   overlapping = tlv_tag(overlap.data(), 3);
    ASSERT_EQ(TLV_OK, tlv_variable_identifier_write(&identifier, &overlapping, overlap.data() + 1,
                                                    3, &used));
    EXPECT_EQ((std::array<uint8_t, 4>{{0x1F, 0x1F, 0x81, 0}}), overlap);
}

TEST(Unit_Tlv_Variable, KnownLengthEncodingsAndLogicalBoundaries) {
    struct Case {
        tlv_size_t           value;
        std::vector<uint8_t> bytes;
    };
    const Case cases[] = {{0, {0}},
                          {127, {127}},
                          {128, {0x81, 0x80}},
                          {255, {0x81, 0xFF}},
                          {256, {0x82, 1, 0}},
                          {65536, {0x83, 1, 0, 0}},
                          {UINT64_C(0x100000000), {0x85, 1, 0, 0, 0, 0}},
                          {UINT64_MAX, {0x88, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}}};
    for (const auto& c : cases) {
        size_t used = 0;
        ASSERT_EQ(TLV_OK, tlv_variable_length_write(&count, c.value, nullptr, 0, &used));
        EXPECT_EQ(c.bytes.size(), used);
        std::vector<uint8_t> out(used);
        ASSERT_EQ(TLV_OK,
                  tlv_variable_length_write(&count, c.value, out.data(), out.size(), &used));
        EXPECT_EQ(c.bytes, out);
        tlv_size_t value = 99;
        ASSERT_EQ(TLV_OK, tlv_variable_length_read(&count, out.data(), out.size(), &value, &used));
        EXPECT_EQ(c.value, value);
    }
    const tlv_variable_length_t alternate = {1, 0xAA, TLV_BYTE_ORDER_LITTLE_ENDIAN};
    uint8_t                     out[3] = {};
    size_t                      used = 0;
    ASSERT_EQ(TLV_OK, tlv_variable_length_write(&alternate, 13, out, 3, &used));
    EXPECT_EQ(0xA2, out[0]); // 1101 packed into bits 7,5,3,1.
    ASSERT_EQ(TLV_OK, tlv_variable_length_write(&alternate, 0x1234, out, 3, &used));
    EXPECT_EQ(0x09, out[0]);
    EXPECT_EQ(0x34, out[1]);
    EXPECT_EQ(0x12, out[2]);
    tlv_size_t value = 0;
    ASSERT_EQ(TLV_OK, tlv_variable_length_read(&alternate, out, 3, &value, &used));
    EXPECT_EQ(0x1234u, value);
}

TEST(Unit_Tlv_Variable, PaddedLengthsAndOverflowInBothByteOrders) {
    for (auto order : {TLV_BYTE_ORDER_BIG_ENDIAN, TLV_BYTE_ORDER_LITTLE_ENDIAN}) {
        auto c = count;
        c.byte_order = order;
        // The all-one prefix is generic here, with no protocol reservation.
        std::vector<uint8_t> bytes(128, 0);
        bytes[0] = 0xFF;
        bytes[order == TLV_BYTE_ORDER_BIG_ENDIAN ? 127 : 1] = 7;
        tlv_size_t value = 99;
        size_t     used = 0;
        ASSERT_EQ(TLV_OK, tlv_variable_length_read(&c, bytes.data(), bytes.size(), &value, &used));
        EXPECT_EQ(7u, value);
        EXPECT_EQ(128u, used);
        for (size_t size = 1; size < bytes.size(); ++size) {
            EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
                      tlv_variable_length_read(&c, bytes.data(), size, &value, &used));
            EXPECT_EQ(size, used);
            EXPECT_EQ(7u, value);
        }
        bytes[order == TLV_BYTE_ORDER_BIG_ENDIAN ? 119 : 9] = 1;
        EXPECT_EQ(TLV_ERR_OVERFLOW,
                  tlv_variable_length_read(&c, bytes.data(), bytes.size(), &value, &used));
        EXPECT_EQ(7u, value);
        EXPECT_EQ(128u, used);
    }
}

TEST(Unit_Tlv_Variable, LengthFailuresPreserveOutputAndReportAvailablePrefix) {
    const uint8_t zero_width[] = {0x80};
    tlv_size_t    value = 99;
    size_t        used = 99;
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
              tlv_variable_length_read(&count, zero_width, 1, &value, &used));
    EXPECT_EQ(1u, used);
    EXPECT_EQ(99u, value);
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              tlv_variable_length_read(&count, nullptr, 0, &value, &used));
    EXPECT_EQ(0u, used);
    const tlv_variable_length_t tiny = {0x80, 1, TLV_BYTE_ORDER_BIG_ENDIAN};
    const uint8_t               invalid[] = {2};
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_variable_length_read(&tiny, invalid, 1, &value, &used));
    used = 99;
    std::array<uint8_t, 3> out = {{0xCC, 0xCC, 0xCC}};
    const auto             before = out;
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_variable_length_write(&tiny, 256, out.data(), 3, &used));
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              tlv_variable_length_write(&count, 256, out.data(), 2, &used));
    EXPECT_EQ(99u, used);
    EXPECT_EQ(before, out);
}

TEST(Unit_Tlv_Variable, ConfigurationAndNullArguments) {
    tlv_format_t format = {};
    ASSERT_EQ(TLV_OK, tlv_variable_format_init(&format, &config));
    const auto                         original_context = format.context;
    const auto                         original_decode = format.decode;
    std::vector<tlv_variable_format_t> invalid(8, config);
    invalid[0].identifier.inline_mask = 0;
    invalid[1].identifier.escape = 0xFF;
    invalid[2].identifier.continuation_bit = 3;
    invalid[3].identifier.payload_mask = 0xFF;
    invalid[4].identifier.max_size = 0;
    invalid[5].length.long_form_bit = 3;
    invalid[6].length.payload_mask = 0;
    invalid[7].length.payload_mask = 0xFF;
    for (const auto& c : invalid) {
        EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_variable_format_init(&format, &c));
        EXPECT_EQ(original_context, format.context);
        EXPECT_EQ(original_decode, format.decode);
    }
    auto bad_order = config;
    bad_order.length.byte_order = static_cast<tlv_byte_order_t>(99);
    EXPECT_EQ(TLV_ERR_INVALID_BYTE_ORDER, tlv_variable_format_init(&format, &bad_order));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_variable_format_init(nullptr, &config));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_variable_format_init(&format, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_variable_fields_init(nullptr, &config));
    tlv_field_layout_t fields = {};
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_variable_fields_init(&fields, nullptr));
    tlv_tag_t  tag = {};
    size_t     used = 99;
    tlv_size_t value = 99;
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_variable_identifier_read(nullptr, nullptr, 0, &tag, &used));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_variable_identifier_read(&identifier, nullptr, 1, &tag, &used));
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              tlv_variable_identifier_write(&identifier, &tag, nullptr, 1, &used));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_variable_length_read(nullptr, nullptr, 0, &value, &used));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_variable_length_write(&count, 0, nullptr, 1, &used));
    EXPECT_EQ(99u, used);
    EXPECT_EQ(99u, value);
}
