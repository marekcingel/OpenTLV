// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/field/variable.h"
#include <gtest/gtest.h>
#include <array>
#include <cstring>
#include <vector>

namespace {
const tlv_variable_identifier_t identifier = {0x1F, 0x1F, 0x80, 0x7F, 16, NULL};
const tlv_variable_length_t     count = {0x80, 0x7F, TLV_BYTE_ORDER_BIG_ENDIAN, NULL};
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
    const tlv_variable_identifier_t alternate = {0x70, 0x20, 0x01, 0xF0, 4, NULL};
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
        EXPECT_EQ(size, used);
        EXPECT_EQ(sizeof(bytes), tag.size);
    }
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE,
              tlv_variable_identifier_read(&limited, bytes, sizeof(bytes), &tag, &used));
    EXPECT_EQ(2u, used);
    used = 99;
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
    const tlv_variable_length_t alternate = {1, 0xAA, TLV_BYTE_ORDER_LITTLE_ENDIAN, NULL};
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
    const tlv_variable_length_t tiny = {0x80, 1, TLV_BYTE_ORDER_BIG_ENDIAN, NULL};
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

TEST(Unit_Tlv_VariableField, NullArgumentsPreserveOutputs) {
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

TEST(Unit_Tlv_VariableField, InvalidConfigurationPreservesOutputs) {
    const uint8_t input[] = {0x01};
    tlv_tag_t     tag = tlv_tag(input, sizeof(input));
    size_t        used = 99;
    uint8_t       output = 0xCC;
    auto          invalid_identifier = identifier;
    invalid_identifier.payload_mask |= invalid_identifier.continuation_bit;
    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              tlv_variable_identifier_read(&invalid_identifier, input, sizeof(input), &tag, &used));
    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              tlv_variable_identifier_write(&invalid_identifier, &tag, &output, 1, &used));
    EXPECT_EQ(input, tag.data);
    EXPECT_EQ(sizeof(input), tag.size);
    auto invalid_length = count;
    invalid_length.long_form_bit = 3;
    tlv_size_t value = 42;
    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              tlv_variable_length_read(&invalid_length, input, sizeof(input), &value, &used));
    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              tlv_variable_length_write(&invalid_length, 1, &output, 1, &used));
    invalid_length = count;
    invalid_length.byte_order = TLV_BYTE_ORDER_UNKNOWN;
    EXPECT_EQ(TLV_ERR_INVALID_BYTE_ORDER,
              tlv_variable_length_read(&invalid_length, input, sizeof(input), &value, &used));
    EXPECT_EQ(TLV_ERR_INVALID_BYTE_ORDER,
              tlv_variable_length_write(&invalid_length, 1, &output, 1, &used));
    EXPECT_EQ(42u, value);
    EXPECT_EQ(99u, used);
    EXPECT_EQ(0xCC, output);
}

TEST(Unit_Tlv_VariablePolicies, IdentifierPrefixAndMinimality) {
    const uint8_t             forbidden[] = {0, 0xFF};
    tlv_identifier_policy_t   policy = {forbidden, sizeof(forbidden), 1, 0};
    tlv_variable_identifier_t config = {0x1F, 0x1F, 0x80, 0x7F, 16, &policy};
    const uint8_t             invalid[][3] = {{0, 0, 0}, {0xFF, 0x81, 0}, {0x9F, 0x80, 0}};
    for (const auto& bytes : invalid) {
        tlv_tag_t tag = tlv_tag(forbidden, 1);
        size_t    used = 99;
        EXPECT_EQ(TLV_ERR_INVALID_TAG,
                  tlv_variable_identifier_read(&config, bytes, 2, &tag, &used));
        EXPECT_EQ(forbidden, tag.data);
        EXPECT_EQ(99u, used);
        auto    input = tlv_tag(bytes, 2);
        uint8_t output[3] = {0xCC, 0xCC, 0xCC};
        EXPECT_EQ(TLV_ERR_INVALID_TAG,
                  tlv_variable_identifier_write(&config, &input, output, 3, &used));
        EXPECT_EQ(0xCC, output[0]);
        EXPECT_EQ(99u, used);
    }
    const uint8_t compatible[] = {0x9F, 0x1C};
    tlv_tag_t     tag{};
    size_t        used = 0;
    ASSERT_EQ(TLV_OK, tlv_variable_identifier_read(&config, compatible, 2, &tag, &used));
    policy.require_minimal = 1;
    EXPECT_EQ(TLV_ERR_INVALID_TAG,
              tlv_variable_identifier_read(&config, compatible, 2, &tag, &used));
    const uint8_t minimum[] = {0x9F, 0x1F};
    EXPECT_EQ(TLV_OK, tlv_variable_identifier_read(&config, minimum, 2, &tag, &used));
    // Wider than uint64_t: canonicality must not narrow the identifier number.
    const uint8_t wide[] = {0x9F, 0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0};
    ASSERT_EQ(TLV_OK, tlv_variable_identifier_read(&config, wide, sizeof(wide), &tag, &used));
    EXPECT_EQ(sizeof(wide), used);
    config.max_size = 2;
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE,
              tlv_variable_identifier_read(&config, wide, sizeof(wide), &tag, &used));
}

TEST(Unit_Tlv_VariablePolicies, SparseIdentifierMasksAndNonmaximalEscape) {
    const tlv_identifier_policy_t   policy = {nullptr, 0, 0, 1};
    const tlv_variable_identifier_t config = {0x50, 0x10, 1, 0xA0, 8, &policy};
    // Inline values 0, 2 and 3 exist. Value 1 must escape; payload bits are 5 and 7.
    const uint8_t minimal[] = {0x10, 0x20};
    const uint8_t nonminimal[] = {0x10, 0x80};
    const uint8_t padded[] = {0x10, 1, 0x20};
    const uint8_t larger[] = {0x10, 0x21, 0}; // Base four: 1, 0 -> 4.
    tlv_tag_t     tag{};
    size_t        used = 0;
    EXPECT_EQ(TLV_OK, tlv_variable_identifier_read(&config, minimal, 2, &tag, &used));
    EXPECT_EQ(TLV_ERR_INVALID_TAG,
              tlv_variable_identifier_read(&config, nonminimal, 2, &tag, &used));
    EXPECT_EQ(TLV_ERR_INVALID_TAG, tlv_variable_identifier_read(&config, padded, 3, &tag, &used));
    EXPECT_EQ(TLV_OK, tlv_variable_identifier_read(&config, larger, 3, &tag, &used));
}

TEST(Unit_Tlv_VariablePolicies, LengthFormsBoundsAndMinimalityBothOrders) {
    for (auto order : {TLV_BYTE_ORDER_BIG_ENDIAN, TLV_BYTE_ORDER_LITTLE_ENDIAN}) {
        tlv_length_policy_t   policy = {1, 1, 1, 2, 511};
        tlv_variable_length_t config = {0x80, 0x7F, order, &policy};
        for (tlv_size_t value : {UINT64_C(0), UINT64_C(127), UINT64_C(128), UINT64_C(255),
                                 UINT64_C(256), UINT64_C(511)}) {
            uint8_t    wire[3]{};
            size_t     written = 0, consumed = 0;
            tlv_size_t decoded = 99;
            ASSERT_EQ(TLV_OK, tlv_variable_length_write(&config, value, wire, 3, &written));
            EXPECT_EQ(value < 128 ? value : (value < 256 ? 0x81u : 0x82u), wire[0]);
            ASSERT_EQ(TLV_OK,
                      tlv_variable_length_read(&config, wire, written, &decoded, &consumed));
            EXPECT_EQ(value, decoded);
            EXPECT_EQ(written, consumed);
        }
        const uint8_t short_long[] = {0x81, 127};
        const uint8_t padded_be[] = {0x82, 0, 128}, padded_le[] = {0x82, 128, 0};
        tlv_size_t    decoded = 999;
        size_t        used = 99;
        EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
                  tlv_variable_length_read(&config, short_long, 2, &decoded, &used));
        EXPECT_EQ(999u, decoded);
        EXPECT_EQ(2u, used);
        EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
                  tlv_variable_length_read(
                      &config, order == TLV_BYTE_ORDER_BIG_ENDIAN ? padded_be : padded_le, 3,
                      &decoded, &used));
        policy.require_minimal = 0;
        EXPECT_EQ(TLV_OK, tlv_variable_length_read(&config, short_long, 2, &decoded, &used));
        for (uint8_t prefix : {0x80, 0x83, 0xFF}) {
            EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
                      tlv_variable_length_read(&config, &prefix, 1, &decoded, &used));
            EXPECT_EQ(1u, used);
        }
        const uint8_t truncated[] = {0x82, 1};
        EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
                  tlv_variable_length_read(&config, truncated, 2, &decoded, &used));
        EXPECT_EQ(2u, used);
        uint8_t output[3] = {0xCC, 0xCC, 0xCC};
        used = 99;
        EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
                  tlv_variable_length_write(&config, 512, output, 3, &used));
        EXPECT_EQ(0xCC, output[0]);
        EXPECT_EQ(99u, used);
        policy.allow_long = 0;
        EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
                  tlv_variable_length_write(&config, 128, output, 3, &used));
        policy.allow_long = 1;
        policy.allow_short = 0;
        policy.require_minimal = 1;
        ASSERT_EQ(TLV_OK, tlv_variable_length_write(&config, 0, output, 3, &used));
        EXPECT_EQ(2u, used);
        EXPECT_EQ(0x81, output[0]);
        EXPECT_EQ(0, output[1]);
        EXPECT_EQ(TLV_OK, tlv_variable_length_read(&config, output, used, &decoded, &used));
        const uint8_t zero = 0;
        EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
                  tlv_variable_length_read(&config, &zero, 1, &decoded, &used));
    }
}

TEST(Unit_Tlv_VariablePolicies, SparseLengthMasksAndOverflow) {
    tlv_length_policy_t   policy = {1, 1, 1, 15, UINT64_MAX};
    tlv_variable_length_t config = {1, 0xAA, TLV_BYTE_ORDER_LITTLE_ENDIAN, &policy};
    const uint8_t         wire[] = {9, 0, 1}; // Two following octets, 256 little endian.
    tlv_size_t            value = 0;
    size_t                used = 0;
    ASSERT_EQ(TLV_OK, tlv_variable_length_read(&config, wire, 3, &value, &used));
    EXPECT_EQ(256u, value);
    uint8_t output[3]{};
    ASSERT_EQ(TLV_OK, tlv_variable_length_write(&config, value, output, 3, &used));
    EXPECT_EQ(0, std::memcmp(wire, output, 3));
    config = {0x80, 0x7F, TLV_BYTE_ORDER_BIG_ENDIAN, &policy};
    const uint8_t overflow[] = {0x89, 1, 0, 0, 0, 0, 0, 0, 0, 0};
    value = 99;
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
              tlv_variable_length_read(&config, overflow, sizeof(overflow), &value, &used));
    EXPECT_EQ(99u, value);
    EXPECT_EQ(sizeof(overflow), used);
    config.policy = nullptr;
    EXPECT_EQ(TLV_ERR_OVERFLOW,
              tlv_variable_length_read(&config, overflow, sizeof(overflow), &value, &used));
}

TEST(Unit_Tlv_VariablePolicies, InvalidPolicyPreservesOutputs) {
    tlv_length_policy_t         policy = {0, 0, 0, 0, 0};
    const tlv_variable_length_t config = {0x80, 0x7F, TLV_BYTE_ORDER_BIG_ENDIAN, &policy};
    const uint8_t               wire = 0;
    size_t                      used = 99;
    tlv_size_t                  value = 99;
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_variable_length_read(&config, &wire, 1, &value, &used));
    EXPECT_EQ(99u, value);
    EXPECT_EQ(99u, used);
    policy = {1, 1, 0, 0, UINT64_MAX};
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_variable_length_write(&config, 0, nullptr, 0, &used));
    policy = {1, 1, 2, 8, UINT64_MAX};
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_variable_length_write(&config, 0, nullptr, 0, &used));
    tlv_identifier_policy_t         tag_policy = {nullptr, 1, 0, 0};
    const tlv_variable_identifier_t identifier = {0x1F, 0x1F, 0x80, 0x7F, 8, &tag_policy};
    tlv_tag_t                       tag{};
    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              tlv_variable_identifier_read(&identifier, &wire, 1, &tag, &used));
    tag_policy = {nullptr, 0, 2, 0};
    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              tlv_variable_identifier_read(&identifier, &wire, 1, &tag, &used));
    EXPECT_EQ(99u, used);
}
