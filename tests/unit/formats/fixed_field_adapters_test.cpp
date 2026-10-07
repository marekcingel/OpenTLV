// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/formats/fixed.h"
#include "tlv/formats/escaped.h"
#include "tlv/tlv.h"
#if OPENTLV_FORMAT_CER
#include "tlv/builtins/asn1/cer.h"
#endif
#if OPENTLV_EMV
#include "tlv/builtins/emv/format.h"
#endif
#include <gtest/gtest.h>
#include <algorithm>
#include <array>
#include <vector>

TEST(Unit_Tlv_FixedFieldAdapters, DecodePreservesPrefixRangesAndElementRelativeErrors) {
    for (auto order : {TLV_ELEMENT_ORDER_TLV, TLV_ELEMENT_ORDER_LTV}) {
        const tlv_fixed_format_t binary{
            {2}, {2, TLV_BYTE_ORDER_BIG_ENDIAN}, order, TLV_LENGTH_SCOPE_VALUE};
        const tlv_escaped_format_t escaped{{2},     {0x80, 2, TLV_BYTE_ORDER_BIG_ENDIAN, 0, 65535},
                                           order,   TLV_LENGTH_SCOPE_VALUE,
                                           nullptr, 0};
        for (bool use_escape : {false, true}) {
            SCOPED_TRACE(::testing::Message() << "escaped=" << use_escape << " order=" << order);
            tlv_format_t format{};
            ASSERT_EQ(TLV_OK, use_escape ? tlv_escaped_format_init(&format, &escaped)
                                         : tlv_fixed_format_init(&format, &binary));
            const size_t         length_width = use_escape ? 3 : 2;
            const size_t         tag_offset = order == TLV_ELEMENT_ORDER_TLV ? 0 : length_width;
            const size_t         length_offset = order == TLV_ELEMENT_ORDER_TLV ? 2 : 0;
            std::vector<uint8_t> wire(length_width + 3, 0);
            wire[tag_offset] = 0xAB;
            wire[tag_offset + 1] = 0xCD;
            if (use_escape) wire[length_offset] = 0x80;
            wire[length_offset + length_width - 1] = 1;
            wire.back() = 42;
            for (size_t available = 1; available < wire.size(); ++available) {
                SCOPED_TRACE(available);
                tlv_decoded_t decoded{};
                decoded.source.size = 99;
                tlv_format_error_t error{};
                EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
                          tlv_format_decode(&format, wire.data(), available, &decoded, &error));
                EXPECT_EQ(99u, decoded.source.size);
                const bool         tag_complete = available >= tag_offset + 2;
                const bool         length_complete = available >= length_offset + length_width;
                const bool         tag_first = order == TLV_ELEMENT_ORDER_TLV;
                const tlv_region_t region = tag_first && !tag_complete ? TLV_REGION_TAG
                                            : !length_complete         ? TLV_REGION_LENGTH
                                            : !tag_complete            ? TLV_REGION_TAG
                                                                       : TLV_REGION_VALUE;
                const size_t       offset = region == TLV_REGION_TAG      ? tag_offset
                                            : region == TLV_REGION_LENGTH ? length_offset
                                                                          : length_width + 2;
                EXPECT_EQ(region, error.region);
                EXPECT_TRUE(error.has_offset);
                EXPECT_EQ(offset, error.offset);
                EXPECT_EQ(tag_complete, !!error.tag.present);
                if (tag_complete) {
                    EXPECT_EQ(tag_offset, error.tag.offset);
                    EXPECT_EQ(2u, error.tag.size);
                }
                const bool length_started = !tag_first || tag_complete;
                EXPECT_EQ(length_started, !!error.length.present);
                if (length_started) {
                    EXPECT_EQ(length_offset, error.length.offset);
                    EXPECT_EQ(std::min(length_width, available - length_offset), error.length.size);
                }
                EXPECT_EQ(!use_escape || region == TLV_REGION_VALUE, !!error.has_required);
                if (error.has_required)
                    EXPECT_EQ(region == TLV_REGION_VALUE ? 1u : 2u, error.required);
            }
            tlv_decoded_t decoded{};
            ASSERT_EQ(TLV_OK,
                      tlv_format_decode(&format, wire.data(), wire.size(), &decoded, nullptr));
            EXPECT_EQ(wire.data() + tag_offset, decoded.element.tag.data);
            EXPECT_EQ(2u, decoded.element.tag.size);
            EXPECT_EQ(length_offset, decoded.source.length.offset);
            EXPECT_EQ(length_width, decoded.source.length.size);
            EXPECT_EQ(length_width + 2, decoded.source.header.size);
            EXPECT_EQ(wire.data() + length_width + 2, decoded.element.value.data);
        }
    }
}

TEST(Unit_Tlv_FixedFieldAdapters, TagValidationMatchesPrimitiveAndDoesNotMutateOutput) {
    const tlv_fixed_format_t binary{
        {2}, {1, TLV_BYTE_ORDER_BIG_ENDIAN}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
    const tlv_escaped_format_t escaped{{2},
                                       {0x80, 1, TLV_BYTE_ORDER_BIG_ENDIAN, 0, 255},
                                       TLV_ELEMENT_ORDER_TLV,
                                       TLV_LENGTH_SCOPE_VALUE,
                                       nullptr,
                                       0};
    for (bool use_escape : {false, true}) {
        tlv_format_t format{};
        ASSERT_EQ(TLV_OK, use_escape ? tlv_escaped_format_init(&format, &escaped)
                                     : tlv_fixed_format_init(&format, &binary));
        const uint8_t      tag_bytes[] = {0xAB, 0xCD};
        const uint8_t      value[256] = {};
        const tlv_tag_t    tags[] = {tlv_tag(nullptr, 0), tlv_tag(nullptr, 1), tlv_tag(nullptr, 2),
                                     tlv_tag(tag_bytes, 1), tlv_tag(tag_bytes, 2)};
        const tlv_result_t expected[] = {TLV_ERR_INVALID_TAG_SIZE, TLV_ERR_NULL_ARG,
                                         TLV_ERR_NULL_ARG, TLV_ERR_INVALID_TAG_SIZE,
                                         TLV_ERR_INVALID_LENGTH};
        for (size_t i = 0; i < sizeof(tags) / sizeof(tags[0]); ++i) {
            const tlv_element_t      element{tags[i], {value, sizeof(value)}};
            std::array<uint8_t, 260> output;
            output.fill(0xCC);
            const auto         before = output;
            size_t             written = 99;
            tlv_encoding_t     sizes{11, 12, 13, 36};
            tlv_format_error_t error{};
            // Composition delegates field validation without changing its precedence.
            size_t             field_width = 99;
            const tlv_result_t field_result =
                tlv_fixed_identifier_write(&binary.identifier, &tags[i], nullptr, 0, &field_width);
            EXPECT_EQ(i == 4 ? TLV_OK : expected[i], field_result);
            EXPECT_EQ(expected[i], format.measure(format.context, &element, &sizes, &error));
            EXPECT_EQ(i == 4 ? TLV_REGION_LENGTH : TLV_REGION_TAG, error.region);
            EXPECT_EQ(i == 4 ? 2u : 0u, error.offset);
            EXPECT_EQ(11u, sizes.header);
            EXPECT_EQ(36u, sizes.total);
            EXPECT_EQ(expected[i], format.encode(format.context, &element, output.data(),
                                                 output.size(), &written, &error));
            EXPECT_EQ(99u, written);
            EXPECT_EQ(before, output);
            // The validated entry point rejects a nonempty tag with NULL bytes first.
            const tlv_result_t public_expected = expected[i];
            EXPECT_EQ(public_expected, tlv_format_encode(&format, &element, output.data(),
                                                         output.size(), &written, &error));
            EXPECT_EQ(99u, written);
            EXPECT_EQ(before, output);
        }
    }
}

TEST(Unit_Tlv_FixedFieldAdapters, ShortOutputReportsWidthAtTheExistingApiBoundary) {
    const tlv_fixed_format_t binary{
        {2}, {1, TLV_BYTE_ORDER_BIG_ENDIAN}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
    const tlv_escaped_format_t escaped{{2},
                                       {0x80, 1, TLV_BYTE_ORDER_BIG_ENDIAN, 0, 255},
                                       TLV_ELEMENT_ORDER_TLV,
                                       TLV_LENGTH_SCOPE_VALUE,
                                       nullptr,
                                       0};
    const uint8_t              tag[] = {0xAB, 0xCD};
    const uint8_t              value[] = {42};
    const tlv_element_t        element{tlv_tag(tag, sizeof(tag)), {value, sizeof(value)}};
    for (bool use_escape : {false, true}) {
        tlv_format_t format{};
        ASSERT_EQ(TLV_OK, use_escape ? tlv_escaped_format_init(&format, &escaped)
                                     : tlv_fixed_format_init(&format, &binary));
        for (size_t capacity = 0; capacity < 4; ++capacity) {
            std::array<uint8_t, 5> output{{0xCC, 0xCC, 0xCC, 0xCC, 0xCC}};
            const auto             before = output;
            tlv_format_error_t     error{};
            size_t                 written = 99;
            EXPECT_EQ(
                TLV_ERR_BUFFER_TOO_SHORT,
                format.encode(format.context, &element, output.data(), capacity, &written, &error));
            EXPECT_EQ(99u, written);
            EXPECT_EQ(TLV_REGION_LENGTH, error.region);
            EXPECT_EQ(2u, error.offset);
            EXPECT_EQ(before, output);
            EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_format_encode(&format, &element, output.data(),
                                                                  capacity, &written, &error));
            EXPECT_EQ(4u, written);
            EXPECT_EQ(TLV_REGION_VALUE, error.region);
            EXPECT_TRUE(error.has_required);
            EXPECT_EQ(4u, error.required);
            EXPECT_EQ(before, output);
        }
    }
}

TEST(Unit_Tlv_FixedFieldAdapters, TagOnlyCallbacksRejectNullOutputWithNonzeroCapacity) {
    const uint8_t                         bytes[] = {0xAB, 0xCD};
    const tlv_tag_t                       tag = tlv_tag(bytes, sizeof(bytes));
    const tlv_tagged_binary_composition_t binary{
        {{2}, {1, TLV_BYTE_ORDER_BIG_ENDIAN}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE},
        &tag,
        1};
    const tlv_escaped_format_t escaped{{2},
                                       {0x80, 1, TLV_BYTE_ORDER_BIG_ENDIAN, 0, 255},
                                       TLV_ELEMENT_ORDER_TLV,
                                       TLV_LENGTH_SCOPE_VALUE,
                                       &tag,
                                       1};
    const tlv_element_t        element{tag, {nullptr, 0}};
    for (bool use_escape : {false, true}) {
        tlv_format_t format{};
        ASSERT_EQ(TLV_OK, use_escape ? tlv_escaped_format_init(&format, &escaped)
                                     : tlv_tagged_binary_format_init(&format, &binary));
        tlv_format_error_t error{};
        size_t             written = 99;
        EXPECT_EQ(TLV_ERR_NULL_ARG,
                  format.encode(format.context, &element, nullptr, 2, &written, &error));
        EXPECT_EQ(99u, written);
        written = 99;
        EXPECT_EQ(TLV_ERR_NULL_ARG,
                  tlv_format_encode(&format, &element, nullptr, 2, &written, &error));
        EXPECT_EQ(99u, written);
    }
}

TEST(Unit_Tlv_FixedFieldAdapters, BinaryCallbacksUseTheRealLengthConfiguration) {
    const uint8_t       wire[] = {0xAB, 0xCD, 0, 0, 0, 0};
    const tlv_element_t element{tlv_tag(wire, 2), {nullptr, 0}};
    for (size_t width : {size_t{0}, size_t{2}, size_t{9}}) {
        for (auto order :
             {TLV_BYTE_ORDER_UNKNOWN, TLV_BYTE_ORDER_BIG_ENDIAN, TLV_BYTE_ORDER_LITTLE_ENDIAN}) {
            const tlv_binary_composition_t config{
                {2}, {width, order}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
            const tlv_tagged_binary_composition_t tagged{config, nullptr, 0};
            size_t                                measured = 99;
            const auto expected = tlv_fixed_length_write(&config.length, 0, nullptr, 0, &measured);
            tlv_encoding_t     sizes{};
            tlv_format_error_t error{};
            EXPECT_EQ(expected, tlv_binary_measure(&config, &element, &sizes, &error));
            EXPECT_EQ(expected, tlv_tagged_binary_measure(&tagged, &element, &sizes, &error));
            if (expected != TLV_OK) EXPECT_EQ(99u, measured);
            for (size_t available = 0; available <= 2; ++available) {
                size_t     consumed = 0;
                tlv_size_t value = 99;
                const auto read_result =
                    tlv_fixed_length_read(&config.length, wire + 2, available, &value, &consumed);
                tlv_decoded_t decoded{};
                error = {};
                EXPECT_EQ(read_result,
                          tlv_binary_decode(&config, wire, 2 + available, &decoded, &error));
                EXPECT_EQ(consumed, error.length.size);
                if (expected != TLV_OK) EXPECT_EQ(0u, consumed);
                if (read_result != TLV_OK) EXPECT_EQ(99u, value);
            }
            std::array<uint8_t, 6> output;
            output.fill(0xCC);
            const auto before = output;
            size_t     written = 99;
            EXPECT_EQ(expected, tlv_binary_encode(&config, &element, output.data(), output.size(),
                                                  &written, &error));
            if (expected != TLV_OK) {
                EXPECT_EQ(before, output);
                EXPECT_EQ(99u, written);
            }
        }
    }
}

TEST(Unit_Tlv_FixedFieldAdapters, InitializersValidateFieldsBeforeCompositionPolicy) {
    tlv_format_t             format{};
    const tlv_fixed_format_t valid{
        {1}, {1, TLV_BYTE_ORDER_BIG_ENDIAN}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
    ASSERT_EQ(TLV_OK, tlv_fixed_format_init(&format, &valid));
    auto fixed = valid;
    fixed.identifier.size = 0;
    fixed.length.byte_order = TLV_BYTE_ORDER_UNKNOWN;
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_fixed_format_init(nullptr, &fixed));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_fixed_format_init(&format, &fixed));
    const tlv_tag_t                 missing = tlv_tag(nullptr, 1);
    tlv_tagged_binary_composition_t tagged{fixed, &missing, 1};
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_tagged_binary_format_init(nullptr, &tagged));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_tagged_binary_format_init(&format, &tagged));
    tagged.fields.identifier.size = 1;
    EXPECT_EQ(TLV_ERR_INVALID_BYTE_ORDER, tlv_tagged_binary_format_init(&format, &tagged));
    tlv_escaped_format_t escaped{{0},
                                 {0x80, 1, TLV_BYTE_ORDER_UNKNOWN, 0, 255},
                                 TLV_ELEMENT_ORDER_TLV,
                                 TLV_LENGTH_SCOPE_VALUE,
                                 nullptr,
                                 0};
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_escaped_format_init(nullptr, &escaped));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_escaped_format_init(&format, &escaped));
    escaped.identifier.size = 1;
    EXPECT_EQ(TLV_ERR_INVALID_BYTE_ORDER, tlv_escaped_format_init(&format, &escaped));
    escaped.length.extended_size = 0;
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_escaped_format_init(&format, &escaped));
    EXPECT_EQ(&valid, format.context);
    EXPECT_EQ(&tlv_binary_decode, format.decode);
    EXPECT_EQ(&tlv_binary_measure, format.measure);
    EXPECT_EQ(&tlv_binary_encode, format.encode);
}

TEST(Unit_Tlv_FixedFieldAdapters, BuiltinFieldCallbacksFollowArgumentAndPrefixContracts) {
    const tlv_format_t* formats[] = {
        nullptr,
#if OPENTLV_FORMAT_BER
        &tlv_format_ber,
#endif
#if OPENTLV_FORMAT_DER
        &tlv_format_der,
#endif
#if OPENTLV_FORMAT_CER
        &tlv_format_cer,
#endif
#if OPENTLV_EMV
        &tlv_format_emv,
#endif
    };
    for (const auto* format : formats) {
        if (!format) continue;
        const auto*     fields = static_cast<const tlv_field_composition_t*>(format->context);
        const uint8_t   bytes[] = {0x9F, 0x1F};
        const tlv_tag_t tag = tlv_tag(bytes, sizeof(bytes));
        const tlv_tag_t missing = tlv_tag(nullptr, 999);
        uint8_t         output[] = {0xCC, 0xCC};
        size_t          used = 99;
        EXPECT_EQ(TLV_ERR_NULL_ARG, fields->write_tag(fields->context, &missing, output, 2, &used));
        EXPECT_EQ(TLV_ERR_NULL_ARG, fields->write_tag(fields->context, &tag, nullptr, 2, &used));
        EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
                  fields->write_tag(fields->context, &tag, output, 1, &used));
        EXPECT_EQ(99u, used);
        EXPECT_EQ(0xCC, output[0]);
        EXPECT_EQ(0xCC, output[1]);
        tlv_tag_t parsed = tag;
        EXPECT_EQ(TLV_ERR_NULL_ARG, fields->read_tag(fields->context, nullptr, 1, &parsed, &used));
        EXPECT_EQ(99u, used);
        EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
                  fields->read_tag(fields->context, bytes, 1, &parsed, &used));
        EXPECT_EQ(1u, used);
        EXPECT_EQ(tag.data, parsed.data);
        EXPECT_EQ(tag.size, parsed.size);
        tlv_size_t value = 42;
        used = 99;
        EXPECT_EQ(TLV_ERR_NULL_ARG,
                  fields->read_length(fields->context, nullptr, 1, &value, &used));
        EXPECT_EQ(99u, used);
        EXPECT_EQ(42u, value);
    }
}
