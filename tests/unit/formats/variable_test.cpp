// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/formats/variable.h"
#include <gtest/gtest.h>
#include <vector>

namespace {
const tlv_variable_identifier_t identifier = {0x1F, 0x1F, 0x80, 0x7F, 16, NULL};
const tlv_variable_length_t     count = {0x80, 0x7F, TLV_BYTE_ORDER_BIG_ENDIAN, NULL};
const tlv_variable_format_t     config = {identifier, count, TLV_ELEMENT_ORDER_TLV,
                                          TLV_LENGTH_SCOPE_VALUE, NULL};
} // namespace

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
    bad_order.length.byte_order = TLV_BYTE_ORDER_UNKNOWN;
    EXPECT_EQ(TLV_ERR_INVALID_BYTE_ORDER, tlv_variable_format_init(&format, &bad_order));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_variable_format_init(nullptr, &config));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_variable_format_init(&format, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_variable_fields_init(nullptr, &config));
    tlv_field_composition_t fields = {};
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_variable_fields_init(&fields, nullptr));
}

TEST(Unit_Tlv_Variable, WriteCallbacksProvideSizingWithoutSeparateCallbacks) {
    tlv_field_composition_t fields{};
    ASSERT_EQ(TLV_OK, tlv_variable_fields_init(&fields, &config));
    fields.read_tag = nullptr;
    fields.read_length = nullptr;
    tlv_format_t format{};
    ASSERT_EQ(TLV_OK, tlv_fields_format_init(&format, &fields));
    EXPECT_EQ(nullptr, format.decode);
    ASSERT_NE(nullptr, format.measure);
    ASSERT_NE(nullptr, format.encode);

    const uint8_t   tag_bytes[] = {0x9F, 0x81, 0x00};
    const tlv_tag_t tag = tlv_tag(tag_bytes, sizeof(tag_bytes));
    for (tlv_size_t length : {tlv_size_t{0}, tlv_size_t{127}, tlv_size_t{128}, tlv_size_t{256}}) {
        size_t tag_size = 99, length_size = 99, written = 99;
        ASSERT_EQ(TLV_OK, fields.write_tag(fields.context, &tag, nullptr, 0, &tag_size));
        ASSERT_EQ(TLV_OK, fields.write_length(fields.context, length, nullptr, 0, &length_size));
        std::vector<uint8_t> value(static_cast<size_t>(length), 0xAA);
        const tlv_element_t  element{tag, {value.data(), length}};
        tlv_encoding_t       sizes{};
        ASSERT_EQ(TLV_OK, tlv_format_measure(&format, &element, &sizes, nullptr));
        EXPECT_EQ(tag_size + length_size, sizes.header);
        EXPECT_EQ(tag_size + length_size + length, sizes.total);
        std::vector<uint8_t> encoded(static_cast<size_t>(sizes.total));
        ASSERT_EQ(TLV_OK, tlv_format_encode(&format, &element, encoded.data(), encoded.size(),
                                            &written, nullptr));
        EXPECT_EQ(encoded.size(), written);
        uint8_t identifier_output[sizeof(tag_bytes)] = {};
        ASSERT_EQ(TLV_OK, fields.write_tag(fields.context, &tag, identifier_output,
                                           sizeof(identifier_output), &written));
        EXPECT_EQ(tag_size, written);
        for (size_t i = 0; i < tag_size; ++i) EXPECT_EQ(identifier_output[i], encoded[i]);
        uint8_t count_output[9] = {};
        ASSERT_EQ(TLV_OK, fields.write_length(fields.context, length, count_output,
                                              sizeof(count_output), &written));
        EXPECT_EQ(length_size, written);
        for (size_t i = 0; i < length_size; ++i) EXPECT_EQ(count_output[i], encoded[tag_size + i]);
    }
    fields.write_length = nullptr;
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_fields_format_init(&format, &fields));
}

TEST(Unit_Tlv_Variable, ConstructedPredicateUsesCanonicalBytesAndFormatContext) {
    const uint8_t         bytes[] = {0x9F, 0x22};
    const auto            tag = tlv_tag(bytes, sizeof(bytes));
    tlv_constructed_bit_t bit = {1, 3, 2};
    EXPECT_EQ(1, tlv_constructed_bit_predicate(&bit, &tag));
    EXPECT_EQ(0, tlv_constructed_bit_predicate(nullptr, &tag));
    EXPECT_EQ(0, tlv_constructed_bit_predicate(&bit, nullptr));
    bit.byte_index = SIZE_MAX;
    EXPECT_EQ(0, tlv_constructed_bit_predicate(&bit, &tag));
    bit = {0, 0x20, 0};
    EXPECT_EQ(1, tlv_constructed_bit_predicate(&bit, &tag));
    auto c = config;
    c.constructed = &bit;
    tlv_format_t format{};
    ASSERT_EQ(TLV_OK, tlv_variable_format_init(&format, &c));
    EXPECT_EQ(tlv_variable_decode, format.decode);
    EXPECT_EQ(tlv_variable_measure, format.measure);
    EXPECT_EQ(tlv_variable_encode, format.encode);
    ASSERT_NE(nullptr, format.is_constructed);
    EXPECT_EQ(1, format.is_constructed(format.context, &tag));
    bit.value = 0x40;
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_variable_format_init(&format, &c));
    EXPECT_EQ(0, tlv_constructed_bit_predicate(&bit, &tag));
    bit = {0, 0, 0};
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_variable_format_init(&format, &c));
}
