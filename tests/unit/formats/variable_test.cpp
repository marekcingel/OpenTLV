// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/formats/variable.h"
#include <gtest/gtest.h>
#include <vector>

namespace {
const tlv_variable_identifier_t identifier = {0x1F, 0x1F, 0x80, 0x7F, 16};
const tlv_variable_length_t     count = {0x80, 0x7F, TLV_BYTE_ORDER_BIG_ENDIAN};
const tlv_variable_format_t     config = {identifier, count, TLV_ELEMENT_ORDER_TLV,
                                          TLV_LENGTH_SCOPE_VALUE};
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
    bad_order.length.byte_order = static_cast<tlv_byte_order_t>(99);
    EXPECT_EQ(TLV_ERR_INVALID_BYTE_ORDER, tlv_variable_format_init(&format, &bad_order));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_variable_format_init(nullptr, &config));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_variable_format_init(&format, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_variable_fields_init(nullptr, &config));
    tlv_field_composition_t fields = {};
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_variable_fields_init(&fields, nullptr));
}
