// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/formats/compose.h"
#include "tlv/config.h"
#include <gtest/gtest.h>
#include <cstring>

TEST(Unit_Tlv_TaggedBinary, DifferentIdentifiersWidthsAndByteOrder) {
    const uint8_t                         marker[] = {0xAB, 0xCD};
    const tlv_tag_t                       tags[] = {tlv_tag(marker, sizeof(marker))};
    const tlv_tagged_binary_composition_t layout = {
        {2, 2, TLV_BYTE_ORDER_LITTLE_ENDIAN, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE},
        tags,
        1};
    tlv_format_t format{};
    ASSERT_EQ(TLV_OK, tlv_tagged_binary_format_init(&format, &layout));
    const uint8_t wire[] = {0xAB, 0xCD, 0, 255, 1, 0, 42};
    tlv_decoded_t special{}, normal{};
    ASSERT_EQ(TLV_OK, tlv_format_decode(&format, wire, sizeof(wire), &special, nullptr));
    EXPECT_EQ(2u, special.source.size);
    EXPECT_FALSE(special.source.length.present);
    EXPECT_EQ(2u, special.source.value.offset);
    EXPECT_EQ(0u, special.element.value.size);
    // Bytes 00 FF have no special meaning in the generic composition.
    ASSERT_EQ(TLV_OK, tlv_format_decode(&format, wire + 2, sizeof(wire) - 2, &normal, nullptr));
    EXPECT_EQ(2u, normal.element.tag.size);
    EXPECT_TRUE(normal.source.length.present);
    EXPECT_EQ(2u, normal.source.length.offset);
    EXPECT_EQ(2u, normal.source.length.size);
    EXPECT_EQ(1u, normal.element.value.size);
    EXPECT_EQ(42, normal.element.value.data[0]);
    uint8_t output[sizeof(wire)] = {};
    size_t  written = 0;
    ASSERT_EQ(TLV_OK, tlv_format_encode(&format, &special.element, output, sizeof(output), &written,
                                        nullptr));
    EXPECT_EQ(2u, written);
    ASSERT_EQ(TLV_OK, tlv_format_encode(&format, &normal.element, output + 2, sizeof(output) - 2,
                                        &written, nullptr));
    EXPECT_EQ(5u, written);
    EXPECT_EQ(0, std::memcmp(wire, output, sizeof(wire)));
    auto invalid = special.element;
    invalid.value = normal.element.value;
    tlv_encoding_t sizes{};
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_format_measure(&format, &invalid, &sizes, nullptr));
    EXPECT_EQ(OPENTLV_DHCP, tlv_config_dhcp());
}

TEST(Unit_Tlv_TaggedBinary, ValidatesConfigurationAndPreservesDescriptor) {
    const uint8_t                         marker = 42;
    tlv_tag_t                             tag = tlv_tag(&marker, 1);
    const tlv_tagged_binary_composition_t valid = {
        {1, 1, TLV_BYTE_ORDER_BIG_ENDIAN, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE}, &tag, 1};
    tlv_format_t format{};
    ASSERT_EQ(TLV_OK, tlv_tagged_binary_format_init(&format, &valid));
    const auto original = format;
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_tagged_binary_format_init(nullptr, &valid));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_tagged_binary_format_init(&format, nullptr));
    for (unsigned field = 0; field < 8; ++field) {
        auto bad = valid;
        switch (field) {
            case 0: bad.fields.tag_size = 0; break;
            case 1: bad.fields.length_size = 0; break;
            case 2: bad.fields.length_size = 9; break;
            case 3: bad.fields.element_order = TLV_ELEMENT_ORDER_LTV; break;
            case 4: bad.fields.length_scope = TLV_LENGTH_SCOPE_TAG_AND_VALUE; break;
            case 5: bad.tag_only = nullptr; break;
            case 6: tag.size = 2; break;
            case 7: tag = tlv_tag(nullptr, 1); break;
        }
        EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_tagged_binary_format_init(&format, &bad));
        EXPECT_EQ(original.context, format.context);
        EXPECT_EQ(original.decode, format.decode);
        EXPECT_EQ(original.measure, format.measure);
        EXPECT_EQ(original.encode, format.encode);
        tag = tlv_tag(&marker, 1);
    }
    auto empty = valid;
    empty.fields.length_order = TLV_BYTE_ORDER_UNKNOWN;
    EXPECT_EQ(TLV_ERR_INVALID_BYTE_ORDER, tlv_tagged_binary_format_init(&format, &empty));
    EXPECT_EQ(original.context, format.context);
    empty = valid;
    empty.tag_only = nullptr;
    empty.count = 0;
    ASSERT_EQ(TLV_OK, tlv_tagged_binary_format_init(&format, &empty));
    const uint8_t wire[] = {42, 0};
    tlv_decoded_t decoded{};
    ASSERT_EQ(TLV_OK, tlv_format_decode(&format, wire, sizeof(wire), &decoded, nullptr));
    EXPECT_TRUE(decoded.source.length.present);
    EXPECT_EQ(2u, decoded.source.size);
}
