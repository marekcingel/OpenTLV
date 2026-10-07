// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/formats/escaped.h"
#include "tlv/formats/variable.h"
#include "tlv/config.h"
#include <gtest/gtest.h>
#include <cstring>

TEST(Unit_Tlv_TaggedFields, VariableWidthIdentifiersAndIndependentLengthCodec) {
    const tlv_variable_format_t     config{{0x1F, 0x1F, 0x80, 0x7F, 8},
                                           {0x80, 0x7F, TLV_BYTE_ORDER_BIG_ENDIAN},
                                           TLV_ELEMENT_ORDER_TLV,
                                           TLV_LENGTH_SCOPE_VALUE};
    const uint8_t                   marker[] = {0x9F, 0x02};
    const tlv_tag_t                 tag = tlv_tag(marker, sizeof(marker));
    tlv_tagged_fields_composition_t layout{};
    ASSERT_EQ(TLV_OK, tlv_variable_fields_init(&layout.fields, &config));
    layout.tag_only = &tag;
    layout.count = 1;
    tlv_format_t format{};
    ASSERT_EQ(TLV_OK, tlv_tagged_fields_format_init(&format, &layout));
    const uint8_t wire[] = {4, 0x81, 1, 42, 0x9F, 2};
    tlv_decoded_t normal{}, special{};
    ASSERT_EQ(TLV_OK, tlv_format_decode(&format, wire, sizeof(wire), &normal, nullptr));
    EXPECT_EQ(4u, normal.source.size);
    EXPECT_EQ(2u, normal.source.length.size);
    ASSERT_EQ(TLV_OK, tlv_format_decode(&format, wire + 4, 2, &special, nullptr));
    EXPECT_EQ(2u, special.source.size);
    EXPECT_FALSE(special.source.length.present);
    uint8_t output[2]{};
    size_t  written = 0;
    ASSERT_EQ(TLV_OK, tlv_format_encode(&format, &special.element, output, sizeof(output), &written,
                                        nullptr));
    EXPECT_EQ(0, std::memcmp(marker, output, sizeof(marker)));
    const auto original = format;
    auto       invalid = layout;
    invalid.fields.element_order = TLV_ELEMENT_ORDER_LTV;
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_tagged_fields_format_init(&format, &invalid));
    EXPECT_EQ(original.context, format.context);
    invalid = layout;
    invalid.fields.write_length = nullptr;
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_tagged_fields_format_init(&format, &invalid));
    invalid = layout;
    invalid.tag_only = nullptr;
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_tagged_fields_format_init(&format, &invalid));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_tagged_fields_format_init(nullptr, &layout));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_tagged_fields_format_init(&format, nullptr));
}

TEST(Unit_Tlv_Escaped, NonminimalPreservationAndCanonicalEncoding) {
    const tlv_escaped_format_t config{{2},
                                      {0x80, 2, TLV_BYTE_ORDER_LITTLE_ENDIAN, 0, 65535},
                                      TLV_ELEMENT_ORDER_LTV,
                                      TLV_LENGTH_SCOPE_TAG_AND_VALUE,
                                      nullptr,
                                      0};
    tlv_format_t               format{};
    ASSERT_EQ(TLV_OK, tlv_escaped_format_init(&format, &config));
    const uint8_t wire[] = {0x80, 3, 0, 0xAB, 0xCD, 42};
    tlv_decoded_t decoded{};
    ASSERT_EQ(TLV_OK, tlv_format_decode(&format, wire, sizeof(wire), &decoded, nullptr));
    EXPECT_EQ(3u, decoded.source.tag.offset);
    EXPECT_EQ(3u, decoded.source.length.size);
    EXPECT_EQ(1u, decoded.element.value.size);
    uint8_t output[sizeof(wire)]{};
    size_t  written = 0;
    ASSERT_EQ(TLV_OK, tlv_source_preserve(&decoded.source, &decoded.element, output, sizeof(output),
                                          &written));
    EXPECT_EQ(sizeof(wire), written);
    EXPECT_EQ(0, std::memcmp(wire, output, sizeof(wire)));
    ASSERT_EQ(TLV_OK, tlv_format_encode(&format, &decoded.element, output, sizeof(output), &written,
                                        nullptr));
    const uint8_t canonical[] = {3, 0xAB, 0xCD, 42};
    EXPECT_EQ(sizeof(canonical), written);
    EXPECT_EQ(0, std::memcmp(canonical, output, sizeof(canonical)));
    const uint8_t underflow[] = {1, 0xAB, 0xCD};
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
              tlv_format_decode(&format, underflow, sizeof(underflow), &decoded, nullptr));
}

TEST(Unit_Tlv_Escaped, IdentifierSelectionIsIndependentOfNfc) {
    EXPECT_EQ(OPENTLV_NFC, tlv_config_nfc());
    const uint8_t              tag_bytes[] = {0xAB, 0xCD};
    const tlv_tag_t            tag = tlv_tag(tag_bytes, 2);
    const tlv_escaped_format_t config{{2},
                                      {0x80, 2, TLV_BYTE_ORDER_LITTLE_ENDIAN, 0x80, 65535},
                                      TLV_ELEMENT_ORDER_TLV,
                                      TLV_LENGTH_SCOPE_VALUE,
                                      &tag,
                                      1};
    tlv_format_t               format{};
    ASSERT_EQ(TLV_OK, tlv_escaped_format_init(&format, &config));
    const uint8_t wire[] = {0xAB, 0xCD, 0, 0xFE, 1, 42};
    tlv_decoded_t special{}, normal{};
    ASSERT_EQ(TLV_OK, tlv_format_decode(&format, wire, sizeof(wire), &special, nullptr));
    EXPECT_EQ(2u, special.source.size);
    EXPECT_FALSE(special.source.length.present);
    ASSERT_EQ(TLV_OK, tlv_format_decode(&format, wire + 2, sizeof(wire) - 2, &normal, nullptr));
    EXPECT_EQ(1u, normal.element.value.size);
    uint8_t output[sizeof(wire)]{};
    size_t  written = 0;
    ASSERT_EQ(TLV_OK, tlv_format_encode(&format, &special.element, output, 2, &written, nullptr));
    ASSERT_EQ(TLV_OK,
              tlv_format_encode(&format, &normal.element, output + 2, 4, &written, nullptr));
    EXPECT_EQ(0, std::memcmp(wire, output, sizeof(wire)));
}

TEST(Unit_Tlv_Escaped, InvalidConfigurationPreservesDescriptorAndOutputs) {
    const tlv_escaped_format_t valid{{1},
                                     {255, 2, TLV_BYTE_ORDER_BIG_ENDIAN, 255, 65534},
                                     TLV_ELEMENT_ORDER_TLV,
                                     TLV_LENGTH_SCOPE_VALUE,
                                     nullptr,
                                     0};
    tlv_format_t               format{};
    ASSERT_EQ(TLV_OK, tlv_escaped_format_init(&format, &valid));
    const auto original = format;
    for (int field = 0; field < 10; ++field) {
        auto bad = valid;
        switch (field) {
            case 0: bad.identifier.size = 0; break;
            case 1: bad.length.escape = 0; break;
            case 2: bad.length.extended_size = 0; break;
            case 3: bad.length.extended_size = 9; break;
            case 4: bad.length.min_extended = 256; break;
            case 5: bad.length.max_length = 254; break;
            case 6: bad.length.max_length = 65536; break;
            case 7: bad.element_order = static_cast<tlv_element_order_t>(9); break;
            case 8: bad.length_scope = static_cast<tlv_length_scope_t>(9); break;
            case 9: bad.count = 1; break;
        }
        EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_escaped_format_init(&format, &bad));
        EXPECT_EQ(original.context, format.context);
    }
    auto bad = valid;
    bad.length.byte_order = TLV_BYTE_ORDER_UNKNOWN;
    EXPECT_EQ(TLV_ERR_INVALID_BYTE_ORDER, tlv_escaped_format_init(&format, &bad));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_escaped_format_init(nullptr, &valid));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_escaped_format_init(&format, nullptr));
    uint64_t count = 123;
    size_t   used = 456;
    EXPECT_EQ(TLV_ERR_INVALID_BYTE_ORDER,
              tlv_escaped_length_read(&bad.length, nullptr, 0, &count, &used));
    EXPECT_EQ(123u, count);
    EXPECT_EQ(456u, used);
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_escaped_length_read(&valid.length, nullptr, 1, &count, &used));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_escaped_length_write(&valid.length, 0, nullptr, 1, &used));
}
