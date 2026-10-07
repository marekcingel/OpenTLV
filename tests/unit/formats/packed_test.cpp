// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/formats/packed.h"
#include <gtest/gtest.h>
#include <array>
#include <cstring>

namespace {
const uint8_t       tags[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
tlv_packed_layout_t layout() {
    return {2,
            {2, 12, 4, TLV_BYTE_ORDER_BIG_ENDIAN},
            {2, 0, 12, TLV_BYTE_ORDER_BIG_ENDIAN},
            TLV_LENGTH_SCOPE_VALUE,
            tags,
            1,
            sizeof(tags)};
}
tlv_format_t descriptor(const tlv_packed_layout_t& config) {
    return {&config, tlv_packed_decode, tlv_packed_measure, tlv_packed_encode, nullptr};
}
} // namespace

TEST(Unit_Tlv_Packed, IndependentFourTwelveBitWireVector) {
    auto          config = layout();
    auto          format = descriptor(config);
    const uint8_t wire[] = {0xB0, 3, 7, 8, 9};
    tlv_decoded_t decoded{};
    ASSERT_EQ(TLV_OK, tlv_format_decode(&format, wire, sizeof(wire), &decoded, nullptr));
    EXPECT_EQ(tags + 11, decoded.element.tag.data);
    EXPECT_EQ(3u, decoded.element.value.size);
    EXPECT_EQ(0u, decoded.source.tag.offset);
    EXPECT_EQ(1u, decoded.source.tag.size);
    EXPECT_EQ(0u, decoded.source.length.offset);
    EXPECT_EQ(2u, decoded.source.length.size);
    EXPECT_EQ(TLV_TAG_BINDING_FORMAT, decoded.source.tag_binding);
    uint8_t output[5]{};
    size_t  written = 0;
    // A copied semantic identifier must work, independently of table pointers.
    const uint8_t tag = 11;
    decoded.element.tag = tlv_tag(&tag, 1);
    ASSERT_EQ(TLV_OK, tlv_format_encode(&format, &decoded.element, output, sizeof(output), &written,
                                        nullptr));
    EXPECT_EQ(sizeof(wire), written);
    EXPECT_EQ(0, std::memcmp(wire, output, written));
}

TEST(Unit_Tlv_Packed, EveryHeaderWidthEndianAndScopeClearsUnusedBits) {
    for (size_t width = 1; width <= 8; ++width) {
        for (auto order : {TLV_BYTE_ORDER_BIG_ENDIAN, TLV_BYTE_ORDER_LITTLE_ENDIAN}) {
            for (auto scope : {TLV_LENGTH_SCOPE_VALUE, TLV_LENGTH_SCOPE_TAG_AND_VALUE}) {
                tlv_packed_layout_t config = {
                    width, {width, 4, 4, order}, {width, 0, 4, order}, scope, tags,
                    1,     sizeof(tags)};
                auto                    format = descriptor(config);
                const uint8_t           tag = 10, value[] = {42, 43};
                const tlv_element_t     element = {tlv_tag(&tag, 1), {value, 2}};
                std::array<uint8_t, 10> wire;
                wire.fill(0xFF);
                size_t written = 0;
                ASSERT_EQ(TLV_OK, tlv_format_encode(&format, &element, wire.data(), wire.size(),
                                                    &written, nullptr));
                const size_t index = order == TLV_BYTE_ORDER_BIG_ENDIAN ? width - 1 : 0;
                EXPECT_EQ(scope == TLV_LENGTH_SCOPE_VALUE ? 0xA2 : 0xA3, wire[index]);
                for (size_t i = 0; i < width; ++i)
                    if (i != index) EXPECT_EQ(0, wire[i]);
                EXPECT_EQ(42, wire[width]);
                EXPECT_EQ(43, wire[width + 1]);
                tlv_decoded_t decoded{};
                ASSERT_EQ(TLV_OK,
                          tlv_format_decode(&format, wire.data(), written, &decoded, nullptr));
                EXPECT_EQ(index, decoded.source.tag.offset);
                EXPECT_EQ(index, decoded.source.length.offset);
                EXPECT_EQ(2u, decoded.element.value.size);
                EXPECT_EQ(tags + 10, decoded.element.tag.data);
                // Reserved bits may be set by a source; normalized encoding clears them.
                if (width > 1) wire[index == 0 ? 1 : 0] = 0xFF;
                ASSERT_EQ(TLV_OK,
                          tlv_format_decode(&format, wire.data(), written, &decoded, nullptr));
            }
        }
    }
}

TEST(Unit_Tlv_Packed, ScopeUsesWireEnvelopeInsteadOfCanonicalWidth) {
    std::array<uint8_t, 32> table{};
    for (size_t i = 0; i < 16; ++i) table[2 * i + 1] = static_cast<uint8_t>(i);
    auto config = layout();
    config.tag_storage = table.data();
    config.tag_storage_size = table.size();
    config.tag_size = 2;
    config.length_scope = TLV_LENGTH_SCOPE_TAG_AND_VALUE;
    auto          format = descriptor(config);
    const uint8_t wire[] = {0x70, 1};
    tlv_decoded_t first{}, second{};
    ASSERT_EQ(TLV_OK, tlv_format_decode(&format, wire, sizeof(wire), &first, nullptr));
    EXPECT_EQ(0u, first.element.value.size);
    EXPECT_EQ(2u, first.element.tag.size);
    const uint8_t next[] = {0x80, 1};
    ASSERT_EQ(TLV_OK, tlv_format_decode(&format, next, sizeof(next), &second, nullptr));
    EXPECT_EQ(7, first.element.tag.data[1]);
    uint8_t output[2]{};
    size_t  written = 0;
    ASSERT_EQ(TLV_OK, tlv_format_encode(&format, &first.element, output, 2, &written, nullptr));
    EXPECT_EQ(0, std::memcmp(wire, output, 2));
    table[15] = 8;
    EXPECT_EQ(TLV_ERR_INVALID_TAG, tlv_format_decode(&format, wire, 2, &second, nullptr));
}

TEST(Unit_Tlv_Packed, MultibyteIdentifierAndSharedByteEnvelope) {
    std::array<uint8_t, 1024> table{};
    for (size_t i = 0; i < 512; ++i) {
        table[2 * i] = static_cast<uint8_t>(i >> 8);
        table[2 * i + 1] = static_cast<uint8_t>(i);
    }
    const tlv_packed_layout_t config = {3,
                                        {3, 7, 9, TLV_BYTE_ORDER_LITTLE_ENDIAN},
                                        {3, 0, 7, TLV_BYTE_ORDER_LITTLE_ENDIAN},
                                        TLV_LENGTH_SCOPE_TAG_AND_VALUE,
                                        table.data(),
                                        2,
                                        table.size()};
    auto                      format = descriptor(config);
    const uint8_t wire[] = {0x82, 0xFF, 0xAA}; // Type 511, count 2, reserved byte ignored.
    tlv_decoded_t decoded{};
    ASSERT_EQ(TLV_OK, tlv_format_decode(&format, wire, 3, &decoded, nullptr));
    EXPECT_EQ(1, decoded.element.tag.data[0]);
    EXPECT_EQ(255, decoded.element.tag.data[1]);
    EXPECT_EQ(2u, decoded.source.tag.size);
    EXPECT_EQ(1u, decoded.source.length.size);
    EXPECT_EQ(0u, decoded.element.value.size);
    uint8_t output[3]{};
    size_t  written = 0;
    ASSERT_EQ(TLV_OK, tlv_format_encode(&format, &decoded.element, output, 3, &written, nullptr));
    EXPECT_EQ(0x82, output[0]);
    EXPECT_EQ(0xFF, output[1]);
    EXPECT_EQ(0, output[2]);
}

TEST(Unit_Tlv_Packed, TruncationAndScopeUnderflowPreserveDecodedOutput) {
    auto config = layout();
    config.length_scope = TLV_LENGTH_SCOPE_TAG_AND_VALUE;
    auto          format = descriptor(config);
    const uint8_t wire[] = {0x10, 4, 42, 43, 44};
    for (size_t size = 0; size < sizeof(wire); ++size) {
        tlv_decoded_t decoded{};
        decoded.source.size = 99;
        tlv_format_error_t error{};
        EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
                  tlv_packed_decode(&config, size ? wire : nullptr, size, &decoded, &error));
        EXPECT_EQ(99u, decoded.source.size);
        EXPECT_EQ(size < 2 ? TLV_REGION_HEADER : TLV_REGION_VALUE, error.region);
        EXPECT_EQ(size < 2 ? 0u : 2u, error.offset);
        EXPECT_EQ(size < 2 ? 2u : 3u, error.required);
    }
    const uint8_t      invalid[] = {0x10, 0};
    tlv_decoded_t      decoded{};
    tlv_format_error_t error{};
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_format_decode(&format, invalid, 2, &decoded, &error));
    EXPECT_EQ(TLV_REGION_LENGTH, error.region);
}

TEST(Unit_Tlv_Packed, MeasureRejectsOutOfRangeAndEncodeFailureIsAtomic) {
    auto               config = layout();
    auto               format = descriptor(config);
    uint8_t            tag = 16, value = 42;
    tlv_element_t      element = {tlv_tag(&tag, 1), {&value, 0}};
    tlv_encoding_t     sizes{};
    tlv_format_error_t error{};
    EXPECT_EQ(TLV_ERR_INVALID_TAG, tlv_format_measure(&format, &element, &sizes, &error));
    tag = 15;
    element.tag.size = 2;
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE, tlv_format_measure(&format, &element, &sizes, &error));
    element.tag.size = 1;
    element.value.size = 4095;
    EXPECT_EQ(TLV_OK, tlv_format_measure(&format, &element, &sizes, &error));
    config.length_scope = TLV_LENGTH_SCOPE_TAG_AND_VALUE;
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_format_measure(&format, &element, &sizes, &error));
    element.value.size = UINT64_MAX;
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_format_measure(&format, &element, &sizes, &error));
    element.value.size = 1;
    uint8_t output[] = {0xCC, 0xCC, 0xCC};
    size_t  written = 99;
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              tlv_packed_encode(&config, &element, output, 2, &written, &error));
    EXPECT_EQ(99u, written);
    for (auto byte : output) EXPECT_EQ(0xCC, byte);
}

TEST(Unit_Tlv_Packed, ConfigurationValidationDoesNotReadStorage) {
    auto good = layout();
    ASSERT_EQ(TLV_OK, tlv_packed_layout_validate(&good));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_packed_layout_validate(nullptr));
    for (int i = 0; i < 10; ++i) {
        auto bad = good;
        switch (i) {
            case 0: bad.header_size = 0; break;
            case 1: bad.header_size = 9; break;
            case 2: bad.tag.storage_size = 1; break;
            case 3: bad.tag.bit_width = 0; break;
            case 4: bad.tag.bit_offset = 64; break;
            case 5: bad.tag.bit_offset = 0; break;
            case 6: bad.length.byte_order = TLV_BYTE_ORDER_LITTLE_ENDIAN; break;
            case 7: bad.tag_size = 0; break;
            case 8: bad.tag_size = 9; break;
            case 9: bad.tag_storage_size = 15; break;
        }
        EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_packed_layout_validate(&bad)) << i;
    }
    auto bad = good;
    bad.tag.byte_order = TLV_BYTE_ORDER_UNKNOWN;
    EXPECT_EQ(TLV_ERR_INVALID_BYTE_ORDER, tlv_packed_layout_validate(&bad));
    bad = good;
    bad.tag_storage = nullptr;
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_packed_layout_validate(&bad));
    // Full table multiplication overflows on both 32-bit and 64-bit hosts.
    bad = {8,
           {8, 1, 63, TLV_BYTE_ORDER_BIG_ENDIAN},
           {8, 0, 1, TLV_BYTE_ORDER_BIG_ENDIAN},
           TLV_LENGTH_SCOPE_VALUE,
           tags,
           8,
           SIZE_MAX};
    EXPECT_EQ(TLV_ERR_OVERFLOW, tlv_packed_layout_validate(&bad));
}

TEST(Unit_Tlv_Packed, WideLengthIsCheckedBeforeNativeNarrowing) {
    const tlv_packed_layout_t config = {8,
                                        {8, 63, 1, TLV_BYTE_ORDER_BIG_ENDIAN},
                                        {8, 0, 63, TLV_BYTE_ORDER_BIG_ENDIAN},
                                        TLV_LENGTH_SCOPE_VALUE,
                                        tags,
                                        1,
                                        sizeof(tags)};
    auto                      format = descriptor(config);
    const uint8_t             wire[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    tlv_decoded_t             decoded{};
    tlv_format_error_t        error{};
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              tlv_format_decode(&format, wire, sizeof(wire), &decoded, &error));
    EXPECT_EQ(UINT64_MAX >> 1, error.required);
    EXPECT_EQ(8u, error.offset);
    const uint8_t  tag = 1;
    tlv_element_t  element = {tlv_tag(&tag, 1), {nullptr, UINT64_MAX >> 1}};
    tlv_encoding_t sizes{};
    // Measurement need not access a logical Value that exceeds address space.
    EXPECT_EQ(TLV_OK, tlv_packed_measure(&config, &element, &sizes, &error));
    EXPECT_EQ((UINT64_MAX >> 1) + 8, sizes.total);
    ++element.value.size;
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_packed_measure(&config, &element, &sizes, &error));
}

TEST(Unit_Tlv_Packed, RequiredPointersAndFailedOutputs) {
    auto           config = layout();
    uint8_t        wire[] = {0, 0};
    tlv_decoded_t  decoded{};
    tlv_encoding_t sizes{};
    sizes.total = 99;
    tlv_format_error_t error{};
    const uint8_t      tag = 1;
    tlv_element_t      element = {tlv_tag(&tag, 1), {nullptr, 0}};
    size_t             written = 99;
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_packed_decode(nullptr, wire, 2, &decoded, &error));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_packed_decode(&config, nullptr, 1, &decoded, &error));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_packed_decode(&config, wire, 2, nullptr, &error));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_packed_decode(&config, wire, 2, &decoded, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_packed_measure(nullptr, &element, &sizes, &error));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_packed_measure(&config, nullptr, &sizes, &error));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_packed_measure(&config, &element, nullptr, &error));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_packed_measure(&config, &element, &sizes, nullptr));
    EXPECT_EQ(99u, sizes.total);
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_packed_encode(&config, &element, nullptr, 0, &written, &error));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_packed_encode(&config, &element, wire, 2, nullptr, &error));
    element.value.size = 1;
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_packed_encode(&config, &element, wire, 2, &written, &error));
    EXPECT_EQ(99u, written);
    EXPECT_EQ(0, wire[0]);
    EXPECT_EQ(0, wire[1]);
}
