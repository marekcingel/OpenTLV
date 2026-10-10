// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/builtins/nfc/type2.h"
#include "tlv/config.h"
#include <gtest/gtest.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <vector>

TEST(Unit_Tlv_NfcType2, EveryIdentifierLengthBoundaryRangesAndRoundtrip) {
    EXPECT_EQ(1, tlv_config_nfc());
    for (unsigned code = 0; code <= 255; ++code) {
        for (size_t size : {0u, 1u, 254u, 255u, 256u, 65534u}) {
            const bool special = code == 0 || code == 0xFE;
            if (special && size) continue;
            SCOPED_TRACE(code);
            SCOPED_TRACE(size);
            const size_t         header = special ? 1 : size < 255 ? 2 : 4;
            std::vector<uint8_t> wire(header + size, 0xA5);
            wire[0] = static_cast<uint8_t>(code);
            if (!special) {
                wire[1] = size < 255 ? static_cast<uint8_t>(size) : 0xFF;
                if (size >= 255) {
                    wire[2] = static_cast<uint8_t>(size >> 8);
                    wire[3] = static_cast<uint8_t>(size);
                }
            }
            tlv_decoded_t decoded{};
            ASSERT_EQ(TLV_OK, tlv_format_decode(&tlv_format_nfc_type2, wire.data(), wire.size(),
                                                &decoded, nullptr));
            EXPECT_EQ(wire.data(), decoded.element.tag.data);
            EXPECT_EQ(1u, decoded.element.tag.size);
            EXPECT_EQ(wire.data() + header, decoded.element.value.data);
            EXPECT_EQ(size, decoded.element.value.size);
            EXPECT_EQ(wire.size(), decoded.source.size);
            EXPECT_EQ(0u, decoded.source.tag.offset);
            EXPECT_EQ(1u, decoded.source.tag.size);
            EXPECT_EQ(!special, !!decoded.source.length.present);
            if (!special) {
                EXPECT_EQ(1u, decoded.source.length.offset);
                EXPECT_EQ(header - 1, decoded.source.length.size);
            }
            EXPECT_EQ(header, decoded.source.header.size);
            EXPECT_EQ(header, decoded.source.value.offset);
            EXPECT_EQ(size, decoded.source.value.size);
            EXPECT_TRUE(decoded.source.value.present);
            EXPECT_TRUE(decoded.source.trailer.present);
            EXPECT_EQ(wire.size(), decoded.source.trailer.offset);
            EXPECT_EQ(0u, decoded.source.trailer.size);
            tlv_encoding_t measured{};
            ASSERT_EQ(TLV_OK, tlv_format_measure(&tlv_format_nfc_type2, &decoded.element, &measured,
                                                 nullptr));
            EXPECT_EQ(wire.size(), measured.total);
            std::vector<uint8_t> encoded(wire.size() + 1, 0xCC);
            size_t               written = 0;
            ASSERT_EQ(TLV_OK, tlv_format_encode(&tlv_format_nfc_type2, &decoded.element,
                                                encoded.data(), wire.size(), &written, nullptr));
            EXPECT_EQ(wire.size(), written);
            EXPECT_TRUE(std::equal(wire.begin(), wire.end(), encoded.begin()));
            EXPECT_EQ(0xCC, encoded.back());
            std::fill(encoded.begin(), encoded.end(), 0xCC);
            ASSERT_EQ(TLV_OK, tlv_source_preserve(&decoded.source, &decoded.element, encoded.data(),
                                                  wire.size(), &written));
            EXPECT_TRUE(std::equal(wire.begin(), wire.end(), encoded.begin()));
            auto          changed = decoded.element;
            const uint8_t different = static_cast<uint8_t>(code ^ 1);
            changed.tag = tlv_tag(&different, 1);
            EXPECT_EQ(TLV_ERR_INVALID_ARG,
                      tlv_source_preserve(&decoded.source, &changed, encoded.data(), wire.size(),
                                          &written));
        }
    }
}

TEST(Unit_Tlv_NfcType2, InvalidExtendedLengthsAndTruncationDiagnostics) {
    for (const auto wire :
         {std::array<uint8_t, 4>{3, 255, 0, 0}, {3, 255, 0, 254}, {3, 255, 255, 255}}) {
        tlv_decoded_t decoded{};
        decoded.source.size = 777;
        tlv_format_error_t error{};
        EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_format_decode(&tlv_format_nfc_type2, wire.data(),
                                                            wire.size(), &decoded, &error));
        EXPECT_EQ(777u, decoded.source.size);
        EXPECT_EQ(TLV_REGION_LENGTH, error.region);
        EXPECT_EQ(1u, error.offset);
        EXPECT_EQ(3u, error.length.size);
    }
    std::vector<uint8_t> wire(259, 0xA5);
    wire[0] = 3;
    wire[1] = 255;
    wire[2] = 0;
    wire[3] = 255;
    for (size_t available = 0; available < wire.size(); ++available) {
        tlv_decoded_t decoded{};
        decoded.source.size = 777;
        tlv_format_error_t error{};
        EXPECT_EQ(
            available ? TLV_ERR_TRUNCATED : TLV_END,
            tlv_format_decode(&tlv_format_nfc_type2, wire.data(), available, &decoded, &error));
        EXPECT_EQ(777u, decoded.source.size);
        if (available) {
            EXPECT_EQ(available < 4 ? TLV_REGION_LENGTH : TLV_REGION_VALUE, error.region);
            EXPECT_EQ(available < 4 ? 1u : 4u, error.offset);
        }
    }
}

TEST(Unit_Tlv_NfcType2, RejectsUnrepresentableElementsAndInsufficientCapacityBeforeWriting) {
    const uint8_t  bytes[] = {3, 0};
    tlv_element_t  element{tlv_tag(bytes, 1), {nullptr, 65534}};
    tlv_encoding_t measured{};
    ASSERT_EQ(TLV_OK, tlv_format_measure(&tlv_format_nfc_type2, &element, &measured, nullptr));
    EXPECT_EQ(65538u, measured.total);
    element.value.size = 65535;
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
              tlv_format_measure(&tlv_format_nfc_type2, &element, &measured, nullptr));
    element.value = {bytes, 1};
    for (uint8_t code : {uint8_t(0), uint8_t(0xFE)}) {
        element.tag = tlv_tag(&code, 1);
        uint8_t output[8];
        std::memset(output, 0xCC, sizeof(output));
        size_t written = 99;
        EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_format_encode(&tlv_format_nfc_type2, &element, output,
                                                            sizeof(output), &written, nullptr));
        EXPECT_EQ(99u, written);
        EXPECT_EQ(0xCC, output[0]);
    }
    element.tag = tlv_tag(bytes, 2);
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE,
              tlv_format_measure(&tlv_format_nfc_type2, &element, &measured, nullptr));
    element.tag = tlv_tag(bytes, 1);
    uint8_t output[2] = {0xCC, 0xCC};
    size_t  written = 99;
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_format_encode(&tlv_format_nfc_type2, &element, output,
                                                          sizeof(output), &written, nullptr));
    EXPECT_EQ(3u, written);
    EXPECT_EQ(0xCC, output[0]);
    EXPECT_EQ(0xCC, output[1]);
}
