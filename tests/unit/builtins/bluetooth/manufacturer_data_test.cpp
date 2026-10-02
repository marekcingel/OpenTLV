// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/builtins/bluetooth/manufacturer_data.h"
#include <gtest/gtest.h>
#include <cstring>

namespace {
template <typename T, typename U>
void check(const tlv_codec_t& codec, const U& company_id, const uint8_t* wire, size_t width) {
    for (size_t length = 0; length <= width + 2; ++length) {
        SCOPED_TRACE(length);
        T             value = {};
        unsigned char before[sizeof(value)];
        std::memcpy(before, &value, sizeof(value));
        const auto rc = tlv_codec_decode(&codec, wire, length, &value, sizeof(value));
        if (length < width) {
            EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE, rc);
            EXPECT_EQ(0, std::memcmp(before, &value, sizeof(value)));
            continue;
        }
        ASSERT_EQ(TLV_CODEC_OK, rc);
        EXPECT_EQ(0, std::memcmp(&company_id, &value.company_id, sizeof(company_id)));
        EXPECT_EQ(wire, value.raw.data);
        EXPECT_EQ(length, value.raw.size);
        EXPECT_EQ(wire + width, value.payload.data);
        EXPECT_EQ(length - width, value.payload.size);
        size_t written = 99;
        ASSERT_EQ(TLV_CODEC_OK,
                  tlv_codec_encode(&codec, &value, sizeof(value), nullptr, 0, &written));
        EXPECT_EQ(length, written);
        uint8_t output[19];
        std::memset(output, 0xA5, sizeof(output));
        EXPECT_EQ(TLV_CODEC_ERR_BUFFER_TOO_SHORT,
                  tlv_codec_encode(&codec, &value, sizeof(value), output, length - 1, &written));
        EXPECT_EQ(0u, written);
        for (auto byte : output) EXPECT_EQ(0xA5, byte);
        ASSERT_EQ(TLV_CODEC_OK,
                  tlv_codec_encode(&codec, &value, sizeof(value), output, length, &written));
        EXPECT_EQ(length, written);
        EXPECT_EQ(0, std::memcmp(wire, output, length));
        EXPECT_EQ(0xA5, output[length]);
    }
    T value = {};
    EXPECT_EQ(TLV_CODEC_ERR_NULL_ARG,
              tlv_codec_decode(&codec, nullptr, width, &value, sizeof(value)));
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_decode(&codec, nullptr, 0, &value, sizeof(value)));
    EXPECT_EQ(TLV_CODEC_ERR_NULL_ARG,
              tlv_codec_decode(&codec, wire, width, nullptr, sizeof(value)));
    EXPECT_EQ(TLV_CODEC_ERR_BUFFER_TOO_SHORT,
              tlv_codec_decode(&codec, wire, width, &value, sizeof(value) - 1));
    size_t written = 99;
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_encode(&codec, &value, sizeof(value) - 1, nullptr, 0, &written));
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_encode(&codec, &value, sizeof(value) + 1, nullptr, 0, &written));
    EXPECT_EQ(TLV_CODEC_ERR_NULL_ARG,
              tlv_codec_encode(&codec, nullptr, sizeof(value), nullptr, 0, &written));
    value.payload = {nullptr, 1};
    EXPECT_EQ(TLV_CODEC_ERR_NULL_ARG,
              tlv_codec_encode(&codec, &value, sizeof(value), nullptr, 0, &written));
    value.payload = {wire, UINT64_MAX};
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_encode(&codec, &value, sizeof(value), nullptr, 0, &written));
    EXPECT_EQ(0u, written);
    value.payload = {wire, SIZE_MAX};
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_encode(&codec, &value, sizeof(value), nullptr, 0, &written));
    EXPECT_EQ(0u, written);
    // Encoding a fresh object needs no original raw view.
    value.company_id = company_id;
    value.payload = {nullptr, 0};
    uint8_t output[18] = {};
    ASSERT_EQ(TLV_CODEC_OK,
              tlv_codec_encode(&codec, &value, sizeof(value), output, width, &written));
    EXPECT_EQ(width, written);
    EXPECT_EQ(0, std::memcmp(wire, output, width));
    // Editing a decoded object regenerates bytes from Company Identifier and payload.
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_decode(&codec, wire, width + 2, &value, sizeof(value)));
    value.company_id = {};
    const uint8_t replacement[] = {0xDE, 0xAD};
    value.payload = {replacement, sizeof(replacement)};
    ASSERT_EQ(TLV_CODEC_OK,
              tlv_codec_encode(&codec, &value, sizeof(value), output, sizeof(output), &written));
    for (size_t i = 0; i < width; ++i) EXPECT_EQ(0, output[i]);
    EXPECT_EQ(0xDE, output[width]);
    EXPECT_EQ(0xAD, output[width + 1]);
    EXPECT_EQ(wire, value.raw.data);
}
} // namespace

TEST(Unit_Tlv_BluetoothManufacturerData, ContractsAndOpaquePayload) {
    const uint8_t wire[] = {0x4C, 0x00, 0x02, 0x15};
    check<tlv_bluetooth_manufacturer_data_t>(tlv_bluetooth_codec_manufacturer_data,
                                             uint16_t(0x004C), wire, 2);
}

TEST(Unit_Tlv_BluetoothManufacturerData, UnknownAndBoundaryIdentifiersRemainValid) {
    const uint8_t values[][4] = {
        {0x00, 0x00, 0xFF, 0x00}, {0x34, 0xAB, 0xFF, 0x00}, {0xFF, 0xFF, 0xFF, 0x00}};
    const uint16_t ids[] = {0x0000, 0xAB34, 0xFFFF};
    for (size_t i = 0; i < 3; ++i)
        check<tlv_bluetooth_manufacturer_data_t>(tlv_bluetooth_codec_manufacturer_data, ids[i],
                                                 values[i], 2);
}

TEST(Unit_Tlv_BluetoothManufacturerData, ValueCodecHasNoAdFramingLimit) {
    uint8_t                           wire[300] = {0x4C, 0x00};
    tlv_bluetooth_manufacturer_data_t value = {};
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_decode(&tlv_bluetooth_codec_manufacturer_data, wire,
                                             sizeof(wire), &value, sizeof(value)));
    EXPECT_EQ(298u, value.payload.size);
    uint8_t output[300] = {};
    size_t  written = 0;
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_encode(&tlv_bluetooth_codec_manufacturer_data, &value,
                                             sizeof(value), output, sizeof(output), &written));
    EXPECT_EQ(sizeof(wire), written);
    EXPECT_EQ(0, std::memcmp(wire, output, sizeof(wire)));
}
