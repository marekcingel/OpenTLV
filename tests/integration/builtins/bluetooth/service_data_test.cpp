// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/builtins/bluetooth/service_data.h"
#include "tlv/config.h"
#include <gtest/gtest.h>

#if OPENTLV_BLUETOOTH
#include "tlv/builtins/bluetooth/bluetooth_ltv.h"
#include "tlv/reader/reader.h"
#include <cstring>

namespace {
template <typename T> void check(uint8_t type, size_t width, const tlv_codec_t& codec) {
    uint8_t wire[20] = {};
    wire[0] = static_cast<uint8_t>(width + 3);
    wire[1] = type;
    wire[2] = 0x0F;
    wire[3] = 0x18;
    wire[width + 2] = 0x64;
    wire[width + 3] = 0x01;
    tlv_element_t element = {};
    size_t        consumed = 0, native = 0;
    ASSERT_EQ(TLV_OK, tlv_read(wire, width + 4, &tlv_format_bluetooth_ltv, &element, &consumed));
    EXPECT_EQ(width + 4, consumed);
    EXPECT_EQ(type, element.tag.data[0]);
    ASSERT_EQ(TLV_OK, tlv_size_to_native(element.value.size, &native));
    T value = {};
    ASSERT_EQ(TLV_CODEC_OK,
              tlv_codec_decode(&codec, element.value.data, native, &value, sizeof(value)));
    EXPECT_EQ(element.value.data, value.raw.data);
    EXPECT_EQ(element.value.size, value.raw.size);
    EXPECT_EQ(wire + width + 2, value.payload.data);
    ASSERT_EQ(2u, value.payload.size);
    EXPECT_EQ(0x64, value.payload.data[0]);
    EXPECT_EQ(0x01, value.payload.data[1]);
    uint8_t output[18] = {};
    size_t  written = 0;
    ASSERT_EQ(TLV_CODEC_OK,
              tlv_codec_encode(&codec, &value, sizeof(value), output, sizeof(output), &written));
    EXPECT_EQ(native, written);
    EXPECT_EQ(0, std::memcmp(wire + 2, output, written));
    // Framing accepts a value with an incomplete UUID; codec validation is separate.
    wire[0] = static_cast<uint8_t>(width);
    ASSERT_EQ(TLV_OK, tlv_read(wire, width + 1, &tlv_format_bluetooth_ltv, &element, &consumed));
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_decode(&codec, element.value.data, width - 1, &value, sizeof(value)));
    EXPECT_EQ(wire + 2, element.value.data);
    EXPECT_EQ(width - 1, element.value.size);
}
} // namespace

TEST(Integration_Tlv_BluetoothServiceData, Story348AndAllServiceDataAdTypes) {
    check<tlv_bluetooth_service_data16_t>(0x16, 2, tlv_bluetooth_codec_service_data16);
    check<tlv_bluetooth_service_data32_t>(0x20, 4, tlv_bluetooth_codec_service_data32);
    check<tlv_bluetooth_service_data128_t>(0x21, 16, tlv_bluetooth_codec_service_data128);
}
#endif
