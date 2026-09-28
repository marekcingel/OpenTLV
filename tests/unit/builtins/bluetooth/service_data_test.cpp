#include "tlv/builtins/bluetooth/service_data.h"
#include <gtest/gtest.h>
#include <cstring>

namespace {
template <typename T, typename U>
void check(const tlv_codec_t& codec, const U& uuid, const uint8_t* wire, size_t width) {
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
        EXPECT_EQ(0, std::memcmp(&uuid, &value.uuid, sizeof(uuid)));
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
    // Encoding a fresh object needs no original raw view.
    value.uuid = uuid;
    value.payload = {nullptr, 0};
    uint8_t output[18] = {};
    ASSERT_EQ(TLV_CODEC_OK,
              tlv_codec_encode(&codec, &value, sizeof(value), output, width, &written));
    EXPECT_EQ(width, written);
    EXPECT_EQ(0, std::memcmp(wire, output, width));
    // Editing a decoded object regenerates bytes from UUID and payload.
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_decode(&codec, wire, width + 2, &value, sizeof(value)));
    value.uuid = {};
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

TEST(Unit_Tlv_BluetoothServiceData, Uuid16ContractsAndOpaquePayload) {
    const uint8_t wire[] = {0x0F, 0x18, 0x64, 0x01};
    check<tlv_bluetooth_service_data16_t>(tlv_bluetooth_codec_service_data16, uint16_t(0x180F),
                                          wire, 2);
}

TEST(Unit_Tlv_BluetoothServiceData, Uuid32ContractsAndOpaquePayload) {
    const uint8_t wire[] = {0xEF, 0xCD, 0xAB, 0x89, 0x64, 0x01};
    check<tlv_bluetooth_service_data32_t>(tlv_bluetooth_codec_service_data32, uint32_t(0x89ABCDEF),
                                          wire, 4);
}

TEST(Unit_Tlv_BluetoothServiceData, Uuid128ContractsAndOpaquePayload) {
    const uint8_t                 wire[] = {0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77,
                                            0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x64, 0x01};
    const tlv_bluetooth_uuid128_t uuid = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                           0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}};
    check<tlv_bluetooth_service_data128_t>(tlv_bluetooth_codec_service_data128, uuid, wire, 16);
}
