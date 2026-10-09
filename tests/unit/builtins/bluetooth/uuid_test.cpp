// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/builtins/bluetooth/uuid.h"
#include <gtest/gtest.h>
#include <cstring>

namespace {
template <typename T>
void scalar(const tlv_codec_t& codec, const T& expected, const uint8_t* wire, size_t width) {
    T value = {};
    ASSERT_EQ(TLV_OK, tlv_codec_decode(&codec, wire, width, &value, sizeof(value), NULL));
    EXPECT_EQ(0, std::memcmp(&expected, &value, sizeof(value)));
    uint8_t output[17] = {};
    output[width] = 0xA5;
    size_t written = 99;
    ASSERT_EQ(TLV_OK,
              tlv_codec_encode(&codec, &expected, sizeof(expected), nullptr, 0, &written, NULL));
    EXPECT_EQ(width, written);
    ASSERT_EQ(TLV_OK,
              tlv_codec_encode(&codec, &expected, sizeof(expected), output, width, &written, NULL));
    EXPECT_EQ(width, written);
    EXPECT_EQ(0, std::memcmp(wire, output, width));
    EXPECT_EQ(0xA5, output[width]);
    for (size_t size = 0; size <= 17; ++size) {
        if (size == width) continue;
        EXPECT_EQ(TLV_ERR_INVALID_VALUE,
                  tlv_codec_decode(&codec, output, size, &value, sizeof(value), NULL));
    }
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              tlv_codec_decode(&codec, wire, width, &value, sizeof(value) - 1, NULL));
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              tlv_codec_decode(&codec, nullptr, width, &value, sizeof(value), NULL));
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              tlv_codec_decode(&codec, wire, width, nullptr, sizeof(value), NULL));
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_codec_encode(&codec, &expected, sizeof(expected),
                                                         output, width - 1, &written, NULL));
    EXPECT_EQ(0u, written);
    EXPECT_EQ(TLV_ERR_INVALID_VALUE, tlv_codec_encode(&codec, &expected, sizeof(expected) - 1,
                                                      nullptr, 0, &written, NULL));
    EXPECT_EQ(0u, written);
    EXPECT_EQ(TLV_ERR_INVALID_VALUE, tlv_codec_encode(&codec, &expected, sizeof(expected) + 1,
                                                      nullptr, 0, &written, NULL));
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              tlv_codec_encode(&codec, nullptr, sizeof(expected), nullptr, 0, &written, NULL));
}
const tlv_codec_t* const lists[] = {&tlv_bluetooth_codec_uuid16_list,
                                    &tlv_bluetooth_codec_uuid32_list,
                                    &tlv_bluetooth_codec_uuid128_list};
const size_t             widths[] = {2, 4, 16};
} // namespace

TEST(Unit_Tlv_BluetoothUuid, ScalarWireOrderAndContracts) {
    const uint8_t short_wire[] = {0x0F, 0x18};
    scalar(tlv_bluetooth_codec_uuid16, uint16_t(0x180F), short_wire, 2);
    const uint8_t long_wire[] = {0xEF, 0xCD, 0xAB, 0x89};
    scalar(tlv_bluetooth_codec_uuid32, uint32_t(0x89ABCDEF), long_wire, 4);
    // 00112233-4455-6677-8899-aabbccddeeff: reverse the WHOLE UUID.
    const uint8_t                 full_wire[] = {0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
                                                 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00};
    const tlv_bluetooth_uuid128_t full = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                           0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}};
    scalar(tlv_bluetooth_codec_uuid128, full, full_wire, 16);
    for (uint8_t fill : {uint8_t(0), uint8_t(0xFF)}) {
        uint8_t bytes[16];
        std::memset(bytes, fill, sizeof(bytes));
        scalar(tlv_bluetooth_codec_uuid16, uint16_t(fill ? UINT16_MAX : 0), bytes, 2);
        scalar(tlv_bluetooth_codec_uuid32, uint32_t(fill ? UINT32_MAX : 0), bytes, 4);
        tlv_bluetooth_uuid128_t uuid;
        std::memcpy(uuid.bytes, bytes, 16);
        scalar(tlv_bluetooth_codec_uuid128, uuid, bytes, 16);
    }
}

TEST(Unit_Tlv_BluetoothUuid, ListsValidateLengthsBorrowAndRoundTrip) {
    uint8_t wire[49];
    for (size_t i = 0; i < sizeof(wire); ++i) wire[i] = static_cast<uint8_t>(i + 1);
    for (size_t kind = 0; kind < 3; ++kind) {
        const size_t width = widths[kind];
        for (size_t length = 0; length <= sizeof(wire); ++length) {
            SCOPED_TRACE(length);
            tlv_bluetooth_uuid_list_t view = {};
            const auto                expected = length % width ? TLV_ERR_INVALID_VALUE : TLV_OK;
            ASSERT_EQ(expected,
                      tlv_codec_decode(lists[kind], wire, length, &view, sizeof(view), NULL));
            const tlv_bluetooth_uuid_list_t input = {{wire, length}, width};
            size_t                          written = 99;
            EXPECT_EQ(expected, tlv_codec_encode(lists[kind], &input, sizeof(input), nullptr, 0,
                                                 &written, NULL));
            EXPECT_EQ(expected == TLV_OK ? length : 0u, written);
            uint8_t output[50] = {};
            output[length] = 0xA5;
            EXPECT_EQ(expected, tlv_codec_encode(lists[kind], &input, sizeof(input), output, length,
                                                 &written, NULL));
            EXPECT_EQ(0xA5, output[length]);
            if (expected != TLV_OK) continue;
            EXPECT_EQ(wire, view.raw.data);
            EXPECT_EQ(length, view.raw.size);
            EXPECT_EQ(width, view.uuid_size);
            EXPECT_EQ(0, std::memcmp(wire, output, length));
            for (size_t index = 0; index < length / width; ++index) {
                const uint8_t* entry = wire + index * width;
                if (width == 2) {
                    uint16_t uuid = 0;
                    ASSERT_EQ(TLV_OK,
                              tlv_bluetooth_uuid_list_at(&view, index, &uuid, sizeof(uuid)));
                    EXPECT_EQ(uint16_t(entry[0] | uint16_t(entry[1]) << 8), uuid);
                } else if (width == 4) {
                    uint32_t uuid = 0;
                    ASSERT_EQ(TLV_OK,
                              tlv_bluetooth_uuid_list_at(&view, index, &uuid, sizeof(uuid)));
                    EXPECT_EQ(uint32_t(entry[0]) | uint32_t(entry[1]) << 8 |
                                  uint32_t(entry[2]) << 16 | uint32_t(entry[3]) << 24,
                              uuid);
                } else {
                    tlv_bluetooth_uuid128_t uuid = {};
                    ASSERT_EQ(TLV_OK,
                              tlv_bluetooth_uuid_list_at(&view, index, &uuid, sizeof(uuid)));
                    for (size_t j = 0; j < 16; ++j) EXPECT_EQ(entry[15 - j], uuid.bytes[j]);
                }
            }
            uint32_t sentinel = 0x12345678;
            EXPECT_EQ(
                TLV_ERR_INVALID_VALUE,
                tlv_bluetooth_uuid_list_at(&view, length / width, &sentinel, sizeof(sentinel)));
            EXPECT_EQ(TLV_ERR_INVALID_VALUE,
                      tlv_bluetooth_uuid_list_at(&view, SIZE_MAX, &sentinel, sizeof(sentinel)));
            EXPECT_EQ(0x12345678u, sentinel);
        }
    }
}

TEST(Unit_Tlv_BluetoothUuid, EmptyListsAndInvalidViews) {
    const uint8_t bytes[16] = {};
    for (size_t kind = 0; kind < 3; ++kind) {
        tlv_bluetooth_uuid_list_t view = {};
        size_t                    written = 99;
        uint32_t                  value = 42;
        ASSERT_EQ(TLV_OK, tlv_codec_decode(lists[kind], nullptr, 0, &view, sizeof(view), NULL));
        EXPECT_EQ(nullptr, view.raw.data);
        EXPECT_EQ(TLV_OK,
                  tlv_codec_encode(lists[kind], &view, sizeof(view), nullptr, 0, &written, NULL));
        EXPECT_EQ(0u, written);
        EXPECT_EQ(TLV_ERR_INVALID_VALUE,
                  tlv_bluetooth_uuid_list_at(&view, 0, &value, sizeof(value)));
        EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_codec_decode(lists[kind], bytes, widths[kind],
                                                             &view, sizeof(view) - 1, NULL));
        EXPECT_EQ(TLV_ERR_INVALID_VALUE, tlv_codec_encode(lists[kind], &view, sizeof(view) - 1,
                                                          nullptr, 0, &written, NULL));
        view.raw = {bytes, widths[kind]};
        uint8_t output[16];
        EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
                  tlv_codec_encode(lists[kind], &view, sizeof(view), output, widths[kind] - 1,
                                   &written, NULL));
        EXPECT_EQ(0u, written);
        EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_bluetooth_uuid_list_at(&view, 0, &value, 0));
        EXPECT_EQ(42u, value);
        view.raw.data = nullptr;
        EXPECT_EQ(TLV_ERR_NULL_ARG,
                  tlv_codec_encode(lists[kind], &view, sizeof(view), nullptr, 0, &written, NULL));
        EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_bluetooth_uuid_list_at(&view, 0, &value, sizeof(value)));
        view.raw = {bytes, widths[kind] + 1};
        EXPECT_EQ(TLV_ERR_INVALID_VALUE,
                  tlv_bluetooth_uuid_list_at(&view, 0, &value, sizeof(value)));
        view.raw.size = 0;
        view.uuid_size = widths[(kind + 1) % 3];
        EXPECT_EQ(TLV_ERR_INVALID_VALUE,
                  tlv_codec_encode(lists[kind], &view, sizeof(view), nullptr, 0, &written, NULL));
        view.uuid_size = 0;
        EXPECT_EQ(TLV_ERR_INVALID_VALUE,
                  tlv_bluetooth_uuid_list_at(&view, 0, &value, sizeof(value)));
        view.uuid_size = widths[kind];
        EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_bluetooth_uuid_list_at(nullptr, 0, &value, sizeof(value)));
        EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_bluetooth_uuid_list_at(&view, 0, nullptr, 0));
#if SIZE_MAX < UINT64_MAX
        view.raw.size = uint64_t(SIZE_MAX) + 1;
        EXPECT_EQ(TLV_ERR_INVALID_VALUE,
                  tlv_codec_encode(lists[kind], &view, sizeof(view), nullptr, 0, &written, NULL));
        EXPECT_EQ(TLV_ERR_INVALID_VALUE,
                  tlv_bluetooth_uuid_list_at(&view, 0, &value, sizeof(value)));
#endif
    }
}

TEST(Unit_Tlv_BluetoothUuid, ScalarIntegerNamesAreGenericAliases) {
    EXPECT_EQ(&tlv_codec_uint16_le, &tlv_bluetooth_codec_uuid16);
    EXPECT_EQ(&tlv_codec_uint32_le, &tlv_bluetooth_codec_uuid32);
}
