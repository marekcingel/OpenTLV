// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/builtins/bluetooth/uuid.h"
#include "tlv/config.h"
#include <gtest/gtest.h>

#if OPENTLV_BLUETOOTH
#include "tlv/builtins/bluetooth/bluetooth_ltv.h"
#include "tlv/reader/reader.h"
#include <cstring>

TEST(Integration_Tlv_BluetoothUuid, Story347AndAllListAdTypesPreserveRawValues) {
    const tlv_codec_t* codecs[] = {&tlv_bluetooth_codec_uuid16_list,
                                   &tlv_bluetooth_codec_uuid32_list,
                                   &tlv_bluetooth_codec_uuid128_list};
    const size_t       widths[] = {2, 4, 16};
    for (uint8_t type = 2; type <= 7; ++type) {
        const size_t kind = (type - 2) / 2;
        const size_t length = widths[kind] * 2;
        uint8_t      wire[34] = {static_cast<uint8_t>(length + 1), type, 0x0F, 0x18, 0x0A, 0x18};
        uint8_t      original[34];
        std::memcpy(original, wire, sizeof(wire));
        tlv_element_t element = {};
        size_t        consumed = 0, native = 0;
        ASSERT_EQ(TLV_OK,
                  tlv_read(wire, length + 2, &tlv_format_bluetooth_ltv, &element, &consumed));
        ASSERT_EQ(TLV_OK, tlv_size_to_native(element.value.size, &native));
        EXPECT_EQ(length + 2, consumed);
        EXPECT_EQ(type, element.tag.data[0]);
        tlv_bluetooth_uuid_list_t list = {};
        ASSERT_EQ(TLV_OK, tlv_codec_decode(codecs[kind], element.value.data, native, &list,
                                           sizeof(list), NULL));
        EXPECT_EQ(wire + 2, list.raw.data);
        EXPECT_EQ(element.value.data, list.raw.data);
        EXPECT_EQ(element.value.size, list.raw.size);
        EXPECT_EQ(2u, list.raw.size / list.uuid_size);
        if (kind == 0) {
            uint16_t uuid = 0;
            ASSERT_EQ(TLV_OK, tlv_bluetooth_uuid_list_at(&list, 0, &uuid, sizeof(uuid)));
            EXPECT_EQ(0x180F, uuid);
            ASSERT_EQ(TLV_OK, tlv_bluetooth_uuid_list_at(&list, 1, &uuid, sizeof(uuid)));
            EXPECT_EQ(0x180A, uuid);
        }
        EXPECT_EQ(0, std::memcmp(original, wire, sizeof(wire)));
    }
}

TEST(Integration_Tlv_BluetoothUuid, MalformedListRemainsAvailableAsRawValue) {
    const uint8_t wire[] = {4, 3, 0x0F, 0x18, 0x0A};
    tlv_element_t element = {};
    size_t        consumed = 0;
    ASSERT_EQ(TLV_OK, tlv_read(wire, sizeof(wire), &tlv_format_bluetooth_ltv, &element, &consumed));
    tlv_bluetooth_uuid_list_t list = {};
    EXPECT_EQ(TLV_ERR_INVALID_VALUE,
              tlv_codec_decode(&tlv_bluetooth_codec_uuid16_list, element.value.data, 3, &list,
                               sizeof(list), NULL));
    EXPECT_EQ(wire + 2, element.value.data);
    EXPECT_EQ(3u, element.value.size);
}
#endif
