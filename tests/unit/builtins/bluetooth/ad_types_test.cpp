// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/builtins/bluetooth/ad_types.h"
#include "tlv/config.h"
#if OPENTLV_BLUETOOTH
#include "tlv/builtins/bluetooth/bluetooth_ltv.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#endif
#include <gtest/gtest.h>
#include <cstring>

TEST(Unit_Tlv_BluetoothAdTypes, ResolvesCanonicalIdentifiersAndOfficialNames) {
    const struct {
        uint8_t     id;
        const char* name;
    } expected[] = {{0x01, "Flags"},
                    {0x02, "Incomplete List of 16-bit Service or Service Class UUIDs"},
                    {0x03, "Complete List of 16-bit Service or Service Class UUIDs"},
                    {0x04, "Incomplete List of 32-bit Service or Service Class UUIDs"},
                    {0x05, "Complete List of 32-bit Service or Service Class UUIDs"},
                    {0x06, "Incomplete List of 128-bit Service or Service Class UUIDs"},
                    {0x07, "Complete List of 128-bit Service or Service Class UUIDs"},
                    {0x08, "Shortened Local Name"},
                    {0x09, "Complete Local Name"},
                    {0x0A, "Tx Power Level"},
                    {0x16, "Service Data - 16-bit UUID"},
                    {0x20, "Service Data - 32-bit UUID"},
                    {0x21, "Service Data - 128-bit UUID"},
                    {0xFF, "Manufacturer Specific Data"}};
    for (const auto& item : expected) {
        const auto  tag = tlv_tag(&item.id, 1);
        const auto* definition = tlv_definition_find(&tlv_bluetooth_ad_types, &tag);
        ASSERT_NE(nullptr, definition);
        EXPECT_STREQ(item.name, definition->name);
        ASSERT_EQ(1u, definition->tag.size);
        EXPECT_EQ(item.id, definition->tag.data[0]);
    }
    const auto unknown = TLV_TAG(0xFE);
    const auto padded = TLV_TAG(0x00, 0x01);
    EXPECT_EQ(nullptr, tlv_definition_find(&tlv_bluetooth_ad_types, &unknown));
    EXPECT_EQ(nullptr, tlv_definition_find(&tlv_bluetooth_ad_types, &padded));
}

#if OPENTLV_BLUETOOTH
TEST(Unit_Tlv_BluetoothAdTypes, ReadsAndWritesKnownAndUnknownTypesIndependently) {
    const uint8_t input[] = {0x02, 0x01, 0x06, 0x02, 0xFE, 0x42};
    tlv_reader_t  reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, input, sizeof(input), &tlv_format_bluetooth_ltv));
    uint8_t output[sizeof(input)] = {};
    size_t  offset = 0;
    for (size_t i = 0; i < 2; ++i) {
        tlv_element_t element;
        ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
        const auto* definition = tlv_definition_find(&tlv_bluetooth_ad_types, &element.tag);
        if (i == 0) {
            ASSERT_NE(nullptr, definition);
            EXPECT_STREQ("Flags", definition->name);
        } else {
            EXPECT_EQ(nullptr, definition);
        }
        ASSERT_EQ(1u, element.value.size);
        EXPECT_EQ(input + i * 3 + 2, element.value.data);
        size_t written = 0;
        ASSERT_EQ(TLV_OK,
                  tlv_write(output + offset, sizeof(output) - offset, &tlv_format_bluetooth_ltv,
                            element.tag, element.value.data, 1, &written));
        offset += written;
    }
    EXPECT_TRUE(tlv_reader_at_end(&reader));
    EXPECT_EQ(sizeof(input), offset);
    EXPECT_EQ(0, std::memcmp(input, output, sizeof(input)));
}
#endif
