// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/builtins/bluetooth/company_ids.h"
#include <gtest/gtest.h>

TEST(Unit_Tlv_BluetoothCompanyIds, IndependentDefinitionsAndByteIdentity) {
    const uint8_t keys[][2] = {{0x00, 0x00}, {0x06, 0x00}, {0x4C, 0x00},
                               {0x59, 0x00}, {0x75, 0x00}, {0xE0, 0x00}};
    const char*   names[] = {"Ericsson AB",
                             "Microsoft",
                             "Apple, Inc.",
                             "Nordic Semiconductor ASA",
                             "Samsung Electronics Co. Ltd.",
                             "Google"};
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
        const tlv_tag_t key = {keys[i], 2};
        const auto*     definition = tlv_definition_find(&tlv_bluetooth_company_ids, &key);
        ASSERT_NE(nullptr, definition);
        EXPECT_STREQ(names[i], definition->name);
        EXPECT_TRUE(tlv_tag_equal(key, definition->tag));
    }
    const uint8_t other[][2] = {{0x00, 0x4C}, {0x34, 0xAB}, {0xFF, 0xFF}};
    for (const auto& bytes : other) {
        const tlv_tag_t key = {bytes, 2};
        EXPECT_EQ(nullptr, tlv_definition_find(&tlv_bluetooth_company_ids, &key));
    }
    const tlv_tag_t short_key = {keys[2], 1};
    EXPECT_EQ(nullptr, tlv_definition_find(&tlv_bluetooth_company_ids, &short_key));
    EXPECT_EQ(nullptr, tlv_definition_find(&tlv_bluetooth_company_ids, nullptr));
}
