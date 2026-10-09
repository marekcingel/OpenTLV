// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include <gtest/gtest.h>
#include <vector>
#include "tlv/builtins/bluetooth/ad_data.h"
#include "tlv/builtins/bluetooth/ad_types.h"
#include "tlv/builtins/bluetooth/ad_schema.h"
#include "tlv/builtins/bluetooth/bluetooth_ltv.h"
#include "tlv/builtins/bluetooth/uuid.h"
#include "tlv/reader/reader.h"

TEST(Integration_Tlv_BluetoothSemantic, EveryUuidLengthThroughContainerReaderSchemaAndCodec) {
    for (uint8_t type = 2; type <= 7; ++type) {
        const size_t width = type <= 3 ? 2 : type <= 5 ? 4 : 16;
        const auto*  codec = width == 2   ? &tlv_bluetooth_codec_uuid16_list
                             : width == 4 ? &tlv_bluetooth_codec_uuid32_list
                                          : &tlv_bluetooth_codec_uuid128_list;
        for (size_t length = 0; length <= 254; ++length) {
            SCOPED_TRACE(::testing::Message() << "type=" << unsigned(type) << " length=" << length);
            std::vector<uint8_t> wire = {2, 1, 6, static_cast<uint8_t>(length + 1), type};
            wire.insert(wire.end(), length, 0xAA);
            wire.insert(wire.end(), 3, 0);
            const auto original = wire;
            size_t     significant = 0;
            ASSERT_EQ(TLV_OK, tlv_bluetooth_ad_data_validate(wire.data(), wire.size(), &significant,
                                                             nullptr));
            ASSERT_EQ(length + 5, significant);
            tlv_decoded_t decoded{};
            ASSERT_EQ(TLV_OK, tlv_format_decode(&tlv_format_bluetooth_ltv, wire.data() + 3,
                                                significant - 3, &decoded, nullptr));
            EXPECT_EQ(wire.data() + 3, decoded.source.data);
            EXPECT_TRUE(decoded.source.length.present);
            EXPECT_TRUE(decoded.source.tag.present);
            EXPECT_TRUE(decoded.source.value.present);
            EXPECT_EQ(0u, decoded.source.length.offset);
            EXPECT_EQ(1u, decoded.source.tag.offset);
            EXPECT_EQ(2u, decoded.source.value.offset);
            EXPECT_EQ(length, decoded.source.value.size);
            EXPECT_EQ(wire.data() + 4, decoded.element.tag.data);
            EXPECT_EQ(wire.data() + 5, decoded.element.value.data);
            ASSERT_NE(nullptr, tlv_definition_find(&tlv_bluetooth_ad_types, &decoded.element.tag));
            tlv_bluetooth_uuid_list_t list{};
            const auto                rc =
                tlv_codec_decode(codec, decoded.element.value.data, length, &list, sizeof(list));
            EXPECT_EQ(length % width == 0 ? TLV_CODEC_OK : TLV_CODEC_ERR_INVALID_VALUE, rc);
            tlv_schema_diagnostic_t        diagnostic{};
            tlv_schema_diagnostic_report_t report = {&diagnostic, 1, 0};
            const auto                     schema = tlv_schema_validate_all_diag(
                wire.data(), significant, &tlv_format_bluetooth_ltv, &tlv_bluetooth_ad_schema, 0, 2,
                TLV_SCHEMA_UNKNOWN_BY_SCHEMA, &report, nullptr);
            if (length % width == 0) {
                EXPECT_EQ(TLV_OK, schema);
                EXPECT_EQ(0u, report.count);
                EXPECT_EQ(wire.data() + 5, list.raw.data);
                EXPECT_EQ(width, list.uuid_size);
            } else {
                EXPECT_EQ(TLV_ERR_SCHEMA, schema);
                ASSERT_EQ(1u, report.count);
                EXPECT_TRUE(diagnostic.diagnostic.location.kind);
                EXPECT_EQ(3u, diagnostic.diagnostic.location.begin);
                EXPECT_EQ(type, diagnostic.tag.data[0]);
            }
            EXPECT_EQ(original, wire);
        }
    }
}
