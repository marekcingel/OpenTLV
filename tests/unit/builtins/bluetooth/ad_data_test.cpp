// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/builtins/bluetooth/ad_data.h"
#include "tlv/builtins/bluetooth/ad_schema.h"
#include "tlv/builtins/bluetooth/bluetooth_ltv.h"
#include "tlv/reader/reader.h"
#include "tlv/schema/schema.h"
#include <gtest/gtest.h>
#include <vector>

TEST(Unit_Tlv_BluetoothAdData, AcceptsEmptyAndZeroPadding) {
    const uint8_t           zeros[] = {0, 0, 0};
    size_t                  significant = 99;
    tlv_reader_diagnostic_t offset = {};
    offset.diagnostic.location.begin = 99;
    ASSERT_EQ(TLV_OK, tlv_bluetooth_ad_data_validate(nullptr, 0, &significant, &offset));
    EXPECT_EQ(0u, significant);
    EXPECT_EQ(99u, offset.diagnostic.location.begin);
    for (size_t size = 0; size <= sizeof(zeros); ++size) {
        significant = 99;
        ASSERT_EQ(TLV_OK, tlv_bluetooth_ad_data_validate(zeros, size, &significant, nullptr));
        EXPECT_EQ(0u, significant);
    }
}

TEST(Unit_Tlv_BluetoothAdData, ReturnsPrefixForReaderAndSchema) {
    const uint8_t           data[] = {2, 1, 6, 0, 0, 0};
    size_t                  significant = 99;
    tlv_schema_diagnostic_t offset{};
    offset.diagnostic.location.begin = 99;
    tlv_reader_diagnostic_t reader_diagnostic{};
    for (size_t size = 3; size <= sizeof(data); ++size) {
        ASSERT_EQ(TLV_OK,
                  tlv_bluetooth_ad_data_validate(data, size, &significant, &reader_diagnostic));
        EXPECT_EQ(3u, significant);
        EXPECT_EQ(99u, offset.diagnostic.location.begin);
    }
    tlv_reader_t  reader;
    tlv_element_t element;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, significant, &tlv_format_bluetooth_ltv));
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
    EXPECT_EQ(data + 2, element.value.data);
    EXPECT_EQ(TLV_END, tlv_reader_next(&reader, &element));
    EXPECT_EQ(TLV_OK, tlv_schema_validate(data, significant, &tlv_format_bluetooth_ltv,
                                          &tlv_bluetooth_ad_schema, 8, 100, &offset));
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data), &tlv_format_bluetooth_ltv));
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_reader_next(&reader, &element));
    EXPECT_EQ(3u, reader.pos);
}

TEST(Unit_Tlv_BluetoothAdData, PreservesZeroValuesAndUnknownTypesWithoutSchemaChecks) {
    // Unknown type, type-only Flags, and a Tx Power value rejected by its codec.
    const uint8_t data[] = {2, 0xFE, 0, 1, 1, 2, 0x0A, 0x80, 0, 0};
    size_t        significant = 99;
    ASSERT_EQ(TLV_OK, tlv_bluetooth_ad_data_validate(data, sizeof(data), &significant, nullptr));
    EXPECT_EQ(8u, significant);
    std::vector<uint8_t> maximum(258, 0);
    maximum[0] = 255;
    maximum[1] = 0xFE;
    ASSERT_EQ(TLV_OK, tlv_bluetooth_ad_data_validate(maximum.data(), maximum.size(), &significant,
                                                     nullptr));
    EXPECT_EQ(256u, significant);
}

TEST(Unit_Tlv_BluetoothAdData, RejectsNonzeroPaddingAtOriginalOffset) {
    const uint8_t           data[] = {2, 1, 6, 0, 0, 1, 0xFE};
    size_t                  significant = 99;
    tlv_reader_diagnostic_t offset = {};
    offset.diagnostic.location.begin = 99;
    EXPECT_EQ(TLV_ERR_INVALID_VALUE,
              tlv_bluetooth_ad_data_validate(data, sizeof(data), &significant, &offset));
    EXPECT_EQ(99u, significant);
    EXPECT_EQ(5u, offset.diagnostic.location.begin);
    EXPECT_EQ(TLV_ERR_INVALID_VALUE,
              tlv_bluetooth_ad_data_validate(data, sizeof(data), &significant, nullptr));
    const uint8_t leading[] = {0, 1};
    EXPECT_EQ(TLV_ERR_INVALID_VALUE,
              tlv_bluetooth_ad_data_validate(leading, sizeof(leading), &significant, &offset));
    EXPECT_EQ(1u, offset.diagnostic.location.begin);
}

TEST(Unit_Tlv_BluetoothAdData, PropagatesTruncationAndFieldOffsets) {
    // Zeros in an incomplete declared value must not turn into padding.
    const uint8_t data[] = {2, 1, 6, 4, 9, 0, 0};
    for (size_t size = 4; size <= sizeof(data); ++size) {
        size_t                  significant = 99;
        tlv_reader_diagnostic_t offset = {};
        offset.diagnostic.location.begin = 99;
        EXPECT_EQ(TLV_ERR_TRUNCATED,
                  tlv_bluetooth_ad_data_validate(data, size, &significant, &offset));
        EXPECT_EQ(99u, significant);
        EXPECT_EQ(size == 4 ? 4u : 5u, offset.diagnostic.location.begin);
        EXPECT_EQ(TLV_ERR_TRUNCATED,
                  tlv_bluetooth_ad_data_validate(data, size, &significant, nullptr));
    }
}

TEST(Unit_Tlv_BluetoothAdData, RejectsMissingArgumentsWithoutChangingSize) {
    size_t                  significant = 99;
    tlv_reader_diagnostic_t offset = {};
    offset.diagnostic.location.begin = 99;
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_bluetooth_ad_data_validate(nullptr, 1, &significant, &offset));
    EXPECT_EQ(99u, significant);
    EXPECT_EQ(0u, offset.diagnostic.location.begin);
    offset.diagnostic.location.begin = 99;
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_bluetooth_ad_data_validate(nullptr, 0, nullptr, &offset));
    EXPECT_EQ(0u, offset.diagnostic.location.begin);
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_bluetooth_ad_data_validate(nullptr, 1, &significant, nullptr));
}
