// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/builtins/bluetooth/ad_schema.h"
#include "tlv/config.h"
#include <gtest/gtest.h>

TEST(Unit_Tlv_BluetoothAdSchema, AvailableWithoutFormatOrRegistry) {
    EXPECT_EQ(14u, tlv_bluetooth_ad_schema.count);
    EXPECT_EQ(4u, tlv_bluetooth_ad_schema.group_count);
    EXPECT_NE(0, tlv_bluetooth_ad_schema.allow_unknown);
    EXPECT_EQ(TLV_SCHEMA_ORDER_ANY, tlv_bluetooth_ad_schema.order);
}

#if OPENTLV_BLUETOOTH
#include "tlv/builtins/bluetooth/bluetooth_ltv.h"
#include "tlv/reader/reader.h"
#include <vector>

namespace {
using Wire = std::vector<uint8_t>;

Wire element(uint8_t tag, size_t length) {
    Wire wire(length + 2, 0xA5);
    wire[0] = static_cast<uint8_t>(length + 1);
    wire[1] = tag;
    return wire;
}

tlv_result_t validate(const Wire& wire, size_t* offset = nullptr) {
    tlv_schema_diagnostic_t diagnostic{};
    const auto rc = tlv_schema_validate(wire.data(), wire.size(), &tlv_format_bluetooth_ltv,
                                        &tlv_bluetooth_ad_schema, 1, 64, &diagnostic);
    if (offset) *offset = diagnostic.diagnostic.location.begin;
    return rc;
}

void append(Wire& wire, const Wire& suffix) {
    wire.insert(wire.end(), suffix.begin(), suffix.end());
}
} // namespace

TEST(Unit_Tlv_BluetoothAdSchema, ValueLengthsAreIndependentOfFraming) {
    struct Case {
        uint8_t tag;
        size_t  min;
        size_t  max;
        size_t  width;
    };
    const Case cases[] = {
        {0x01, 0, 254, 1},  {0x08, 0, 248, 1},  {0x09, 0, 248, 1}, {0x0A, 1, 1, 1},
        {0x02, 0, 254, 2},  {0x03, 0, 254, 2},  {0x04, 0, 254, 4}, {0x05, 0, 254, 4},
        {0x06, 0, 254, 16}, {0x07, 0, 254, 16}, {0x16, 2, 254, 1}, {0x20, 4, 254, 1},
        {0x21, 16, 254, 1}, {0xFF, 2, 254, 1},  {0xFE, 0, 254, 1},
    };
    for (const auto& test : cases) {
        for (size_t length = 0; length <= 254; ++length) {
            SCOPED_TRACE(::testing::Message()
                         << "tag=" << unsigned(test.tag) << " length=" << length);
            const Wire    wire = element(test.tag, length);
            tlv_element_t parsed = {};
            size_t        used = 0;
            ASSERT_EQ(TLV_OK, tlv_read(wire.data(), wire.size(), &tlv_format_bluetooth_ltv, &parsed,
                                       &used));
            EXPECT_EQ(wire.size(), used);
            const bool valid = length >= test.min && length <= test.max && length % test.width == 0;
            EXPECT_EQ(valid ? TLV_OK : TLV_ERR_SCHEMA, validate(wire));
        }
    }
}

TEST(Unit_Tlv_BluetoothAdSchema, OptionalFieldsAndSharedOccurrenceLimits) {
    EXPECT_EQ(TLV_OK, validate({}));
    const uint8_t pairs[][2] = {{0x02, 0x03}, {0x04, 0x05}, {0x06, 0x07}, {0x08, 0x09}};
    for (const auto& pair : pairs) {
        for (uint8_t first : pair) {
            for (uint8_t second : pair) {
                Wire wire = element(first, 0);
                append(wire, element(second, 0));
                EXPECT_EQ(TLV_ERR_SCHEMA, validate(wire));
            }
        }
    }
    EXPECT_EQ(TLV_ERR_SCHEMA, validate({1, 1, 1, 1}));           // Two empty Flags.
    EXPECT_EQ(TLV_OK, validate({1, 3, 1, 5, 1, 7, 1, 9, 1, 1})); // Independent groups.
    const uint8_t repeatable[] = {0x0A, 0x16, 0x20, 0x21, 0xFF, 0xFE};
    for (uint8_t tag : repeatable) {
        Wire       wire = element(tag, tag == 0x0A ? 1 : 16);
        const Wire duplicate = wire;
        append(wire, duplicate); // Repeated types permitted by CSS Table 1.1.
        EXPECT_EQ(TLV_OK, validate(wire));
    }
}

TEST(Unit_Tlv_BluetoothAdSchema, ReportsLengthMultipleAndExactLengthAtElementOffsets) {
    const Wire              wire = {2, 0xFE, 0, 4, 3, 0x0F, 0x18, 0, 3, 0x0A, 0xFC, 0xFD};
    tlv_schema_diagnostic_t offset = {};
    offset.diagnostic.location.begin = SIZE_MAX;
    EXPECT_EQ(TLV_ERR_SCHEMA, validate(wire, &offset.diagnostic.location.begin));
    EXPECT_EQ(3u, offset.diagnostic.location.begin);
    tlv_schema_diagnostic_t        diagnostics[2] = {};
    tlv_schema_diagnostic_report_t detailed = {diagnostics, 2, 0};
    EXPECT_EQ(TLV_ERR_SCHEMA,
              tlv_schema_validate_all_diag(wire.data(), wire.size(), &tlv_format_bluetooth_ltv,
                                           &tlv_bluetooth_ad_schema, 1, 64,
                                           TLV_SCHEMA_UNKNOWN_BY_SCHEMA, &detailed, &offset));
    ASSERT_EQ(2u, detailed.count);
    EXPECT_EQ(TLV_SCHEMA_ISSUE_LENGTH, diagnostics[0].detail.kind);
    EXPECT_EQ(3u, diagnostics[0].diagnostic.location.begin);
    EXPECT_EQ(8u, diagnostics[1].diagnostic.location.begin);
    EXPECT_NE(0, diagnostics[0].detail.has_length);
    EXPECT_EQ(2u, diagnostics[0].detail.length_multiple);
    EXPECT_EQ(3u, diagnostics[0].detail.actual_length);
    EXPECT_EQ(0u, diagnostics[0].detail.min_length);
    EXPECT_EQ(SIZE_MAX, diagnostics[0].detail.max_length);
    EXPECT_EQ(0u, diagnostics[1].detail.length_multiple);
    EXPECT_EQ(1u, diagnostics[1].detail.min_length);
    EXPECT_EQ(1u, diagnostics[1].detail.max_length);
    EXPECT_EQ(2u, diagnostics[1].detail.actual_length);
    EXPECT_STREQ("Tx Power Level", diagnostics[1].detail.field);
    tlv_schema_diagnostic_init(&diagnostics[0]);
    EXPECT_EQ(0u, diagnostics[0].detail.length_multiple);
}

TEST(Unit_Tlv_BluetoothAdSchema, ExamplesPaddingAndTruncation) {
    EXPECT_EQ(TLV_OK, validate({2, 0x0A, 0xFC}));
    EXPECT_EQ(TLV_ERR_SCHEMA, validate({3, 0x0A, 0xFC, 0xFD}));
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, validate({2, 1, 6, 0, 0}));
    EXPECT_EQ(TLV_ERR_TRUNCATED, validate({3, 0x0A, 0xFC}));
    EXPECT_EQ(TLV_OK, validate({1, 0xFE}));
}

TEST(Unit_Tlv_BluetoothAdSchema, ReportsSharedGroupAndSupportsExplicitUnknownPolicy) {
    const Wire                     wire = {1, 8, 1, 9, 1, 0xFE};
    tlv_schema_diagnostic_t        diagnostics[2] = {};
    tlv_schema_diagnostic_report_t report = {diagnostics, 2, 0};
    EXPECT_EQ(TLV_ERR_SCHEMA,
              tlv_schema_validate_all_diag(wire.data(), wire.size(), &tlv_format_bluetooth_ltv,
                                           &tlv_bluetooth_ad_schema, 1, 64,
                                           TLV_SCHEMA_UNKNOWN_BY_SCHEMA, &report, nullptr));
    ASSERT_EQ(1u, report.count);
    EXPECT_EQ(TLV_SCHEMA_ISSUE_DUPLICATE, diagnostics[0].detail.kind);
    EXPECT_NE(0, diagnostics[0].detail.is_group);
    EXPECT_STREQ("Local Name", diagnostics[0].detail.field);
    EXPECT_EQ(2u, diagnostics[0].detail.occurs);
    EXPECT_EQ(1u, diagnostics[0].detail.max_occurs);
    EXPECT_EQ(TLV_ERR_SCHEMA,
              tlv_schema_validate_all_diag(wire.data(), wire.size(), &tlv_format_bluetooth_ltv,
                                           &tlv_bluetooth_ad_schema, 1, 64,
                                           TLV_SCHEMA_UNKNOWN_REJECT, &report, nullptr));
    EXPECT_EQ(2u, report.count);
}
#endif
