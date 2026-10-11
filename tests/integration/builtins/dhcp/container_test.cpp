// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "../../../diagnostic_assertions.h"
#include "tlv/builtins/dhcp/container.h"
#include "tlv/builtins/dhcp/dhcpv4.h"
#include "tlv/reader/reader.h"
#include <gtest/gtest.h>

TEST(Integration_Tlv_DhcpContainer, SignificantPrefixPreservesPadAndEnd) {
    const uint8_t           wire[] = {0, 53, 1, 3, 0, 255, 0, 0};
    size_t                  significant = 999;
    tlv_schema_diagnostic_t diagnostic{};
    ASSERT_EQ(TLV_OK, tlv_dhcpv4_options_validate(wire, sizeof(wire), nullptr, 4, &significant,
                                                  &diagnostic));
    EXPECT_EQ(6u, significant);
    EXPECT_EQ(TLV_OK, diagnostic.diagnostic.code);
    EXPECT_FALSE(diagnostic.diagnostic.location.kind);
    tlv_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, wire, significant, &tlv_format_dhcpv4));
    for (uint8_t code : {0, 53, 0, 255}) {
        tlv_element_t element;
        ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
        EXPECT_EQ(code, element.tag.data[0]);
    }
    EXPECT_TRUE(tlv_reader_at_end(&reader));
}

TEST(Integration_Tlv_DhcpContainer, ValuesUnknownCodesAndRepeatedOptionsAreOpaque) {
    const uint8_t wire[] = {254, 2, 0, 255, 254, 0, 255};
    size_t        significant = 0;
    ASSERT_EQ(TLV_OK,
              tlv_dhcpv4_options_validate(wire, sizeof(wire), nullptr, 3, &significant, nullptr));
    EXPECT_EQ(sizeof(wire), significant);
}

TEST(Integration_Tlv_DhcpContainer, TailPoliciesStopAtFirstEnd) {
    const uint8_t           wire[] = {0, 255, 0, 255, 53};
    size_t                  significant = 999;
    tlv_schema_diagnostic_t diagnostic{};
    EXPECT_EQ(TLV_ERR_SCHEMA, TLV_DIAGNOSTIC_RESULT(diagnostic, tlv_dhcpv4_options_validate(
                                                                    wire, sizeof(wire), nullptr, 2,
                                                                    &significant, &diagnostic)));
    EXPECT_EQ(3u, diagnostic.diagnostic.location.begin);
    EXPECT_EQ(999u, significant);
    tlv_dhcpv4_options_rules_t rules{1, TLV_DHCPV4_OPTIONS_TAIL_EMPTY};
    EXPECT_EQ(TLV_ERR_SCHEMA, TLV_DIAGNOSTIC_RESULT(diagnostic, tlv_dhcpv4_options_validate(
                                                                    wire, sizeof(wire), &rules, 2,
                                                                    &significant, &diagnostic)));
    EXPECT_EQ(2u, diagnostic.diagnostic.location.begin);
    EXPECT_EQ(TLV_OK, tlv_dhcpv4_options_validate(wire, 2, &rules, 2, &significant, nullptr));
    rules.tail = TLV_DHCPV4_OPTIONS_TAIL_IGNORE;
    EXPECT_EQ(TLV_OK, tlv_dhcpv4_options_validate(wire, sizeof(wire), &rules, 2, &significant,
                                                  &diagnostic));
    EXPECT_EQ(2u, significant);
    EXPECT_EQ(TLV_OK, diagnostic.diagnostic.code);
    EXPECT_FALSE(diagnostic.diagnostic.location.kind);
}

TEST(Integration_Tlv_DhcpContainer, MissingAndOptionalEndIncludingEmptyAndAllPad) {
    const uint8_t           wire[] = {0, 0};
    size_t                  significant = 999;
    tlv_schema_diagnostic_t diagnostic{};
    EXPECT_EQ(TLV_ERR_SCHEMA,
              TLV_DIAGNOSTIC_RESULT(
                  diagnostic, tlv_dhcpv4_options_validate(wire, sizeof(wire), nullptr, SIZE_MAX,
                                                          &significant, &diagnostic)));
    EXPECT_EQ(sizeof(wire), diagnostic.diagnostic.location.begin);
    EXPECT_EQ(TLV_SCHEMA_ISSUE_MISSING, diagnostic.detail.kind);
    EXPECT_EQ(TLV_LOCATION_SCOPE_END, diagnostic.diagnostic.location.kind);
    EXPECT_TRUE(diagnostic.diagnostic.location.kind);
    EXPECT_EQ(999u, significant);
    EXPECT_EQ(TLV_ERR_SCHEMA, TLV_DIAGNOSTIC_RESULT(diagnostic, tlv_dhcpv4_options_validate(
                                                                    nullptr, 0, nullptr, 0,
                                                                    &significant, &diagnostic)));
    EXPECT_EQ(0u, diagnostic.diagnostic.location.begin);
    const tlv_dhcpv4_options_rules_t rules{0, TLV_DHCPV4_OPTIONS_TAIL_PAD};
    EXPECT_EQ(TLV_OK,
              tlv_dhcpv4_options_validate(wire, sizeof(wire), &rules, 2, &significant, nullptr));
    EXPECT_EQ(sizeof(wire), significant);
    EXPECT_EQ(TLV_OK, tlv_dhcpv4_options_validate(nullptr, 0, &rules, 0, &significant, nullptr));
    EXPECT_EQ(0u, significant);
}

TEST(Integration_Tlv_DhcpContainer, LimitsIncludePadAndEndButExcludeTail) {
    const uint8_t           wire[] = {0, 53, 1, 3, 0, 255, 0, 0};
    const size_t            offsets[] = {0, 1, 4, 5};
    size_t                  significant = 999;
    tlv_schema_diagnostic_t diagnostic{};
    for (size_t limit = 0; limit < 4; ++limit) {
        EXPECT_EQ(TLV_ERR_LIMIT,
                  TLV_DIAGNOSTIC_RESULT(
                      diagnostic, tlv_dhcpv4_options_validate(wire, sizeof(wire), nullptr, limit,
                                                              &significant, &diagnostic)));
        EXPECT_EQ(offsets[limit], diagnostic.diagnostic.location.begin);
        EXPECT_EQ(999u, significant);
    }
    EXPECT_EQ(TLV_OK,
              tlv_dhcpv4_options_validate(wire, sizeof(wire), nullptr, 4, &significant, nullptr));
}

TEST(Integration_Tlv_DhcpContainer, TruncationPreservesReaderFieldOffsets) {
    const uint8_t wire[] = {0, 42, 0, 53, 2, 255};
    for (size_t size : {4u, 5u, 6u}) {
        tlv_reader_t            reader;
        tlv_element_t           element;
        tlv_reader_diagnostic_t expected{};
        ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, wire, size, &tlv_format_dhcpv4));
        ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
        ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
        ASSERT_EQ(
            TLV_ERR_TRUNCATED,
            TLV_DIAGNOSTIC_RESULT(expected, tlv_reader_next_diag(&reader, &element, &expected)));
        size_t                  significant = 999;
        tlv_schema_diagnostic_t diagnostic{};
        EXPECT_EQ(TLV_ERR_TRUNCATED,
                  TLV_DIAGNOSTIC_RESULT(diagnostic,
                                        tlv_dhcpv4_options_validate(wire, size, nullptr, SIZE_MAX,
                                                                    &significant, &diagnostic)));
        EXPECT_TRUE(diagnostic.diagnostic.location.kind);
        EXPECT_EQ(expected.diagnostic.location.begin, diagnostic.diagnostic.location.begin);
        EXPECT_EQ(TLV_ERR_TRUNCATED, diagnostic.diagnostic.code);
        EXPECT_EQ(999u, significant);
        EXPECT_EQ(TLV_ERR_TRUNCATED, tlv_dhcpv4_options_validate(wire, size, nullptr, SIZE_MAX,
                                                                 &significant, nullptr));
    }
}

TEST(Integration_Tlv_DhcpContainer, InvalidArgumentsPreserveOutput) {
    size_t                  significant = 999;
    tlv_schema_diagnostic_t diagnostic{};
    EXPECT_EQ(TLV_ERR_NULL_ARG, TLV_DIAGNOSTIC_RESULT(diagnostic, tlv_dhcpv4_options_validate(
                                                                      nullptr, 1, nullptr, SIZE_MAX,
                                                                      &significant, &diagnostic)));
    EXPECT_EQ(0u, diagnostic.diagnostic.location.begin);
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              tlv_dhcpv4_options_validate(nullptr, 0, nullptr, SIZE_MAX, nullptr, nullptr));
    const tlv_dhcpv4_options_rules_t rules{1, static_cast<tlv_dhcpv4_options_tail_t>(99)};
    EXPECT_EQ(
        TLV_ERR_INVALID_ARG,
        TLV_DIAGNOSTIC_RESULT(diagnostic, tlv_dhcpv4_options_validate(nullptr, 0, &rules, SIZE_MAX,
                                                                      &significant, &diagnostic)));
    EXPECT_EQ(0u, diagnostic.diagnostic.location.begin);
    EXPECT_EQ(999u, significant);
}
