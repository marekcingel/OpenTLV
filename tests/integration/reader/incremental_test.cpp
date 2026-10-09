// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "../../diagnostic_assertions.h"
#include "tlv/config.h"
#include "tlv/reader/reader.h"
#include "tlv/formats/fixed.h"
#if OPENTLV_FORMAT_BER
#include "tlv/builtins/asn1/ber.h"
#endif
#if OPENTLV_FORMAT_DER
#include "tlv/builtins/asn1/der.h"
#endif
#if OPENTLV_FORMAT_CER
#include "tlv/builtins/asn1/cer.h"
#endif
#if OPENTLV_BLUETOOTH
#include "tlv/builtins/bluetooth/bluetooth_ltv.h"
#endif
#if OPENTLV_DHCP
#include "tlv/builtins/dhcp/dhcpv4.h"
#endif
#if OPENTLV_LLDP
#include "tlv/builtins/lldp/lldp.h"
#endif
#include <gtest/gtest.h>
#include <vector>

namespace {
void check_splits(const tlv_format_t* format, const std::vector<uint8_t>& wire) {
    tlv_element_t whole{};
    size_t        consumed = 0;
    ASSERT_EQ(TLV_OK, tlv_read(wire.data(), wire.size(), format, &whole, &consumed));
    ASSERT_EQ(wire.size(), consumed);
    for (size_t split = 0; split < wire.size(); ++split) {
        SCOPED_TRACE(split);
        tlv_reader_t reader;
        ASSERT_EQ(TLV_OK, tlv_reader_init_incremental(&reader, wire.data(), split, format));
        tlv_element_t element{};
        ASSERT_EQ(TLV_NEED_MORE_DATA, tlv_reader_next(&reader, &element));
        // Relocation is caller-owned. This fixture retains the original storage too.
        const std::vector<uint8_t> replacement = wire;
        ASSERT_EQ(TLV_OK,
                  tlv_reader_set_input(&reader, replacement.data(), replacement.size(), 0, 1));
        tlv_source_t source{};
        ASSERT_EQ(TLV_OK, tlv_reader_next_source_diag(&reader, &element, &source, nullptr));
        EXPECT_TRUE(tlv_tag_equal(whole.tag, element.tag));
        EXPECT_EQ(whole.value.size, element.value.size);
        EXPECT_EQ(replacement.data() + source.value.offset, element.value.data);
        EXPECT_EQ(replacement.data(), source.data);
        EXPECT_EQ(wire.size(), tlv_reader_consumed(&reader));
        EXPECT_EQ(TLV_ERR_END_OF_BUFFER, tlv_reader_next(&reader, &element));
    }
}
} // namespace

TEST(Integration_Tlv_Incremental, EverySplitUsesTheSelectedFormatAndBorrowedRepresentation) {
    const tlv_fixed_format_t config = {
        {1}, {1, TLV_BYTE_ORDER_BIG_ENDIAN}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
    tlv_format_t format;
    ASSERT_EQ(TLV_OK, tlv_fixed_format_init(&format, &config));
    check_splits(&format, {1, 2, 0xAA, 0xBB});
#if OPENTLV_FORMAT_BER
    check_splits(&tlv_format_ber, {0x9F, 0x33, 0x82, 0, 2, 0xAA, 0xBB});
    check_splits(&tlv_format_ber, {0x30, 0x80, 0x30, 0x80, 4, 1, 0xAA, 0, 0, 0, 0});
#endif
#if OPENTLV_FORMAT_DER
    check_splits(&tlv_format_der, {4, 2, 0xAA, 0xBB});
#endif
#if OPENTLV_FORMAT_CER
    check_splits(&tlv_format_cer, {0x30, 0x80, 4, 1, 0xAA, 0, 0});
#endif
#if OPENTLV_BLUETOOTH
    check_splits(&tlv_format_bluetooth_ltv, {3, 9, 'A', 'B'});
#endif
#if OPENTLV_DHCP
    check_splits(&tlv_format_dhcpv4, {0});
    check_splits(&tlv_format_dhcpv4, {255});
    check_splits(&tlv_format_dhcpv4, {12, 2, 'A', 'B'});
#endif
#if OPENTLV_LLDP
    check_splits(&tlv_format_lldp, {0x0A, 2, 'A', 'B'});
#endif
}

#if OPENTLV_FORMAT_BER
TEST(Integration_Tlv_Incremental, MalformedBytesAndClosedParentBoundsDoNotRequestMoreInput) {
    const std::vector<std::vector<uint8_t>> invalid = {
        {4, 0x80},
        {0x30, 0x80, 0x30, 3, 4, 2, 0xAA, 0, 0},
        {0x30, 0x80, 0x30, 2, 0x30, 0x80, 0, 0},
        {0x30, 0x80, 0x30, 1, 0x9F, 0, 0},
    };
    for (const auto& wire : invalid) {
        tlv_reader_t reader;
        ASSERT_EQ(TLV_OK,
                  tlv_reader_init_incremental(&reader, wire.data(), wire.size(), &tlv_format_ber));
        tlv_element_t element{};
        EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_reader_next(&reader, &element));
        EXPECT_EQ(0u, reader.pos);
    }
}

TEST(Integration_Tlv_Incremental, MissingEocReportsTrailerExtentThenTruncationAtEof) {
    const uint8_t wire[] = {0x30, 0x80, 4, 0, 0};
    tlv_reader_t  reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init_incremental(&reader, wire, sizeof(wire), &tlv_format_ber));
    tlv_element_t           element{};
    tlv_reader_diagnostic_t diagnostic{};
    ASSERT_EQ(
        TLV_NEED_MORE_DATA,
        TLV_DIAGNOSTIC_RESULT(diagnostic, tlv_reader_next_diag(&reader, &element, &diagnostic)));
    EXPECT_EQ(TLV_READER_OP_TRAILER, diagnostic.detail.operation);
    EXPECT_TRUE(diagnostic.detail.has_required);
    EXPECT_EQ(2u, diagnostic.detail.required);
    EXPECT_EQ(1u, diagnostic.detail.available);
    ASSERT_EQ(TLV_OK, tlv_reader_set_input(&reader, wire, sizeof(wire), 0, 1));
    EXPECT_EQ(
        TLV_ERR_BUFFER_TOO_SHORT,
        TLV_DIAGNOSTIC_RESULT(diagnostic, tlv_reader_next_diag(&reader, &element, &diagnostic)));
}
#endif
