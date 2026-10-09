// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "../../diagnostic_assertions.h"
#include "tlv/builtins/asn1/ber.h"
#include "tlv/reader/reader.h"
#include <gtest/gtest.h>
#include <limits>

TEST(Integration_Tlv_Reader, EmptyValueAndBerLength) {
    const uint8_t data[] = {0x42, 0x82, 0, 0};
    tlv_element_t element{};
    size_t        consumed = 0;
    ASSERT_EQ(TLV_OK, tlv_read(data, sizeof(data), &tlv_format_ber, &element, &consumed));
    EXPECT_EQ(data + sizeof(data), element.value.data);
    EXPECT_EQ(0u, element.value.size);
    EXPECT_EQ(sizeof(data), consumed);
}

namespace {
void expect_failure(const uint8_t* data, size_t size, const tlv_format_t* format,
                    tlv_result_t error) {
    tlv_element_t element = {TLV_TAG(0xEE), {data, 42}};
    size_t        consumed = 99;
    EXPECT_EQ(error, tlv_read(data, size, format, &element, &consumed));
    EXPECT_EQ(99u, consumed);
    EXPECT_EQ(1u, element.tag.size);
    EXPECT_EQ(0xEE, element.tag.data[0]);
    EXPECT_EQ(data, element.value.data);
    EXPECT_EQ(42u, element.value.size);
}
} // namespace

TEST(Integration_Tlv_Reader, DetectsTruncatedBerLengthAndValue) {
    const uint8_t data[] = {1, 0x82, 0, 2, 0xAB, 0xCD};
    for (size_t size = 1; size < sizeof(data); ++size)
        expect_failure(data, size, &tlv_format_ber, TLV_ERR_BUFFER_TOO_SHORT);
    const uint8_t invalid[] = {1, 0x80};
    expect_failure(invalid, sizeof(invalid), &tlv_format_ber, TLV_ERR_INVALID_LENGTH);
}

TEST(Integration_Tlv_Reader, CursorDistinguishesIncompleteTagLengthValueAndTrailer) {
    // Two complete elements; the second uses a multibyte identifier, a long
    // length and an indefinite parent, exercising all framing regions.
    const uint8_t data[] = {4, 0, 0x30, 0x80, 0x9F, 0x33, 0x81, 1, 0xAB, 0, 0};
    for (size_t size = 3; size < sizeof(data); ++size) {
        SCOPED_TRACE(size);
        tlv_reader_t reader;
        ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, size, &tlv_format_ber));
        tlv_element_t element{};
        ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
        for (int repeat = 0; repeat != 2; ++repeat) {
            tlv_reader_diagnostic_t diagnostic{};
            EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
                      TLV_DIAGNOSTIC_RESULT(diagnostic,
                                            tlv_reader_next_diag(&reader, &element, &diagnostic)));
            EXPECT_EQ(2u, reader.pos);
            EXPECT_EQ(data, element.tag.data);
            EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, diagnostic.diagnostic.code);
            EXPECT_GE(diagnostic.diagnostic.location.begin, 2u);
            EXPECT_LE(diagnostic.diagnostic.location.begin, size);
            EXPECT_EQ(size, diagnostic.detail.enclosing_end);
        }
    }
    tlv_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data), &tlv_format_ber));
    tlv_element_t element{};
    tlv_source_t  source{};
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
    ASSERT_EQ(TLV_OK, tlv_reader_next_source_diag(&reader, &element, &source, nullptr));
    EXPECT_EQ(sizeof(data), reader.pos);
    EXPECT_EQ(data + 2, source.data);
    EXPECT_EQ(9u, source.size);
    EXPECT_EQ(5u, element.value.size);
    EXPECT_EQ(7u, source.trailer.offset);
    EXPECT_EQ(2u, source.trailer.size);
    EXPECT_EQ(TLV_ERR_END_OF_BUFFER, tlv_reader_next(&reader, &element));
}

TEST(Integration_Tlv_Reader, CursorReturnsMalformedInputWithoutScanningForLaterElement) {
    const uint8_t data[] = {4, 0, 4, 0x80, 4, 0}; // Indefinite primitive is malformed.
    tlv_reader_t  reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data), &tlv_format_ber));
    tlv_element_t element{};
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
    tlv_reader_diagnostic_t diagnostic{};
    for (int repeat = 0; repeat != 2; ++repeat) {
        EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
                  TLV_DIAGNOSTIC_RESULT(diagnostic,
                                        tlv_reader_next_diag(&reader, &element, &diagnostic)));
        EXPECT_EQ(2u, reader.pos);
        EXPECT_EQ(data, element.tag.data);
        EXPECT_EQ(3u, diagnostic.diagnostic.location.begin);
        EXPECT_EQ(TLV_READER_OP_LENGTH, diagnostic.detail.operation);
    }
}
