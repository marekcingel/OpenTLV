#include "tlv/formats/default/default.h"
#include "tlv/formats/fixed/fixed_1byte.h"
#include "tlv/reader/scanner.h"
#include "tlv/reader/reader.h"
#include <gtest/gtest.h>

namespace {
const tlv_schema_entry_t rules[] = {{{{0x42}, 1}, 1, 2, 0}};
const tlv_schema_t schema = {rules, 1};



class Integration_Scanner : public ::testing::Test {
protected:
    tlv_view_t view = {{{0xAA}, 1}, {nullptr, 99}};
    size_t offset = 88;
    size_t consumed = 77;

    tlv_result_t scan(const uint8_t* data, size_t size, size_t start = 0,
                      const tlv_schema_t* filter = nullptr,
                      const tlv_reader_format_t* format = &tlv_reader_format_fixed_1byte) {
        return tlv_scan(data, size, start, format, filter, &view, &offset, &consumed);
    }

    void unchanged() {
        EXPECT_EQ(0xAA, view.tag.data[0]);
        EXPECT_EQ(1, view.tag.size);
        EXPECT_EQ(nullptr, view.value.data);
        EXPECT_EQ(99u, view.value.length);
        EXPECT_EQ(88u, offset);
        EXPECT_EQ(77u, consumed);
    }
};
}

TEST_F(Integration_Scanner, SkipsInvalidLeadingBytesWithoutSchema) {
    const uint8_t data[] = {0xFF, 0xFF, 0x42, 1, 0xAB};
    ASSERT_EQ(TLV_OK, scan(data, sizeof(data)));
    EXPECT_EQ(2u, offset);
    EXPECT_EQ(3u, consumed);
    EXPECT_EQ(0x42, view.tag.data[0]);
    EXPECT_EQ(data + 4, view.value.data);
    EXPECT_EQ(1u, view.value.length);
}

TEST_F(Integration_Scanner, ReturnsFirstCandidateAndResumesAtAbsoluteOffset) {
    const uint8_t data[] = {1, 0, 0xFF, 0x42, 0};
    ASSERT_EQ(TLV_OK, scan(data, sizeof(data)));
    EXPECT_EQ(0u, offset);
    ASSERT_EQ(TLV_OK, scan(data, sizeof(data), offset + consumed));
    EXPECT_EQ(3u, offset);
    EXPECT_EQ(2u, consumed);
    EXPECT_EQ(0u, view.value.length);
}

TEST_F(Integration_Scanner, SchemaRejectsUnknownTagsAndInvalidLengths) {
    const uint8_t data[] = {7, 0, 0x42, 0, 0x42, 3, 0xFF, 0xFF, 0xFF,
                            0x42, 2, 0xAA, 0xBB};
    ASSERT_EQ(TLV_OK, scan(data, sizeof(data)));
    EXPECT_EQ(0u, offset);
    ASSERT_EQ(TLV_OK, scan(data, sizeof(data), 0, &schema));
    EXPECT_EQ(9u, offset);
    EXPECT_EQ(2u, view.value.length);
    EXPECT_EQ(4u, consumed);
}

TEST_F(Integration_Scanner, EmptyAndReversedSchemasRejectAllCandidates) {
    const uint8_t data[] = {0x42, 1, 0xFF};
    const tlv_schema_t empty = {nullptr, 0};
    EXPECT_EQ(TLV_ERR_END_OF_BUFFER, scan(data, sizeof(data), 0, &empty));
    unchanged();
    const tlv_schema_entry_t reversed_rule = {{{0x42}, 1}, 2, 1, 0};
    const tlv_schema_t reversed = {&reversed_rule, 1};
    EXPECT_EQ(TLV_ERR_END_OF_BUFFER, scan(data, sizeof(data), 0, &reversed));
    unchanged();
}

TEST_F(Integration_Scanner, HandlesEveryTruncatedPrefixSafely) {
    const uint8_t data[] = {0x42, 0x82, 0, 2, 0xAA, 0xBB};
    for (size_t size = 0; size < sizeof(data); ++size) {
        EXPECT_EQ(TLV_ERR_END_OF_BUFFER,
                  scan(data, size, 0, &schema, &tlv_reader_format_default));
        unchanged();
    }
    ASSERT_EQ(TLV_OK, scan(data, sizeof(data), 0, &schema, &tlv_reader_format_default));
    EXPECT_EQ(0u, offset);
    EXPECT_EQ(sizeof(data), consumed);
}

TEST_F(Integration_Scanner, ContinuesAfterInvalidLengthAndTruncatedCandidate) {
    const uint8_t data[] = {0xFF, 0xFF, 0x42, 0x81, 1, 0xAA};
    ASSERT_EQ(TLV_OK, scan(data, sizeof(data), 0, &schema, &tlv_reader_format_default));
    EXPECT_EQ(2u, offset);
    EXPECT_EQ(4u, consumed);
    const uint8_t nested[] = {0x42, 0x7F, 0x42, 1, 0xAA};
    ASSERT_EQ(TLV_OK, scan(nested, sizeof(nested), 0, &schema));
    EXPECT_EQ(2u, offset);
}

TEST_F(Integration_Scanner, NormalReaderStillStopsAtInvalidBoundary) {
    const uint8_t data[] = {0xFF, 0xFF, 0x42, 1, 0xAA};
    tlv_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data), &tlv_reader_format_fixed_1byte));
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_reader_next(&reader, &view));
    EXPECT_EQ(0u, reader.pos);
    unchanged();
    ASSERT_EQ(TLV_OK, scan(data, sizeof(data)));
    EXPECT_EQ(2u, offset);
    EXPECT_EQ(0u, reader.pos);
}

