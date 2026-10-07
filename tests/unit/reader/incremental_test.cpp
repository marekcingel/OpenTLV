// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "controlled_format.h"
#include "tlv/reader/reader.h"
#include "tlv/formats/fixed.h"
#include <gtest/gtest.h>
#include <cstring>
#include <vector>

TEST(Unit_Tlv_Incremental, EmptyOpenInputRequiresDataUntilExplicitEof) {
    tlv_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init_incremental(&reader, nullptr, 0, &controlled::format));
    tlv_element_t           element = {TLV_TAG(0xEE), {nullptr, 42}};
    tlv_reader_diagnostic_t diagnostic{};
    for (int i = 0; i < 2; ++i) {
        EXPECT_FALSE(tlv_reader_at_end(&reader));
        EXPECT_EQ(TLV_NEED_MORE_DATA, tlv_reader_next_diag(&reader, &element, &diagnostic));
        EXPECT_EQ(TLV_NEED_MORE_DATA, diagnostic.diagnostic.code);
        EXPECT_EQ(TLV_DIAGNOSTIC_SEVERITY_INFO, diagnostic.diagnostic.severity);
        EXPECT_EQ(0u, diagnostic.available);
        EXPECT_EQ(0u, tlv_reader_consumed(&reader));
        EXPECT_EQ(42u, element.value.size);
    }
    ASSERT_EQ(TLV_OK, tlv_reader_set_input(&reader, nullptr, 0, 0, 1));
    EXPECT_TRUE(tlv_reader_at_end(&reader));
    EXPECT_EQ(TLV_ERR_END_OF_BUFFER, tlv_reader_next(&reader, &element));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_reader_set_input(&reader, nullptr, 0, 0, 0));
    EXPECT_STREQ("need more data", tlv_strerror(TLV_NEED_MORE_DATA));
}

TEST(Unit_Tlv_Incremental, EverySplitResumesWithoutPublishingPartialOutput) {
    const uint8_t wire[] = {1, 3, 0xAB, 0xCD, 0xEF};
    for (size_t split = 0; split < sizeof(wire); ++split) {
        SCOPED_TRACE(split);
        tlv_reader_t reader;
        ASSERT_EQ(TLV_OK, tlv_reader_init_incremental(&reader, wire, split, &controlled::format));
        tlv_element_t element = {TLV_TAG(0xEE), {nullptr, 42}};
        tlv_source_t  source{};
        source.size = 99;
        for (int i = 0; i < 2; ++i) {
            EXPECT_EQ(TLV_NEED_MORE_DATA,
                      tlv_reader_next_source_diag(&reader, &element, &source, nullptr));
            EXPECT_EQ(0xEE, element.tag.data[0]);
            EXPECT_EQ(42u, element.value.size);
            EXPECT_EQ(99u, source.size);
            EXPECT_EQ(0u, tlv_reader_consumed(&reader));
        }
        ASSERT_EQ(TLV_OK, tlv_reader_set_input(&reader, wire, sizeof(wire), 0, 0));
        ASSERT_EQ(TLV_OK, tlv_reader_next_source_diag(&reader, &element, &source, nullptr));
        EXPECT_EQ(wire + 2, element.value.data);
        EXPECT_EQ(wire, source.data);
        EXPECT_EQ(sizeof(wire), tlv_reader_consumed(&reader));
        EXPECT_EQ(TLV_NEED_MORE_DATA, tlv_reader_next(&reader, &element));
        ASSERT_EQ(TLV_OK, tlv_reader_set_input(&reader, wire, sizeof(wire), 0, 1));
        EXPECT_EQ(TLV_ERR_END_OF_BUFFER, tlv_reader_next(&reader, &element));
    }
}

TEST(Unit_Tlv_Incremental, FinalInputReportsTruncationAndPreservesRequiredExtent) {
    const uint8_t wire[] = {1, 5, 0xAA};
    tlv_reader_t  reader;
    ASSERT_EQ(TLV_OK,
              tlv_reader_init_incremental(&reader, wire, sizeof(wire), &controlled::format));
    tlv_element_t           element{};
    tlv_reader_diagnostic_t diagnostic{};
    ASSERT_EQ(TLV_NEED_MORE_DATA, tlv_reader_next_diag(&reader, &element, &diagnostic));
    EXPECT_TRUE(diagnostic.has_required);
    EXPECT_EQ(5u, diagnostic.required);
    EXPECT_EQ(1u, diagnostic.available);
    ASSERT_EQ(TLV_OK, tlv_reader_set_input(&reader, wire, sizeof(wire), 0, 1));
    ASSERT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_reader_next_diag(&reader, &element, &diagnostic));
    EXPECT_EQ(TLV_DIAGNOSTIC_SEVERITY_ERROR, diagnostic.diagnostic.severity);
    EXPECT_EQ(5u, diagnostic.required);
    EXPECT_EQ(0u, tlv_reader_offset(&reader));
    EXPECT_FALSE(tlv_reader_at_end(&reader));
}

TEST(Unit_Tlv_Incremental, RelocatedWindowsPreserveLogicalOffsetsAndOldBorrowedViews) {
    const uint8_t first[] = {1, 1, 0xAA, 2, 2, 0xBB};
    const uint8_t second[] = {2, 2, 0xBB, 0xCC, 3};
    const uint8_t third[] = {3, 0};
    tlv_reader_t  reader;
    ASSERT_EQ(TLV_OK,
              tlv_reader_init_incremental(&reader, first, sizeof(first), &controlled::format));
    tlv_element_t retained{}, element{};
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &retained));
    tlv_reader_diagnostic_t diagnostic{};
    ASSERT_EQ(TLV_NEED_MORE_DATA, tlv_reader_next_diag(&reader, &element, &diagnostic));
    EXPECT_EQ(5u, diagnostic.diagnostic.offset);
    ASSERT_EQ(TLV_OK, tlv_reader_set_input(&reader, second, sizeof(second), 3, 0));
    EXPECT_EQ(3u, tlv_reader_offset(&reader));
    EXPECT_EQ(0u, tlv_reader_consumed(&reader));
    tlv_source_t source{};
    ASSERT_EQ(TLV_OK, tlv_reader_next_source_diag(&reader, &element, &source, nullptr));
    EXPECT_EQ(second, source.data);
    EXPECT_EQ(second + 2, element.value.data);
    EXPECT_EQ(7u, tlv_reader_offset(&reader));
    ASSERT_EQ(TLV_NEED_MORE_DATA, tlv_reader_next_diag(&reader, &element, &diagnostic));
    EXPECT_EQ(8u, diagnostic.diagnostic.offset);
    EXPECT_EQ(7u, diagnostic.tag_offset);
    EXPECT_EQ(8u, diagnostic.length_offset);
    EXPECT_EQ(8u, diagnostic.enclosing_end);
    ASSERT_EQ(TLV_OK, tlv_reader_set_input(&reader, third, sizeof(third), 4, 1));
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
    EXPECT_EQ(9u, tlv_reader_offset(&reader));
    EXPECT_EQ(first + 2, retained.value.data);
    EXPECT_EQ(0xAA, retained.value.data[0]);
    ASSERT_EQ(TLV_OK, tlv_reader_set_input(&reader, nullptr, 0, 2, 1));
    EXPECT_EQ(9u, tlv_reader_offset(&reader));
    EXPECT_EQ(TLV_ERR_END_OF_BUFFER, tlv_reader_next_diag(&reader, &element, &diagnostic));
    EXPECT_EQ(9u, diagnostic.diagnostic.offset);
}

TEST(Unit_Tlv_Incremental, CallerCanSlideWithinBoundedStorageAcrossManyElements) {
    uint8_t      window[5] = {};
    tlv_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init_incremental(&reader, window, 0, &controlled::format));
    size_t published = 0;
    for (size_t i = 0; i != 300; ++i) {
        const size_t discard = tlv_reader_consumed(&reader);
        const size_t retained = reader.size - discard;
        std::memmove(window, window + discard, retained);
        window[retained] = i % 3 == 0 ? 1 : (i % 3 == 1 ? 1 : 0xAA);
        ASSERT_EQ(TLV_OK, tlv_reader_set_input(&reader, window, retained + 1, discard, i == 299));
        tlv_element_t element{};
        const auto    rc = tlv_reader_next(&reader, &element);
        if (i % 3 == 2) {
            ASSERT_EQ(TLV_OK, rc);
            EXPECT_EQ(0xAA, element.value.data[0]);
            ++published;
        } else {
            EXPECT_EQ(TLV_NEED_MORE_DATA, rc);
        }
    }
    EXPECT_EQ(100u, published);
    EXPECT_EQ(300u, tlv_reader_offset(&reader));
    EXPECT_TRUE(tlv_reader_at_end(&reader));
}

TEST(Unit_Tlv_Incremental, RejectsInvalidWindowUpdatesTransactionally) {
    const uint8_t wire[] = {1, 0, 2};
    tlv_reader_t  reader;
    ASSERT_EQ(TLV_OK,
              tlv_reader_init_incremental(&reader, wire, sizeof(wire), &controlled::format));
    tlv_element_t element{};
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
    unsigned char before[sizeof(reader)];
    std::memcpy(before, &reader, sizeof(reader));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_reader_set_input(&reader, wire, sizeof(wire), 3, 0));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_reader_set_input(&reader, wire, 0, 2, 0));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_reader_set_input(&reader, wire, sizeof(wire), 0, 2));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_reader_set_input(&reader, nullptr, 1, 2, 0));
    EXPECT_EQ(0, std::memcmp(before, &reader, sizeof(reader)));
    ASSERT_EQ(TLV_OK, tlv_reader_set_input(&reader, wire, sizeof(wire), 0, 1));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_reader_set_input(&reader, wire, sizeof(wire) + 1, 0, 1));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_reader_set_input(&reader, wire, sizeof(wire), 0, 0));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_reader_set_input(nullptr, nullptr, 0, 0, 0));
}

TEST(Unit_Tlv_Incremental, PartialDiscardAndAppendPreserveTheUnconsumedBoundary) {
    const uint8_t wire[] = {1, 0, 2, 1, 0xAA};
    tlv_reader_t  reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init_incremental(&reader, wire, 3, &controlled::format));
    tlv_element_t element{};
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
    ASSERT_EQ(TLV_OK, tlv_reader_set_input(&reader, wire + 1, 2, 1, 0));
    EXPECT_EQ(1u, tlv_reader_consumed(&reader));
    EXPECT_EQ(2u, tlv_reader_offset(&reader));
    tlv_reader_diagnostic_t diagnostic{};
    ASSERT_EQ(TLV_NEED_MORE_DATA, tlv_reader_next_diag(&reader, &element, &diagnostic));
    EXPECT_FALSE(diagnostic.has_required); // Custom Format does not know the missing extent.
    ASSERT_EQ(TLV_OK, tlv_reader_set_input(&reader, wire + 1, 4, 0, 1));
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
    EXPECT_EQ(wire + 4, element.value.data);
    EXPECT_EQ(5u, tlv_reader_offset(&reader));
    EXPECT_TRUE(tlv_reader_at_end(&reader));
    ASSERT_EQ(TLV_OK, tlv_reader_init_incremental(&reader, nullptr, 0, &controlled::format));
    EXPECT_EQ(0u, tlv_reader_offset(&reader));
    EXPECT_FALSE(tlv_reader_at_end(&reader));
}

TEST(Unit_Tlv_Incremental, AbsoluteOffsetOverflowIsRejectedWithoutPublishing) {
    const uint8_t wire[] = {1, 0};
    tlv_reader_t  reader;
    ASSERT_EQ(TLV_OK,
              tlv_reader_init_incremental(&reader, wire, sizeof(wire), &controlled::format));
    // Exercise the end of the size_t offset domain without allocating a huge stream.
    reader.base_offset = SIZE_MAX - sizeof(wire);
    tlv_element_t element{};
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
    ASSERT_EQ(TLV_OK, tlv_reader_set_input(&reader, nullptr, 0, sizeof(wire), 0));
    EXPECT_EQ(SIZE_MAX, tlv_reader_offset(&reader));
    EXPECT_EQ(TLV_ERR_OVERFLOW, tlv_reader_set_input(&reader, wire, 1, 0, 0));
    EXPECT_EQ(nullptr, reader.data);
    EXPECT_EQ(0u, reader.size);
    ASSERT_EQ(TLV_OK, tlv_reader_set_input(&reader, nullptr, 0, 0, 1));
    tlv_reader_diagnostic_t diagnostic{};
    EXPECT_EQ(TLV_ERR_END_OF_BUFFER, tlv_reader_next_diag(&reader, &element, &diagnostic));
    EXPECT_EQ(SIZE_MAX, diagnostic.diagnostic.offset);
}

TEST(Unit_Tlv_Incremental, FixedHeaderReportsKnownRequiredExtent) {
    const tlv_fixed_format_t config = {
        {2}, {2, TLV_BYTE_ORDER_BIG_ENDIAN}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
    tlv_format_t format;
    ASSERT_EQ(TLV_OK, tlv_fixed_format_init(&format, &config));
    const uint8_t wire[] = {1, 2, 0, 0};
    for (size_t size : {size_t(1), size_t(3)}) {
        tlv_reader_t reader;
        ASSERT_EQ(TLV_OK, tlv_reader_init_incremental(&reader, wire, size, &format));
        tlv_reader_diagnostic_t diagnostic{};
        tlv_element_t           element{};
        ASSERT_EQ(TLV_NEED_MORE_DATA, tlv_reader_next_diag(&reader, &element, &diagnostic));
        EXPECT_TRUE(diagnostic.has_required);
        EXPECT_EQ(2u, diagnostic.required);
        EXPECT_EQ(1u, diagnostic.available);
    }
}
