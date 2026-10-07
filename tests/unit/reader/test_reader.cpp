// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv++/native.hpp"
#include "tlv++/definition.hpp"
#include "controlled_format.h"
#include "tlv++/reader/tree.hpp"
#include "tlv++/query/query.hpp"
#include <gtest/gtest.h>
#include <type_traits>

namespace {
tlv::bytes view(const uint8_t* data, size_t size) {
    return {reinterpret_cast<const tlv::byte*>(data), size};
}
int constructed(const void*, const tlv_tag_t* tag) {
    return tag->data[0] >= 0x80;
}
const tlv_format_t format = {&controlled::format_layout, tlv_fields_decode, tlv_fields_measure,
                             tlv_fields_encode, constructed};
} // namespace

TEST(Unit_Tlvpp_ReaderParity, SingleElementSourceAndFailurePreservation) {
    const uint8_t data[] = {1, 1, 42, 2, 0};
    size_t        consumed = 99;
    auto result = tlv::read(view(data, sizeof(data)), tlv::native::borrow_format(format), consumed);
    ASSERT_TRUE(result);
    EXPECT_EQ(3u, consumed);
    EXPECT_EQ(reinterpret_cast<const tlv::byte*>(data + 2), result->element.value().data());
    EXPECT_EQ(data, result->source.data);
    tlv::reader_diagnostic diagnostic{};
    auto                   failure =
        tlv::read(view(data, 2), tlv::native::borrow_format(format), consumed, &diagnostic);
    ASSERT_FALSE(failure);
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, failure.error().code);
    EXPECT_EQ(3u, consumed);
}

TEST(Unit_Tlvpp_ReaderParity, IncrementalSourceOffsetsAndFinalTruncation) {
    const uint8_t data[] = {1, 1, 42, 2, 1, 43};
    tlv::reader<> reader(view(data, 2), tlv::native::borrow_format(format),
                         tlv::input_mode::incremental);
    tlv_reader_t  native{};
    ASSERT_EQ(TLV_OK, tlv_reader_init_incremental(&native, data, 2, &format));
    tlv_element_t          element{};
    tlv::reader_diagnostic expected{}, actual{};
    auto                   failure = reader.next_source(&actual);
    ASSERT_FALSE(failure);
    EXPECT_EQ(tlv_reader_next_diag(&native, &element, &expected), failure.error().code);
    EXPECT_EQ(expected.diagnostic.offset, actual.diagnostic.offset);
    EXPECT_EQ(expected.operation, actual.operation);
    EXPECT_FALSE(reader.at_end());
    EXPECT_EQ(0u, reader.consumed());
    ASSERT_TRUE(reader.set_input(view(data, 4), 0, tlv::input_mode::incremental));
    ASSERT_TRUE(reader.next_source());
    EXPECT_EQ(3u, reader.consumed());
    ASSERT_TRUE(reader.set_input(view(data + 3, 1), 3, tlv::input_mode::incremental));
    EXPECT_EQ(3u, reader.offset());
    auto need_more = reader.next_source(&actual);
    ASSERT_FALSE(need_more);
    EXPECT_EQ(TLV_NEED_MORE_DATA, need_more.error().code);
    ASSERT_TRUE(reader.set_input(view(data + 3, 1), 0, tlv::input_mode::final));
    auto truncated = reader.next_source(&actual);
    ASSERT_FALSE(truncated);
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, truncated.error().code);
    EXPECT_EQ(4u, actual.diagnostic.offset); // Missing Length field, not the element start.
    EXPECT_EQ(3u, reader.offset());
}

TEST(Unit_Tlvpp_TreeReaderParity, ValidationReportsMalformedChildWithoutRequestingMoreInput) {
    const uint8_t          data[] = {0x80, 2, 1, 1};
    tlv::tree_frame        frames[1]{};
    tlv::tree_reader       reader(view(data, sizeof(data)), tlv::native::borrow_format(format),
                                  {frames, 1}, 1, 5, tlv::input_mode::incremental);
    size_t                 offset = 99;
    tlv::reader_diagnostic diagnostic{};
    auto                   result = reader.validate(&offset, &diagnostic);
    ASSERT_FALSE(result);
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, result.error().code);
    EXPECT_EQ(2u, offset);
    EXPECT_EQ(2u, reader.offset());
    EXPECT_EQ(4u, diagnostic.diagnostic.offset); // Missing Value at the parent's end.
}

TEST(Unit_Tlvpp_QueryParity, MatcherOwnsQueryAfterTemporaryExpires) {
    tlv::query_matcher matcher(*tlv::query::parse("80/01"));
    EXPECT_FALSE(matcher.matches(tlv::tag_bytes<0x80>(), 0));
    EXPECT_TRUE(matcher.matches(tlv::tag_bytes<1>(), 1));
    EXPECT_FALSE(matcher.matches(tlv::tag_bytes<1>(), 0));
}

TEST(Unit_Tlvpp_ReaderParity, VisitorStopThenResumeWithoutReplay) {
    const uint8_t data[] = {1, 0, 2, 0};
    tlv::reader<> reader(view(data, sizeof(data)), tlv::native::borrow_format(format),
                         tlv::input_mode::incremental);
    size_t        count = 0;
    const auto    stop = [&](const tlv::element_view& value) {
        ++count;
        EXPECT_EQ(1u, static_cast<int>(value.tag().data()[0]));
        return TLV_VISIT_STOP;
    };
    ASSERT_TRUE(reader.visit(stop));
    auto status = reader.visit([&](const tlv::element_view& value) {
        ++count;
        EXPECT_EQ(2u, static_cast<int>(value.tag().data()[0]));
        return TLV_VISIT_CONTINUE;
    });
    ASSERT_FALSE(status);
    EXPECT_EQ(TLV_NEED_MORE_DATA, status.error().code);
    EXPECT_EQ(2u, count);
    ASSERT_TRUE(reader.set_input(view(nullptr, 0), sizeof(data), tlv::input_mode::final));
    EXPECT_TRUE(reader.at_end());
}

TEST(Unit_Tlvpp_TreeReaderParity, EveryItemMatchesCanonicalCursor) {
    static_assert(!std::is_copy_constructible<tlv::tree_reader>::value, "frames must not alias");
    const uint8_t     data[] = {0x80, 6, 1, 0, 0x81, 2, 2, 0, 3, 0};
    tlv::tree_frame   frames[2]{}, native_frames[2]{};
    tlv::tree_reader  reader(view(data, sizeof(data)), tlv::native::borrow_format(format),
                             {frames, 2}, 2, 5);
    tlv_tree_reader_t native{};
    ASSERT_EQ(TLV_OK,
              tlv_tree_reader_init(&native, data, sizeof(data), &format, native_frames, 2, 2, 5));
    for (size_t i = 0; i < 5; ++i) {
        auto            item = reader.next();
        tlv_tree_item_t expected{};
        ASSERT_EQ(TLV_OK, tlv_tree_reader_next(&native, &expected));
        ASSERT_TRUE(item);
        EXPECT_EQ(expected.offset, item->offset);
        EXPECT_EQ(expected.depth, item->depth);
        EXPECT_EQ(expected.constructed, item->constructed);
        EXPECT_EQ(reinterpret_cast<const tlv::byte*>(expected.element.value.data),
                  item->element.value().data());
        EXPECT_EQ(expected.element.value.size, item->element.value().size());
        EXPECT_EQ(expected.source.data, item->source.data);
        EXPECT_EQ(expected.source.value.offset, item->source.value.offset);
    }
    EXPECT_TRUE(reader.at_end());
    EXPECT_EQ(sizeof(data), reader.consumed());
    auto end = reader.next();
    ASSERT_FALSE(end);
    EXPECT_EQ(TLV_ERR_END_OF_BUFFER, end.error().code);
}

TEST(Unit_Tlvpp_TreeReaderParity, DescentLimitAllowsSkipAndCountsOnlyPublishedItems) {
    const uint8_t    data[] = {0x80, 2, 1, 0, 2, 0};
    tlv::tree_reader reader(view(data, sizeof(data)), tlv::native::borrow_format(format), {}, 0, 2);
    ASSERT_TRUE(reader.next());
    auto limit = reader.next();
    ASSERT_FALSE(limit);
    EXPECT_EQ(TLV_ERR_LIMIT, limit.error().code);
    ASSERT_TRUE(reader.skip_subtree());
    auto sibling = reader.next();
    ASSERT_TRUE(sibling);
    EXPECT_EQ(4u, sibling->offset);
    EXPECT_TRUE(reader.at_end());
}

TEST(Unit_Tlvpp_TreeReaderParity, CompleteParentRequiredAndVisitorResumesAfterSkip) {
    const uint8_t    data[] = {0x80, 2, 1, 0, 2, 0};
    tlv::tree_frame  frames[1]{};
    tlv::tree_reader reader(view(data, 3), tlv::native::borrow_format(format), {frames, 1}, 1, 3,
                            tlv::input_mode::incremental);
    auto             incomplete = reader.next();
    ASSERT_FALSE(incomplete);
    EXPECT_EQ(TLV_NEED_MORE_DATA, incomplete.error().code);
    EXPECT_EQ(0u, reader.offset());
    ASSERT_TRUE(reader.set_input(view(data, 4), 0, tlv::input_mode::incremental));
    const auto stop = [](const tlv::element_view&, size_t, size_t) { return TLV_VISIT_STOP; };
    ASSERT_TRUE(reader.visit(stop));
    ASSERT_TRUE(reader.skip_subtree());
    EXPECT_EQ(4u, reader.consumed());
    ASSERT_TRUE(reader.set_input(view(data + 4, 2), 4, tlv::input_mode::final));
    size_t count = 0;
    ASSERT_TRUE(reader.visit([&](const tlv::element_view& value, size_t depth, size_t offset) {
        ++count;
        EXPECT_EQ(2u, static_cast<int>(value.tag().data()[0]));
        EXPECT_EQ(0u, depth);
        EXPECT_EQ(4u, offset);
        return TLV_VISIT_CONTINUE;
    }));
    EXPECT_EQ(1u, count);
    EXPECT_TRUE(reader.at_end());
}

TEST(Unit_Tlvpp_QueryParity, MatchStateSurvivesStopAndInputReplacement) {
    const uint8_t data[] = {0x80, 4, 1, 0, 1, 0, 0x80, 2, 1, 0};
    auto          query = tlv::query::parse("80/01");
    ASSERT_TRUE(query);
    EXPECT_EQ(tlv::byte{0x80}, query->step(0).data()[0]);
    EXPECT_EQ(0u, query->step(2).size());
    tlv::query_matcher matcher(*query);
    tlv::tree_frame    frames[1]{};
    tlv::tree_reader   reader(view(data, 6), tlv::native::borrow_format(format), {frames, 1}, 1, 5,
                              tlv::input_mode::incremental);
    size_t             count = 0;
    const auto         stop = [&](const tlv::element_view&, size_t depth, size_t offset) {
        ++count;
        EXPECT_EQ(1u, depth);
        EXPECT_EQ(2u, offset);
        return TLV_VISIT_STOP;
    };
    ASSERT_TRUE(matcher.visit(reader, stop));
    auto status = matcher.visit(reader, [&](const tlv::element_view&, size_t, size_t offset) {
        ++count;
        EXPECT_EQ(4u, offset);
        return TLV_VISIT_CONTINUE;
    });
    ASSERT_FALSE(status);
    EXPECT_EQ(TLV_NEED_MORE_DATA, status.error().code);
    ASSERT_TRUE(reader.set_input(view(data + 6, 4), 6, tlv::input_mode::final));
    ASSERT_TRUE(matcher.visit(reader, [&](const tlv::element_view&, size_t, size_t offset) {
        ++count;
        EXPECT_EQ(8u, offset);
        return TLV_VISIT_CONTINUE;
    }));
    EXPECT_EQ(3u, count);
}

TEST(Unit_Tlvpp_DefinitionParity, LookupUsesCanonicalFirstMatch) {
    const uint8_t         identifier[] = {1};
    const tlv::definition entries[] = {
        {tlv::tag(tlv::bytes(reinterpret_cast<const tlv::byte*>(identifier), 1)), "first"},
        {tlv::tag(tlv::bytes(reinterpret_cast<const tlv::byte*>(identifier), 1)), "second"},
        {tlv::tag(tlv::bytes(static_cast<const tlv::byte*>(nullptr), 0)), nullptr},
    };
    const tlv::definition_registry registry(tlv::span<const tlv::definition>(entries, 3));
    EXPECT_EQ(&entries[0], registry.find(tlv::tag(
                               tlv::bytes(reinterpret_cast<const tlv::byte*>(identifier), 1))));
    EXPECT_EQ(&entries[2],
              registry.find(tlv::tag(tlv::bytes(static_cast<const tlv::byte*>(nullptr), 0))));
    const uint8_t unknown[] = {2};
    EXPECT_EQ(nullptr,
              registry.find(tlv::tag(tlv::bytes(reinterpret_cast<const tlv::byte*>(unknown), 1))));
}
