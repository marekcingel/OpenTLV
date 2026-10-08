// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "../../diagnostic_assertions.h"
#include "controlled_format.h"
#include "tlv/reader/tree.h"
#include "tlv/writer/tree.h"
#include <gtest/gtest.h>
#include <cstring>
#include <vector>

namespace {
int constructed(const void*, const tlv_tag_t* tag) {
    return tag->data[0] >= 0x80;
}
const tlv_format_t format = {&controlled::format_layout, tlv_fields_decode, tlv_fields_measure,
                             tlv_fields_encode, constructed};
} // namespace

TEST(Unit_Tlv_Tree, PreorderMetadataAndIndependentBorrowedResults) {
    const uint8_t     data[] = {0xE1, 6, 1, 0, 0xE2, 2, 2, 0, 3, 0};
    tlv_tree_frame_t  frames[2];
    tlv_tree_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_tree_reader_init(&reader, data, sizeof(data), &format, frames, 2, 2, 5));
    const size_t    offsets[] = {0, 2, 4, 6, 8}, depths[] = {0, 1, 1, 2, 0};
    tlv_tree_item_t retained{};
    for (size_t i = 0; i < 5; ++i) {
        tlv_tree_item_t item{};
        ASSERT_EQ(TLV_OK, tlv_tree_reader_next(&reader, &item));
        EXPECT_EQ(offsets[i], item.offset);
        EXPECT_EQ(depths[i], item.depth);
        EXPECT_EQ(data + offsets[i], item.source.data);
        EXPECT_EQ(item.source.data + item.source.value.offset, item.element.value.data);
        EXPECT_EQ(i == 0 || i == 2, item.constructed != 0);
        if (i == 0) retained = item;
    }
    EXPECT_TRUE(tlv_tree_reader_at_end(&reader));
    EXPECT_EQ(sizeof(data), tlv_tree_reader_consumed(&reader));
    EXPECT_EQ(data + 2, retained.element.value.data);
    EXPECT_EQ(6u, retained.element.value.size);
    tlv_tree_item_t output = retained;
    EXPECT_EQ(TLV_ERR_END_OF_BUFFER, tlv_tree_reader_next(&reader, &output));
    EXPECT_EQ(retained.source.data, output.source.data);
}

TEST(Unit_Tlv_Tree, RuntimeDepthAndStorageCanExceedTheDefault) {
    const size_t         depth = TLV_TREE_DEFAULT_DEPTH + 32;
    std::vector<uint8_t> data;
    for (size_t i = 0; i <= depth; ++i) {
        data.push_back(0x80);
        data.push_back(static_cast<uint8_t>(2 * (depth - i)));
    }
    std::vector<tlv_tree_frame_t> frames(depth);
    tlv_tree_reader_t             reader;
    ASSERT_EQ(TLV_OK, tlv_tree_reader_init(&reader, data.data(), data.size(), &format,
                                           frames.data(), frames.size(), depth, depth + 1));
    for (size_t i = 0; i <= depth; ++i) {
        tlv_tree_item_t item{};
        ASSERT_EQ(TLV_OK, tlv_tree_reader_next(&reader, &item));
        EXPECT_EQ(i, item.depth);
        EXPECT_EQ(2 * i, item.offset);
    }
    EXPECT_TRUE(tlv_tree_reader_at_end(&reader));
}

TEST(Unit_Tlv_Tree, DepthAndCapacityLimitsAllowSkippingPendingSubtrees) {
    const uint8_t data[] = {0x80, 2, 1, 0, 2, 0};
    for (bool capacity_limit : {false, true}) {
        tlv_tree_frame_t  frame{99, 99};
        tlv_tree_reader_t reader;
        ASSERT_EQ(TLV_OK,
                  tlv_tree_reader_init(&reader, data, sizeof(data), &format,
                                       capacity_limit ? nullptr : &frame, capacity_limit ? 0 : 1,
                                       capacity_limit ? 100 : 0, 2));
        tlv_tree_item_t item{};
        ASSERT_EQ(TLV_OK, tlv_tree_reader_next(&reader, &item));
        EXPECT_EQ(2u, tlv_tree_reader_consumed(&reader));
        for (int i = 0; i < 2; ++i) {
            EXPECT_EQ(TLV_ERR_LIMIT, tlv_tree_reader_next(&reader, &item));
            EXPECT_EQ(0u, item.offset);
            EXPECT_EQ(2u, tlv_tree_reader_offset(&reader));
            EXPECT_EQ(99u, frame.end);
        }
        ASSERT_EQ(TLV_OK, tlv_tree_reader_skip_subtree(&reader));
        EXPECT_EQ(4u, tlv_tree_reader_offset(&reader));
        ASSERT_EQ(TLV_OK, tlv_tree_reader_next(&reader, &item));
        EXPECT_EQ(2u, item.element.tag.data[0]);
        EXPECT_EQ(2u, reader.count);
        EXPECT_TRUE(tlv_tree_reader_at_end(&reader));
    }
}

TEST(Unit_Tlv_Tree, SkipDoesNotDecodeMalformedDescendants) {
    const uint8_t     data[] = {0x80, 1, 0xFF, 1, 0};
    tlv_tree_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_tree_reader_init(&reader, data, sizeof(data), &format, nullptr, 0, 0, 2));
    tlv_tree_item_t item{};
    EXPECT_EQ(TLV_ERR_INVALID_STATE, tlv_tree_reader_skip_subtree(&reader));
    ASSERT_EQ(TLV_OK, tlv_tree_reader_next(&reader, &item));
    ASSERT_EQ(TLV_OK, tlv_tree_reader_skip_subtree(&reader));
    EXPECT_EQ(TLV_ERR_INVALID_STATE, tlv_tree_reader_skip_subtree(&reader));
    ASSERT_EQ(TLV_OK, tlv_tree_reader_next(&reader, &item));
    EXPECT_EQ(3u, item.offset);
}

TEST(Unit_Tlv_Tree, CountLimitsAreGlobalAndZeroPermitsEmptyInputOnly) {
    const uint8_t     data[] = {0x80, 2, 1, 0, 2, 0};
    tlv_tree_frame_t  frame;
    tlv_tree_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_tree_reader_init(&reader, data, sizeof(data), &format, &frame, 1, 1, 2));
    tlv_tree_item_t item{};
    ASSERT_EQ(TLV_OK, tlv_tree_reader_next(&reader, &item));
    ASSERT_EQ(TLV_OK, tlv_tree_reader_next(&reader, &item));
    EXPECT_EQ(TLV_ERR_LIMIT, tlv_tree_reader_next(&reader, &item));
    EXPECT_EQ(4u, tlv_tree_reader_offset(&reader));
    ASSERT_EQ(TLV_OK, tlv_tree_reader_init(&reader, nullptr, 0, &format, nullptr, 0, 0, 0));
    EXPECT_EQ(TLV_ERR_END_OF_BUFFER, tlv_tree_reader_next(&reader, &item));
    ASSERT_EQ(TLV_OK, tlv_tree_reader_init(&reader, data, sizeof(data), &format, nullptr, 0, 0, 0));
    EXPECT_EQ(TLV_ERR_LIMIT, tlv_tree_reader_next(&reader, &item));
}

TEST(Unit_Tlv_Tree, EveryParentSplitWaitsWithoutPublishingOrTouchingFrames) {
    const uint8_t data[] = {0x80, 4, 1, 0, 2, 0};
    for (size_t split = 0; split < sizeof(data); ++split) {
        tlv_tree_frame_t  frame{99, 98};
        tlv_tree_reader_t reader;
        ASSERT_EQ(TLV_OK,
                  tlv_tree_reader_init_incremental(&reader, data, split, &format, &frame, 1, 1, 3));
        tlv_tree_item_t item{};
        item.offset = 999;
        for (int i = 0; i < 2; ++i) {
            EXPECT_EQ(TLV_NEED_MORE_DATA, tlv_tree_reader_next(&reader, &item));
            EXPECT_EQ(999u, item.offset);
            EXPECT_EQ(0u, reader.count);
            EXPECT_EQ(0u, tlv_tree_reader_consumed(&reader));
            EXPECT_EQ(99u, frame.end);
        }
        ASSERT_EQ(TLV_OK, tlv_tree_reader_set_input(&reader, data, sizeof(data), 0, 1));
        for (size_t offset : {size_t(0), size_t(2), size_t(4)}) {
            ASSERT_EQ(TLV_OK, tlv_tree_reader_next(&reader, &item));
            EXPECT_EQ(offset, item.offset);
        }
        EXPECT_TRUE(tlv_tree_reader_at_end(&reader));
    }
}

TEST(Unit_Tlv_Tree, RelocationWhileNestedRetainsOnlyStructuralOffsets) {
    const uint8_t     data[] = {0x80, 6, 1, 0, 0x80, 2, 2, 0, 3};
    tlv_tree_frame_t  frames[2];
    tlv_tree_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_tree_reader_init_incremental(&reader, data, sizeof(data), &format, frames,
                                                       2, 2, 5));
    tlv_tree_item_t item{};
    ASSERT_EQ(TLV_OK, tlv_tree_reader_next(&reader, &item));
    // Parent output is no longer used; discard its header and relocate descendants.
    const uint8_t second[] = {1, 0, 0x80, 2, 2, 0, 3};
    ASSERT_EQ(TLV_OK, tlv_tree_reader_set_input(&reader, second, sizeof(second), 2, 0));
    ASSERT_EQ(TLV_OK, tlv_tree_reader_next(&reader, &item));
    EXPECT_EQ(2u, item.offset);
    EXPECT_EQ(second, item.source.data);
    ASSERT_EQ(TLV_OK, tlv_tree_reader_next(&reader, &item));
    const uint8_t third[] = {2, 0, 3, 0};
    ASSERT_EQ(TLV_OK, tlv_tree_reader_set_input(&reader, third, 3, 4, 0));
    ASSERT_EQ(TLV_OK, tlv_tree_reader_next(&reader, &item));
    EXPECT_EQ(6u, item.offset);
    EXPECT_EQ(2u, item.depth);
    tlv_reader_diagnostic_t diagnostic{};
    EXPECT_EQ(
        TLV_NEED_MORE_DATA,
        TLV_DIAGNOSTIC_RESULT(diagnostic, tlv_tree_reader_next_diag(&reader, &item, &diagnostic)));
    EXPECT_EQ(9u, diagnostic.diagnostic.offset);
    EXPECT_EQ(8u, tlv_tree_reader_offset(&reader));
    ASSERT_EQ(TLV_OK, tlv_tree_reader_set_input(&reader, third, 4, 0, 1));
    ASSERT_EQ(TLV_OK, tlv_tree_reader_next(&reader, &item));
    EXPECT_EQ(0u, item.depth);
    EXPECT_EQ(8u, item.offset);
    EXPECT_TRUE(tlv_tree_reader_at_end(&reader));
}

TEST(Unit_Tlv_Tree, ChildErrorsCannotBorrowBytesOutsideTheParent) {
    const uint8_t     data[] = {0x80, 3, 1, 2, 0xAA, 2, 0};
    tlv_tree_frame_t  frame{99, 98};
    tlv_tree_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_tree_reader_init_incremental(&reader, data, sizeof(data), &format, &frame,
                                                       1, 1, 10));
    tlv_tree_item_t item{};
    ASSERT_EQ(TLV_OK, tlv_tree_reader_next(&reader, &item));
    // The parent's header can be discarded; the active bound remains absolute.
    const uint8_t relocated[] = {1, 2, 0xAA, 2, 0};
    ASSERT_EQ(TLV_OK, tlv_tree_reader_set_input(&reader, relocated, sizeof(relocated), 2, 0));
    tlv_reader_diagnostic_t diagnostic{};
    for (int i = 0; i < 2; ++i) {
        EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
                  TLV_DIAGNOSTIC_RESULT(diagnostic,
                                        tlv_tree_reader_next_diag(&reader, &item, &diagnostic)));
        EXPECT_EQ(4u, diagnostic.diagnostic.offset);
        EXPECT_EQ(5u, diagnostic.enclosing_end);
        EXPECT_EQ(2u, diagnostic.required);
        EXPECT_EQ(1u, diagnostic.available);
        EXPECT_EQ(1u, reader.count);
        EXPECT_EQ(0u, reader.depth);
        EXPECT_EQ(99u, frame.end);
        EXPECT_EQ(0u, item.offset);
    }
    ASSERT_EQ(TLV_OK, tlv_tree_reader_skip_subtree(&reader));
    ASSERT_EQ(TLV_OK, tlv_tree_reader_next(&reader, &item));
    EXPECT_EQ(5u, item.offset);
}

TEST(Unit_Tlv_Tree, FinalityAndInvalidUpdatesPreserveTraversal) {
    const uint8_t     data[] = {0x80, 2, 1};
    tlv_tree_frame_t  frame;
    tlv_tree_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_tree_reader_init_incremental(&reader, data, sizeof(data), &format, &frame,
                                                       1, 1, 10));
    tlv_tree_item_t item{};
    EXPECT_EQ(TLV_NEED_MORE_DATA, tlv_tree_reader_next(&reader, &item));
    const auto before = reader;
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_tree_reader_set_input(&reader, data + 1, 2, 1, 0));
    EXPECT_EQ(before.input.data, reader.input.data);
    EXPECT_EQ(before.input.size, reader.input.size);
    EXPECT_EQ(before.count, reader.count);
    ASSERT_EQ(TLV_OK, tlv_tree_reader_set_input(&reader, data, sizeof(data), 0, 1));
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_tree_reader_next(&reader, &item));
    EXPECT_EQ(TLV_ERR_INVALID_STATE, tlv_tree_reader_set_input(&reader, data, sizeof(data), 0, 0));
    ASSERT_EQ(TLV_OK,
              tlv_tree_reader_init_incremental(&reader, nullptr, 0, &format, nullptr, 0, 0, 0));
    EXPECT_FALSE(tlv_tree_reader_at_end(&reader));
    EXPECT_EQ(TLV_NEED_MORE_DATA, tlv_tree_reader_next(&reader, &item));
    ASSERT_EQ(TLV_OK, tlv_tree_reader_set_input(&reader, nullptr, 0, 0, 1));
    EXPECT_TRUE(tlv_tree_reader_at_end(&reader));
    EXPECT_EQ(TLV_ERR_END_OF_BUFFER, tlv_tree_reader_next(&reader, &item));
}

TEST(Unit_Tlv_Tree, NullArgumentsAndFailedInitializationDoNotPublish) {
    tlv_tree_reader_t reader{};
    reader.count = 999;
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              tlv_tree_reader_init(&reader, nullptr, 0, &format, nullptr, 1, 1, 1));
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              tlv_tree_reader_init(&reader, nullptr, 1, &format, nullptr, 0, 0, 1));
    EXPECT_EQ(999u, reader.count);
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              tlv_tree_reader_init(nullptr, nullptr, 0, &format, nullptr, 0, 0, 1));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_tree_reader_next(nullptr, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_tree_reader_next(&reader, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_tree_reader_set_input(nullptr, nullptr, 0, 0, 0));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_tree_reader_skip_subtree(nullptr));
    EXPECT_EQ(0u, tlv_tree_reader_consumed(nullptr));
    EXPECT_EQ(0u, tlv_tree_reader_offset(nullptr));
    EXPECT_FALSE(tlv_tree_reader_at_end(nullptr));
}

TEST(Unit_Tlv_Tree, OpaqueFormatDoesNotInspectValuesAndPropagatesCallbackErrors) {
    const uint8_t     data[] = {0x80, 1, 0xFF};
    tlv_tree_reader_t reader;
    tlv_tree_item_t   item{};
    ASSERT_EQ(TLV_OK, tlv_tree_reader_init(&reader, data, sizeof(data), &controlled::format,
                                           nullptr, 0, 0, 1));
    ASSERT_EQ(TLV_OK, tlv_tree_reader_next(&reader, &item));
    EXPECT_FALSE(item.constructed);
    EXPECT_TRUE(tlv_tree_reader_at_end(&reader));
    auto bad = format;
    bad.decode = [](const void*, const uint8_t*, size_t, tlv_decoded_t*, tlv_format_error_t*) {
        return TLV_ERR_END_OF_BUFFER;
    };
    ASSERT_EQ(TLV_OK, tlv_tree_reader_init_incremental(&reader, data, sizeof(data), &bad, nullptr,
                                                       0, 0, 1));
    EXPECT_EQ(TLV_ERR_END_OF_BUFFER, tlv_tree_reader_next(&reader, &item));
    EXPECT_FALSE(tlv_tree_reader_at_end(&reader));
    EXPECT_EQ(0u, reader.count);
}

TEST(Unit_Tlv_Tree, CanonicalEventsRoundTripAndCloseBeforeNeedMore) {
    const uint8_t     data[] = {0xE1, 6, 1, 0, 0xE2, 2, 2, 0, 0xE3, 0};
    tlv_tree_frame_t  frames[2];
    tlv_tree_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_tree_reader_init_incremental(&reader, data, sizeof(data), &format, frames,
                                                       2, 2, 5));
    uint8_t                 output[32], scratch[32], tags[2];
    tlv_tree_writer_frame_t output_frames[2];
    tlv_tree_writer_t       writer;
    ASSERT_EQ(TLV_OK, tlv_tree_writer_init(&writer, output, sizeof(output), &format, output_frames,
                                           2, scratch, sizeof(scratch), 2, 5));
    ASSERT_EQ(TLV_OK, tlv_tree_writer_set_tag_storage(&writer, tags, sizeof(tags)));
    const tlv_tree_event_kind_t kinds[] = {TLV_TREE_BEGIN,   TLV_TREE_ELEMENT, TLV_TREE_BEGIN,
                                           TLV_TREE_ELEMENT, TLV_TREE_END,     TLV_TREE_END,
                                           TLV_TREE_BEGIN,   TLV_TREE_END};
    const size_t                depths[] = {0, 1, 1, 2, 1, 0, 0, 0};
    tlv_tree_event_t            event{};
    for (size_t i = 0; i < 8; ++i) {
        ASSERT_EQ(TLV_OK, tlv_tree_reader_next_event(&reader, &event));
        EXPECT_EQ(kinds[i], event.kind);
        EXPECT_EQ(depths[i], event.depth);
        if (event.kind == TLV_TREE_END) {
            EXPECT_EQ(nullptr, event.element.tag.data);
            EXPECT_EQ(nullptr, event.source.data);
        }
        ASSERT_EQ(TLV_OK, tlv_tree_writer_write_event(&writer, &event));
    }
    EXPECT_EQ(5u, reader.count);
    EXPECT_EQ(0u, writer.tags_used);
    EXPECT_EQ(TLV_OK, tlv_tree_writer_finish(&writer));
    ASSERT_EQ(sizeof(data), tlv_tree_writer_size(&writer));
    EXPECT_EQ(0, std::memcmp(data, output, sizeof(data)));
    const auto before = reader;
    for (int i = 0; i < 2; ++i) {
        EXPECT_EQ(TLV_NEED_MORE_DATA, tlv_tree_reader_next_event(&reader, &event));
        EXPECT_EQ(TLV_TREE_END, event.kind);
        EXPECT_EQ(before.input.pos, reader.input.pos);
        EXPECT_EQ(before.depth, reader.depth);
    }
    ASSERT_EQ(TLV_OK, tlv_tree_reader_set_input(&reader, nullptr, 0, sizeof(data), 1));
    EXPECT_EQ(TLV_ERR_END_OF_BUFFER, tlv_tree_reader_next_event(&reader, &event));
}

TEST(Unit_Tlv_Tree, EventSkipIsBalancedAndWriterRejectsOmittedContent) {
    const uint8_t     data[] = {0xE1, 1, 0xFF};
    tlv_tree_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_tree_reader_init(&reader, data, sizeof(data), &format, nullptr, 0, 0, 1));
    tlv_tree_event_t event{};
    ASSERT_EQ(TLV_OK, tlv_tree_reader_next_event(&reader, &event));
    EXPECT_EQ(TLV_ERR_LIMIT, tlv_tree_reader_next_event(&reader, &event));
    ASSERT_EQ(TLV_OK, tlv_tree_reader_skip_subtree(&reader));
    EXPECT_FALSE(tlv_tree_reader_at_end(&reader));
    ASSERT_EQ(TLV_OK, tlv_tree_reader_next_event(&reader, &event));
    EXPECT_EQ(TLV_TREE_END, event.kind);
    EXPECT_TRUE(event.skipped);
    EXPECT_TRUE(tlv_tree_reader_at_end(&reader));
    uint8_t                 output[8], scratch[8];
    tlv_tree_writer_frame_t frame;
    tlv_tree_writer_t       writer;
    ASSERT_EQ(TLV_OK,
              tlv_tree_writer_init(&writer, output, 8, &format, &frame, 1, scratch, 8, 1, 1));
    ASSERT_EQ(TLV_OK, tlv_tree_writer_begin(&writer, tlv_tag(data, 1)));
    EXPECT_EQ(TLV_ERR_INVALID_VALUE, tlv_tree_writer_write_event(&writer, &event));
    EXPECT_EQ(1u, writer.depth);
}

TEST(Unit_Tlv_Tree, EventPipelineCanDiscardAndOverwriteParentTags) {
    uint8_t           data[] = {0xE1, 4, 0xE2, 2, 1, 0};
    tlv_tree_frame_t  frames[2];
    tlv_tree_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_tree_reader_init_incremental(&reader, data, sizeof(data), &format, frames,
                                                       2, 2, 3));
    uint8_t                 output[16], scratch[16], tags[2];
    tlv_tree_writer_frame_t output_frames[2];
    tlv_tree_writer_t       writer;
    ASSERT_EQ(TLV_OK, tlv_tree_writer_init(&writer, output, 16, &format, output_frames, 2, scratch,
                                           16, 2, 3));
    ASSERT_EQ(TLV_OK, tlv_tree_writer_set_tag_storage(&writer, tags, 2));
    tlv_tree_event_t event{};
    ASSERT_EQ(TLV_OK, tlv_tree_reader_next_event(&reader, &event));
    ASSERT_EQ(TLV_OK, tlv_tree_writer_write_event(&writer, &event));
    const uint8_t remaining[] = {0xE2, 2, 1, 0};
    ASSERT_EQ(TLV_OK, tlv_tree_reader_set_input(&reader, remaining, 4, 2, 1));
    std::memset(data, 0xFF, sizeof(data));
    while (!tlv_tree_reader_at_end(&reader)) {
        ASSERT_EQ(TLV_OK, tlv_tree_reader_next_event(&reader, &event));
        ASSERT_EQ(TLV_OK, tlv_tree_writer_write_event(&writer, &event));
    }
    const uint8_t expected[] = {0xE1, 4, 0xE2, 2, 1, 0};
    ASSERT_EQ(sizeof(expected), tlv_tree_writer_size(&writer));
    EXPECT_EQ(0, std::memcmp(expected, output, sizeof(expected)));
}

TEST(Unit_Tlv_Tree, EventWriterRejectsDepthAndSupportsRetryAfterTagLimit) {
    uint8_t                 output[16], scratch[16], tag_storage[1];
    const uint8_t           tag[] = {0xE1};
    tlv_tree_writer_frame_t frame;
    tlv_tree_writer_t       writer;
    ASSERT_EQ(TLV_OK,
              tlv_tree_writer_init(&writer, output, 16, &format, &frame, 1, scratch, 16, 1, 1));
    tlv_tree_event_t event{};
    event.kind = TLV_TREE_BEGIN;
    event.element.tag = tlv_tag(tag, 1);
    event.depth = 1;
    EXPECT_EQ(TLV_ERR_INVALID_VALUE, tlv_tree_writer_write_event(&writer, &event));
    event.depth = 0;
    ASSERT_EQ(TLV_OK, tlv_tree_writer_set_tag_storage(&writer, tag_storage, 0));
    EXPECT_EQ(TLV_ERR_LIMIT, tlv_tree_writer_write_event(&writer, &event));
    EXPECT_EQ(0u, writer.count);
    ASSERT_EQ(TLV_OK, tlv_tree_writer_set_tag_storage(&writer, tag_storage, 1));
    ASSERT_EQ(TLV_OK, tlv_tree_writer_write_event(&writer, &event));
    EXPECT_EQ(TLV_ERR_INVALID_STATE, tlv_tree_writer_set_tag_storage(&writer, nullptr, 0));
    event = {};
    event.kind = TLV_TREE_END;
    ASSERT_EQ(TLV_OK, tlv_tree_writer_write_event(&writer, &event));
    EXPECT_EQ(TLV_ERR_INVALID_VALUE, tlv_tree_writer_write_event(&writer, &event));
    EXPECT_EQ(0u, writer.tags_used);
}

TEST(Unit_Tlv_Tree, EventSplitsAreTransactionalAndEmptyContainersNeedNoFrame) {
    const uint8_t data[] = {0xE1, 2, 0xE2, 0};
    for (size_t split = 0; split < sizeof(data); ++split) {
        tlv_tree_frame_t  frame{99, 98};
        tlv_tree_reader_t reader;
        ASSERT_EQ(TLV_OK,
                  tlv_tree_reader_init_incremental(&reader, data, split, &format, &frame, 1, 1, 2));
        tlv_tree_event_t event{};
        event.offset = 999;
        EXPECT_EQ(TLV_NEED_MORE_DATA, tlv_tree_reader_next_event(&reader, &event));
        EXPECT_EQ(999u, event.offset);
        EXPECT_EQ(99u, frame.end);
        EXPECT_EQ(0u, reader.count);
        ASSERT_EQ(TLV_OK, tlv_tree_reader_set_input(&reader, data, sizeof(data), 0, 1));
        for (auto kind : {TLV_TREE_BEGIN, TLV_TREE_BEGIN, TLV_TREE_END, TLV_TREE_END}) {
            ASSERT_EQ(TLV_OK, tlv_tree_reader_next_event(&reader, &event));
            EXPECT_EQ(kind, event.kind);
        }
        EXPECT_TRUE(tlv_tree_reader_at_end(&reader));
    }
    tlv_tree_reader_t reader;
    tlv_tree_event_t  event{};
    ASSERT_EQ(TLV_OK, tlv_tree_reader_init(&reader, data + 2, 2, &format, nullptr, 0, 0, 1));
    ASSERT_EQ(TLV_OK, tlv_tree_reader_next_event(&reader, &event));
    EXPECT_EQ(TLV_TREE_BEGIN, event.kind);
    EXPECT_EQ(TLV_ERR_INVALID_STATE, tlv_tree_reader_skip_subtree(&reader));
    ASSERT_EQ(TLV_OK, tlv_tree_reader_next_event(&reader, &event));
    EXPECT_EQ(TLV_TREE_END, event.kind);
    EXPECT_FALSE(event.skipped);
}
