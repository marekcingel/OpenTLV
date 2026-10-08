// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "../../diagnostic_assertions.h"
#include "controlled_format.h"
#include "tlv/writer/tree.h"
#include <gtest/gtest.h>
#include <cstring>
#include <vector>

namespace {
int constructed(const void*, const tlv_tag_t* tag) {
    return tag->size == 1 && tag->data && tag->data[0] >= 0x80;
}
const tlv_format_t  format = {&controlled::format_layout, tlv_fields_decode, tlv_fields_measure,
                              tlv_fields_encode, constructed};
const uint8_t       parent_tag[] = {0xE1}, child_tag[] = {1}, inner_tag[] = {0xE2};
const tlv_tag_t     parent = tlv_tag(parent_tag, 1), inner = tlv_tag(inner_tag, 1);
const tlv_element_t leaf = {tlv_tag(child_tag, 1), {nullptr, 0}};

tlv_result_t content_measure(const void* context, const tlv_element_t* element,
                             tlv_encoding_t* encoding, tlv_format_error_t* error) {
    if (element->value.size && !element->value.data) return TLV_ERR_NULL_ARG;
    const auto rc = tlv_fields_measure(context, element, encoding, error);
    if (rc != TLV_OK) return rc;
    const bool extra = element->value.size && element->value.data[0] == 1;
    encoding->header += extra ? 1 : 0;
    encoding->trailer = 1;
    encoding->total += extra ? 2 : 1;
    return TLV_OK;
}

tlv_result_t content_encode(const void* context, const tlv_element_t* element, uint8_t* data,
                            size_t capacity, size_t* written, tlv_format_error_t* error) {
    const size_t extra = element->value.size && element->value.data[0] == 1 ? 1 : 0;
    if (extra) data[0] = 0xFE;
    size_t     used = 0;
    const auto rc =
        tlv_fields_encode(context, element, data + extra, capacity - extra - 1, &used, error);
    if (rc != TLV_OK) return rc;
    data[extra + used] = 0xFF;
    *written = extra + used + 1;
    return TLV_OK;
}

// Immutable policy selects an encoder that damages its entire supplied region
// before reporting a field failure. Leaves still encode normally.
tlv_result_t fail_parent(const void* context, const tlv_element_t* element, uint8_t* data,
                         size_t capacity, size_t* written, tlv_format_error_t* error) {
    if (element->tag.data[0] >= 0x80) {
        std::memset(data, 0xCC, capacity);
        error->region = TLV_REGION_LENGTH;
        error->has_offset = 1;
        error->offset = 1;
        return TLV_ERR_INVALID_LENGTH;
    }
    return tlv_fields_encode(context, element, data, capacity, written, error);
}
} // namespace

TEST(Unit_Tlv_TreeWriter, NestedAndSequentialOutputPublishesOnlyClosedRoots) {
    uint8_t                 data[32]{}, scratch[32]{};
    tlv_tree_writer_frame_t frames[2]{};
    tlv_tree_writer_t       writer{};
    ASSERT_EQ(TLV_OK, tlv_tree_writer_init(&writer, data, sizeof(data), &format, frames, 2, scratch,
                                           sizeof(scratch), 2, 5));
    ASSERT_EQ(TLV_OK, tlv_tree_writer_write_element(&writer, &leaf));
    ASSERT_EQ(TLV_OK, tlv_tree_writer_begin(&writer, parent));
    ASSERT_EQ(TLV_OK, tlv_tree_writer_write_element(&writer, &leaf));
    ASSERT_EQ(TLV_OK, tlv_tree_writer_begin(&writer, inner));
    ASSERT_EQ(TLV_OK, tlv_tree_writer_write_element(&writer, &leaf));
    EXPECT_EQ(2u, tlv_tree_writer_size(&writer));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_tree_writer_finish(&writer));
    ASSERT_EQ(TLV_OK, tlv_tree_writer_end(&writer));
    EXPECT_EQ(2u, tlv_tree_writer_size(&writer));
    ASSERT_EQ(TLV_OK, tlv_tree_writer_end(&writer));
    EXPECT_EQ(TLV_OK, tlv_tree_writer_finish(&writer));
    const uint8_t expected[] = {1, 0, 0xE1, 6, 1, 0, 0xE2, 2, 1, 0};
    ASSERT_EQ(sizeof(expected), tlv_tree_writer_size(&writer));
    EXPECT_EQ(0, std::memcmp(data, expected, sizeof(expected)));
    EXPECT_EQ(5u, writer.count);
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_tree_writer_end(&writer));
}

TEST(Unit_Tlv_TreeWriter, LimitsAndEmptyParentsHaveDeterministicState) {
    uint8_t                 data[8]{};
    tlv_tree_writer_frame_t frames[1]{};
    tlv_tree_writer_t       writer{};
    ASSERT_EQ(TLV_OK, tlv_tree_writer_init(&writer, data, sizeof(data), &format, frames, 1, nullptr,
                                           0, 0, 1));
    EXPECT_EQ(TLV_ERR_INVALID_TAG, tlv_tree_writer_begin(&writer, leaf.tag));
    ASSERT_EQ(TLV_OK, tlv_tree_writer_begin(&writer, parent));
    for (int i = 0; i < 2; ++i) {
        EXPECT_EQ(TLV_ERR_LIMIT, tlv_tree_writer_begin(&writer, parent));
        EXPECT_EQ(TLV_ERR_LIMIT, tlv_tree_writer_write_element(&writer, &leaf));
        EXPECT_EQ(1u, writer.depth);
        EXPECT_EQ(1u, writer.count);
        EXPECT_EQ(0u, writer.output.pos);
    }
    ASSERT_EQ(TLV_OK, tlv_tree_writer_end(&writer));
    EXPECT_EQ(0xE1, data[0]);
    EXPECT_EQ(0, data[1]);
    EXPECT_EQ(TLV_ERR_LIMIT, tlv_tree_writer_write_element(&writer, &leaf));
    ASSERT_EQ(TLV_OK, tlv_tree_writer_init(&writer, data, sizeof(data), &format, nullptr, 0,
                                           nullptr, 0, 100, SIZE_MAX));
    EXPECT_EQ(TLV_ERR_LIMIT, tlv_tree_writer_begin(&writer, parent));
    EXPECT_EQ(TLV_OK, tlv_tree_writer_write_element(&writer, &leaf));
    ASSERT_EQ(TLV_OK, tlv_tree_writer_init(&writer, data, sizeof(data), &format, frames, 1, nullptr,
                                           0, 0, SIZE_MAX));
    ASSERT_EQ(TLV_OK, tlv_tree_writer_begin(&writer, parent));
    EXPECT_EQ(TLV_ERR_LIMIT, tlv_tree_writer_write_element(&writer, &leaf));
    EXPECT_EQ(TLV_OK, tlv_tree_writer_end(&writer));
}

TEST(Unit_Tlv_TreeWriter, ScratchAndOutputShortagesPreserveAccumulatedBytes) {
    for (bool small_scratch : {false, true}) {
        uint8_t                 data[4]{}, scratch[2]{};
        tlv_tree_writer_frame_t frames[1]{};
        tlv_tree_writer_t       writer{};
        ASSERT_EQ(TLV_OK,
                  tlv_tree_writer_init(&writer, data, small_scratch ? 4 : 3, &format, frames, 1,
                                       scratch, small_scratch ? 1 : 2, 1, SIZE_MAX));
        ASSERT_EQ(TLV_OK, tlv_tree_writer_begin(&writer, parent));
        ASSERT_EQ(TLV_OK, tlv_tree_writer_write_element(&writer, &leaf));
        for (int i = 0; i < 2; ++i) {
            tlv_writer_diagnostic_t diagnostic{};
            EXPECT_EQ(
                TLV_ERR_BUFFER_TOO_SHORT,
                TLV_DIAGNOSTIC_RESULT(diagnostic, tlv_tree_writer_end_diag(&writer, &diagnostic)));
            EXPECT_EQ(1u, writer.depth);
            EXPECT_EQ(2u, writer.output.pos);
            EXPECT_EQ(1, data[0]);
            EXPECT_EQ(0, data[1]);
            EXPECT_TRUE(diagnostic.has_required);
            EXPECT_EQ(small_scratch ? 2u : 4u, diagnostic.required);
            EXPECT_EQ(small_scratch ? TLV_WRITER_OP_END : TLV_WRITER_OP_VALUE,
                      diagnostic.operation);
        }
    }
}

TEST(Unit_Tlv_TreeWriter, EncoderFailureRestoresValueAndPreservesFinalPrefix) {
    const tlv_format_t failing = {&controlled::format_layout, tlv_fields_decode, tlv_fields_measure,
                                  fail_parent, constructed};
    uint8_t            data[32]{}, scratch[32]{};
    tlv_tree_writer_frame_t frames[1]{};
    tlv_tree_writer_t       writer{};
    ASSERT_EQ(TLV_OK, tlv_tree_writer_init(&writer, data, sizeof(data), &failing, frames, 1,
                                           scratch, sizeof(scratch), 1, SIZE_MAX));
    ASSERT_EQ(TLV_OK, tlv_tree_writer_write_element(&writer, &leaf));
    ASSERT_EQ(TLV_OK, tlv_tree_writer_begin(&writer, parent));
    ASSERT_EQ(TLV_OK, tlv_tree_writer_write_element(&writer, &leaf));
    for (int i = 0; i < 2; ++i) {
        tlv_writer_diagnostic_t diagnostic{};
        EXPECT_EQ(
            TLV_ERR_INVALID_LENGTH,
            TLV_DIAGNOSTIC_RESULT(diagnostic, tlv_tree_writer_end_diag(&writer, &diagnostic)));
        EXPECT_EQ(TLV_WRITER_OP_LENGTH, diagnostic.operation);
        EXPECT_EQ(3u, diagnostic.diagnostic.offset);
        EXPECT_EQ(1u, writer.depth);
        EXPECT_EQ(4u, writer.output.pos);
        EXPECT_EQ(2u, tlv_tree_writer_size(&writer));
        const uint8_t expected[] = {1, 0, 1, 0};
        EXPECT_EQ(0, std::memcmp(data, expected, sizeof(expected)));
    }
    // Rollback leaves the parent usable, even after destructive callback failure.
    EXPECT_EQ(TLV_OK, tlv_tree_writer_write_element(&writer, &leaf));
    EXPECT_EQ(6u, writer.output.pos);
}

TEST(Unit_Tlv_TreeWriter, RuntimeDepthCanExceedDefault) {
    const size_t                         depth = TLV_TREE_DEFAULT_DEPTH + 16;
    std::vector<tlv_tree_writer_frame_t> frames(depth);
    uint8_t                              data[256]{}, scratch[256]{};
    tlv_tree_writer_t                    writer{};
    ASSERT_EQ(TLV_OK,
              tlv_tree_writer_init(&writer, data, sizeof(data), &format, frames.data(),
                                   frames.size(), scratch, sizeof(scratch), depth, SIZE_MAX));
    for (size_t i = 0; i < depth; ++i) ASSERT_EQ(TLV_OK, tlv_tree_writer_begin(&writer, parent));
    for (size_t i = 0; i < depth; ++i) ASSERT_EQ(TLV_OK, tlv_tree_writer_end(&writer));
    EXPECT_EQ(depth * 2, tlv_tree_writer_size(&writer));
    EXPECT_EQ(TLV_OK, tlv_tree_writer_finish(&writer));
}

TEST(Unit_Tlv_TreeWriter, NullAndZeroCapacityContracts) {
    tlv_tree_writer_t writer{};
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              tlv_tree_writer_init(nullptr, nullptr, 0, &format, nullptr, 0, nullptr, 0, 0, 0));
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              tlv_tree_writer_init(&writer, nullptr, 1, &format, nullptr, 0, nullptr, 0, 0, 0));
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              tlv_tree_writer_init(&writer, nullptr, 0, &format, nullptr, 1, nullptr, 0, 0, 0));
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              tlv_tree_writer_init(&writer, nullptr, 0, &format, nullptr, 0, nullptr, 1, 0, 0));
    ASSERT_EQ(TLV_OK, tlv_tree_writer_init(&writer, nullptr, 0, &format, nullptr, 0, nullptr, 0, 0,
                                           SIZE_MAX));
    EXPECT_EQ(TLV_OK, tlv_tree_writer_finish(&writer));
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_tree_writer_write_element(&writer, &leaf));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_tree_writer_write_element(&writer, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_tree_writer_begin(nullptr, parent));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_tree_writer_begin(&writer, tlv_tag(nullptr, 1)));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_tree_writer_write_element(nullptr, &leaf));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_tree_writer_end(nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_tree_writer_finish(nullptr));
    EXPECT_EQ(0u, tlv_tree_writer_size(nullptr));
}

TEST(Unit_Tlv_TreeWriter, ContentDependentHeadersAndTrailersUseReadableValue) {
    const tlv_format_t      content = {&controlled::format_layout, nullptr, content_measure,
                                       content_encode, constructed};
    uint8_t                 data[16]{}, scratch[16]{};
    tlv_tree_writer_frame_t frame{};
    tlv_tree_writer_t       writer{};
    ASSERT_EQ(TLV_OK, tlv_tree_writer_init(&writer, data, sizeof(data), &content, &frame, 1,
                                           scratch, sizeof(scratch), 1, SIZE_MAX));
    ASSERT_EQ(TLV_OK, tlv_tree_writer_begin(&writer, parent));
    ASSERT_EQ(TLV_OK, tlv_tree_writer_write_element(&writer, &leaf));
    ASSERT_EQ(TLV_OK, tlv_tree_writer_end(&writer));
    const uint8_t expected[] = {0xFE, 0xE1, 3, 1, 0, 0xFF, 0xFF};
    EXPECT_EQ(sizeof(expected), tlv_tree_writer_size(&writer));
    EXPECT_EQ(0, std::memcmp(data, expected, sizeof(expected)));
}

TEST(Unit_Tlv_TreeWriter, ParentMeasureFailureDoesNotLoseChildren) {
    uint8_t                 data[512]{}, scratch[512]{};
    tlv_tree_writer_frame_t frame{};
    tlv_tree_writer_t       writer{};
    ASSERT_EQ(TLV_OK, tlv_tree_writer_init(&writer, data, sizeof(data), &format, &frame, 1, scratch,
                                           sizeof(scratch), 1, SIZE_MAX));
    ASSERT_EQ(TLV_OK, tlv_tree_writer_begin(&writer, parent));
    for (int i = 0; i < 128; ++i) ASSERT_EQ(TLV_OK, tlv_tree_writer_write_element(&writer, &leaf));
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_tree_writer_end(&writer));
    EXPECT_EQ(1u, writer.depth);
    EXPECT_EQ(256u, writer.output.pos);
    for (size_t i = 0; i < 256; ++i) EXPECT_EQ(i % 2 == 0 ? 1 : 0, data[i]);
}

TEST(Unit_Tlv_TreeWriter, SuccessPreservesDiagnosticAndInitFailurePreservesCursor) {
    uint8_t                 data[8]{}, scratch[8]{};
    tlv_tree_writer_frame_t frame{};
    tlv_tree_writer_t       writer{};
    ASSERT_EQ(TLV_OK, tlv_tree_writer_init(&writer, data, sizeof(data), &format, &frame, 1, scratch,
                                           sizeof(scratch), 1, SIZE_MAX));
    tlv_writer_diagnostic_t diagnostic{};
    diagnostic.required = 123;
    ASSERT_EQ(TLV_OK, tlv_tree_writer_begin_diag(&writer, parent, &diagnostic));
    ASSERT_EQ(TLV_OK, tlv_tree_writer_write_element_diag(&writer, &leaf, &diagnostic));
    ASSERT_EQ(TLV_OK, tlv_tree_writer_end_diag(&writer, &diagnostic));
    EXPECT_EQ(123u, diagnostic.required);
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_tree_writer_init(&writer, data, sizeof(data), nullptr, &frame,
                                                     1, scratch, sizeof(scratch), 1, SIZE_MAX));
    EXPECT_EQ(4u, tlv_tree_writer_size(&writer));
    EXPECT_EQ(TLV_OK, tlv_tree_writer_finish(&writer));
}

TEST(Unit_Tlv_TreeWriter, LtvOrderingIsOwnedByFormat) {
    auto layout = controlled::format_layout;
    layout.element_order = TLV_ELEMENT_ORDER_LTV;
    const tlv_format_t ltv = {&layout, tlv_fields_decode, tlv_fields_measure, tlv_fields_encode,
                              constructed};
    uint8_t            data[4]{}, scratch[2]{};
    tlv_tree_writer_frame_t frame{};
    tlv_tree_writer_t       writer{};
    ASSERT_EQ(TLV_OK, tlv_tree_writer_init(&writer, data, sizeof(data), &ltv, &frame, 1, scratch,
                                           sizeof(scratch), 1, SIZE_MAX));
    ASSERT_EQ(TLV_OK, tlv_tree_writer_begin(&writer, parent));
    ASSERT_EQ(TLV_OK, tlv_tree_writer_write_element(&writer, &leaf));
    ASSERT_EQ(TLV_OK, tlv_tree_writer_end(&writer));
    const uint8_t expected[] = {2, 0xE1, 0, 1};
    EXPECT_EQ(0, std::memcmp(data, expected, sizeof(expected)));
}

TEST(Unit_Tlv_TreeWriter, AbsentTagAndNoNestingPredicateAreFormatDecisions) {
    const tlv_format_t tagless = {
        nullptr, nullptr,
        [](const void*, const tlv_element_t* element, tlv_encoding_t* sizes, tlv_format_error_t*) {
            if (element->tag.data || element->tag.size) return TLV_ERR_INVALID_TAG;
            if (element->value.size > 255) return TLV_ERR_INVALID_LENGTH;
            *sizes = {1, element->value.size, 0, 1 + element->value.size};
            return TLV_OK;
        },
        [](const void*, const tlv_element_t* element, uint8_t* data, size_t, size_t* written,
           tlv_format_error_t*) {
            data[0] = static_cast<uint8_t>(element->value.size);
            if (element->value.size)
                std::memcpy(data + 1, element->value.data,
                            static_cast<size_t>(element->value.size));
            *written = 1 + static_cast<size_t>(element->value.size);
            return TLV_OK;
        },
        [](const void*, const tlv_tag_t* tag) { return !tag->data && !tag->size ? 1 : 0; }};
    uint8_t                 data[4]{}, scratch[4]{};
    tlv_tree_writer_frame_t frame{};
    tlv_tree_writer_t       writer{};
    const tlv_element_t     absent = {{nullptr, 0}, {nullptr, 0}};
    ASSERT_EQ(TLV_OK, tlv_tree_writer_init(&writer, data, sizeof(data), &tagless, &frame, 1,
                                           scratch, sizeof(scratch), 1, SIZE_MAX));
    ASSERT_EQ(TLV_OK, tlv_tree_writer_begin(&writer, absent.tag));
    ASSERT_EQ(TLV_OK, tlv_tree_writer_write_element(&writer, &absent));
    ASSERT_EQ(TLV_OK, tlv_tree_writer_end(&writer));
    EXPECT_EQ(2u, tlv_tree_writer_size(&writer));
    EXPECT_EQ(1, data[0]);
    EXPECT_EQ(0, data[1]);
    ASSERT_EQ(TLV_OK, tlv_tree_writer_init(&writer, data, sizeof(data), &controlled::format, &frame,
                                           1, scratch, sizeof(scratch), 1, SIZE_MAX));
    EXPECT_EQ(TLV_ERR_INVALID_TAG, tlv_tree_writer_begin(&writer, parent));
    EXPECT_EQ(TLV_OK, tlv_tree_writer_write_element(&writer, &leaf));
}

namespace {
struct SourceItem {
    tlv_element_t element;
    size_t        depth;
    int           constructed;
};
struct Source {
    std::vector<SourceItem> items;
    size_t                  position = 0;
    static tlv_result_t next(void* context, tlv_element_t* element, size_t* depth, int* parent) {
        auto& source = *static_cast<Source*>(context);
        if (source.position == source.items.size()) return TLV_ERR_END_OF_BUFFER;
        const auto& item = source.items[source.position++];
        *element = item.element;
        *depth = item.depth;
        *parent = item.constructed;
        return TLV_OK;
    }
};
} // namespace

TEST(Unit_Tlv_TreeWriter, MeasurementClosesPreorderScopesAndStagesContentDependentBytes) {
    const tlv_format_t          content = {&controlled::format_layout, nullptr, content_measure,
                                           content_encode, constructed};
    Source                      source{{{leaf, 0, 0},
                                        {{parent, {}}, 0, 1},
                                        {{inner, {}}, 1, 1},
                                        {leaf, 2, 0},
                                        {{inner, {}}, 1, 1},
                                        {leaf, 0, 0}}};
    uint8_t                     data[64]{}, scratch[64]{};
    tlv_tree_writer_frame_t     frames[2]{};
    tlv_tree_writer_workspace_t workspace{frames,          2, data, sizeof(data), scratch,
                                          sizeof(scratch), 0, 0};
    size_t                      size = 99;
    tlv_writer_diagnostic_t     diagnostic{};
    diagnostic.operation = TLV_WRITER_OP_COPY;
    ASSERT_EQ(TLV_OK, tlv_tree_writer_measure(&content, Source::next, &source, &workspace, 2, 6,
                                              &size, &diagnostic));
    const std::vector<uint8_t> expected{1,    0,    0xFF, 0xE1, 10,   0xFE, 0xE2, 3, 1,   0,
                                        0xFF, 0xFF, 0xE2, 0,    0xFF, 0xFF, 1,    0, 0xFF};
    EXPECT_EQ(expected, std::vector<uint8_t>(data, data + size));
    EXPECT_EQ(TLV_WRITER_OP_COPY, diagnostic.operation);
    EXPECT_EQ(0u, workspace.required_data);
    EXPECT_EQ(0u, workspace.required_scratch);
}

TEST(Unit_Tlv_TreeWriter, MeasurementReportsOnlyItsOwnStorageShortagesForReplay) {
    Source                      source{{{{parent, {}}, 0, 1}, {leaf, 1, 0}}};
    uint8_t                     data[4]{}, scratch[2]{};
    tlv_tree_writer_frame_t     frame{};
    tlv_tree_writer_workspace_t workspace{&frame, 1, data, 2, scratch, 0, 0, 0};
    size_t                      size = 99;
    tlv_writer_diagnostic_t     diagnostic{};
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              TLV_DIAGNOSTIC_RESULT(diagnostic,
                                    tlv_tree_writer_measure(&format, Source::next, &source,
                                                            &workspace, 1, 2, &size, &diagnostic)));
    EXPECT_EQ(4u, workspace.required_data);
    EXPECT_EQ(2u, workspace.required_scratch);
    EXPECT_EQ(99u, size);
    EXPECT_EQ(TLV_WRITER_OP_END, diagnostic.operation);
    source.position = 0;
    workspace.data_capacity = 4;
    workspace.scratch_capacity = 2;
    ASSERT_EQ(TLV_OK, tlv_tree_writer_measure(&format, Source::next, &source, &workspace, 1, 2,
                                              &size, &diagnostic));
    EXPECT_EQ(4u, size);
    EXPECT_EQ(0u, workspace.required_data);
    EXPECT_EQ(0u, workspace.required_scratch);
    auto failing = format;
    failing.encode = [](const void*, const tlv_element_t*, uint8_t*, size_t, size_t*,
                        tlv_format_error_t*) { return TLV_ERR_BUFFER_TOO_SHORT; };
    source.position = 0;
    size = 99;
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              TLV_DIAGNOSTIC_RESULT(diagnostic,
                                    tlv_tree_writer_measure(&failing, Source::next, &source,
                                                            &workspace, 1, 2, &size, &diagnostic)));
    EXPECT_EQ(0u, workspace.required_data);
    EXPECT_EQ(0u, workspace.required_scratch);
    EXPECT_EQ(99u, size);
    failing.measure = [](const void*, const tlv_element_t*, tlv_encoding_t*, tlv_format_error_t*) {
        return TLV_ERR_BUFFER_TOO_SHORT;
    };
    source.position = 0;
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              TLV_DIAGNOSTIC_RESULT(diagnostic,
                                    tlv_tree_writer_measure(&failing, Source::next, &source,
                                                            &workspace, 1, 2, &size, &diagnostic)));
    EXPECT_EQ(0u, workspace.required_data);
    EXPECT_EQ(0u, workspace.required_scratch);
}

TEST(Unit_Tlv_TreeWriter, MeasurementRejectsInvalidTopologyAndRespectsBounds) {
    uint8_t                     data[16]{}, scratch[16]{};
    tlv_tree_writer_frame_t     frame{};
    tlv_tree_writer_workspace_t workspace{&frame, 1, data, 16, scratch, 16, 0, 0};
    size_t                      size = 99;
    Source                      bad_depth{{{leaf, 0, 0}, {leaf, 1, 0}}};
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_tree_writer_measure(&format, Source::next, &bad_depth,
                                                           &workspace, 2, 2, &size, nullptr));
    Source bad_kind{{{{parent, {}}, 0, 0}}};
    EXPECT_EQ(TLV_ERR_INVALID_TAG, tlv_tree_writer_measure(&format, Source::next, &bad_kind,
                                                           &workspace, 2, 2, &size, nullptr));
    for (int limit = 0; limit < 3; ++limit) {
        Source source{{{{parent, {}}, 0, 1}, {leaf, 1, 0}}};
        workspace.frame_capacity = limit == 0 ? 0 : 1;
        EXPECT_EQ(TLV_ERR_LIMIT,
                  tlv_tree_writer_measure(&format, Source::next, &source, &workspace,
                                          limit == 1 ? 0 : 1, limit == 2 ? 1 : 2, &size, nullptr));
        EXPECT_EQ(99u, size);
    }
    Source                      empty{};
    tlv_tree_writer_workspace_t zero{};
    EXPECT_EQ(TLV_OK,
              tlv_tree_writer_measure(&format, Source::next, &empty, &zero, 0, 0, &size, nullptr));
    EXPECT_EQ(0u, size);
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              tlv_tree_writer_measure(&format, nullptr, nullptr, &zero, 0, 0, &size, nullptr));
}

TEST(Unit_Tlv_TreeWriter, MeasurementKeepsAbsoluteDiagnosticsAndPropagatesSourceErrors) {
    uint8_t                     data[32]{}, scratch[32]{};
    tlv_tree_writer_frame_t     frame{};
    tlv_tree_writer_workspace_t workspace{&frame, 1, data, 32, scratch, 32, 0, 0};
    auto                        failing = format;
    failing.encode = fail_parent;
    Source                  source{{{leaf, 0, 0}, {{parent, {}}, 0, 1}, {leaf, 1, 0}}};
    size_t                  size = 99;
    tlv_writer_diagnostic_t diagnostic{};
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
              TLV_DIAGNOSTIC_RESULT(diagnostic,
                                    tlv_tree_writer_measure(&failing, Source::next, &source,
                                                            &workspace, 1, 3, &size, &diagnostic)));
    EXPECT_EQ(3u, diagnostic.diagnostic.offset);
    EXPECT_EQ(TLV_WRITER_OP_LENGTH, diagnostic.operation);
    EXPECT_EQ(99u, size);
    EXPECT_EQ(0u, workspace.required_data);
    failing.measure = [](const void* context, const tlv_element_t* element,
                         tlv_encoding_t* encoding, tlv_format_error_t* error) {
        if (element->tag.data[0] >= 0x80) {
            error->has_offset = 1;
            error->offset = 1;
            error->region = TLV_REGION_LENGTH;
            return TLV_ERR_INVALID_LENGTH;
        }
        return tlv_fields_measure(context, element, encoding, error);
    };
    source.position = 0;
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
              TLV_DIAGNOSTIC_RESULT(diagnostic,
                                    tlv_tree_writer_measure(&failing, Source::next, &source,
                                                            &workspace, 1, 3, &size, &diagnostic)));
    EXPECT_EQ(3u, diagnostic.diagnostic.offset);
    const auto fail_source = [](void*, tlv_element_t*, size_t*, int*) { return TLV_ERR_VISITOR; };
    EXPECT_EQ(TLV_ERR_VISITOR,
              TLV_DIAGNOSTIC_RESULT(diagnostic,
                                    tlv_tree_writer_measure(&format, fail_source, nullptr,
                                                            &workspace, 1, 3, &size, &diagnostic)));
    EXPECT_EQ(TLV_ERR_VISITOR, diagnostic.diagnostic.code);
}
