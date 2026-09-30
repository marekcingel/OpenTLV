#include "visitor_input.h"
#include "controlled_format.h"
#include "tlv/reader/visitor.h"
#include <gtest/gtest.h>
#include <vector>

namespace {
struct Visits {
    tlv_element_t      elements[4]{};
    size_t             count = 0;
    size_t             finish_after = 4;
    tlv_visit_result_t result = TLV_VISIT_CONTINUE;
};

tlv_visit_result_t collect(const tlv_element_t* element, void* context) {
    auto& visits = *static_cast<Visits*>(context);
    if (visits.count >= 4) return TLV_VISIT_ERROR;
    visits.elements[visits.count++] = *element;
    return visits.count == visits.finish_after ? visits.result : TLV_VISIT_CONTINUE;
}
} // namespace

TEST(Unit_Tlv_Visitor, PropagatesCustomReaderErrorsIncludingEndOfBuffer) {
    const uint8_t data[] = {1, 0};
    for (auto error : {TLV_ERR_INVALID_TAG, TLV_ERR_INVALID_LENGTH, TLV_ERR_END_OF_BUFFER}) {
        for (bool fail_tag : {false, true}) {
            auto layout = controlled::format_layout;
            auto format = controlled::format;
            format.context = &layout;
            layout.context = &error;
            if (fail_tag) {
                layout.read_tag = [](const void* ctx, const uint8_t*, size_t, tlv_tag_t*, size_t*) {
                    return *static_cast<const tlv_result_t*>(ctx);
                };
            } else {
                layout.read_length = [](const void* ctx, const uint8_t*, size_t, tlv_size_t*,
                                        size_t*) { return *static_cast<const tlv_result_t*>(ctx); };
            }
            Visits visits;
            EXPECT_EQ(error, visit_input(data, sizeof(data), &format, collect, &visits));
            EXPECT_EQ(0u, visits.count);
            tlv_reader_t reader;
            ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data), &format));
            EXPECT_EQ(error, tlv_reader_visit(&reader, collect, &visits));
            tlv_tree_reader_t tree;
            ASSERT_EQ(TLV_OK,
                      tlv_tree_reader_init(&tree, data, sizeof(data), &format, nullptr, 0, 0, 1));
            EXPECT_EQ(error, tlv_tree_reader_visit(&tree, nullptr, nullptr, nullptr));
        }
    }
}

TEST(Unit_Tlv_Visitor, EmptyInputSucceedsAndNullContextIsAllowed) {
    const uint8_t data[] = {1, 0};
    Visits        visits;
    EXPECT_EQ(TLV_OK, visit_input(nullptr, 0, &controlled::format, collect, &visits));
    EXPECT_EQ(TLV_OK, visit_input(data, 0, &controlled::format, collect, &visits));
    EXPECT_EQ(0u, visits.count);
    EXPECT_EQ(TLV_OK, visit_input(
                          data, sizeof(data), &controlled::format,
                          [](const tlv_element_t* element, void* ctx) {
                              EXPECT_EQ(nullptr, ctx);
                              EXPECT_EQ(1u, element->tag.data[0]);
                              return TLV_VISIT_CONTINUE;
                          },
                          nullptr));
}

TEST(Unit_Tlv_Visitor, RejectsInvalidArgumentsEvenForEmptyInput) {
    const uint8_t data[] = {1, 0};
    Visits        visits;
    EXPECT_EQ(TLV_ERR_NULL_ARG, visit_input(nullptr, 1, &controlled::format, collect, &visits));
    for (size_t size : {size_t(0), sizeof(data)}) {
        EXPECT_EQ(TLV_ERR_NULL_ARG, visit_input(data, size, nullptr, collect, &visits));
        EXPECT_EQ(TLV_ERR_NULL_ARG, visit_input(data, size, &controlled::format, nullptr, &visits));
        auto layout = controlled::format_layout;
        auto format = controlled::format;
        format.context = &layout;
        format.decode = nullptr;
        EXPECT_EQ(TLV_ERR_NULL_ARG, visit_input(data, size, &format, collect, &visits));
        format = controlled::format;
        format.decode = nullptr;
        EXPECT_EQ(TLV_ERR_NULL_ARG, visit_input(data, size, &format, collect, &visits));
    }
    EXPECT_EQ(0u, visits.count);
}

namespace {
tlv_format_t tree_format() {
    auto format = controlled::format;
    format.is_constructed = [](const void*, const tlv_tag_t* tag) {
        return tag->data[0] >= 0x80 ? 1 : 0;
    };
    return format;
}
} // namespace

TEST(Unit_Tlv_Visitor, CursorArgumentsAndCallbackErrors) {
    const uint8_t data[] = {1, 0, 2, 0};
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_reader_visit(nullptr, collect, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_tree_reader_visit(nullptr, nullptr, nullptr, nullptr));
    for (auto result : {TLV_VISIT_STOP, TLV_VISIT_ERROR, static_cast<tlv_visit_result_t>(99)}) {
        tlv_reader_t reader;
        ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data), &controlled::format));
        EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_reader_visit(&reader, nullptr, nullptr));
        EXPECT_EQ(0u, tlv_reader_offset(&reader));
        Visits visits;
        visits.finish_after = 1;
        visits.result = result;
        tlv_reader_diagnostic_t diagnostic{};
        diagnostic.diagnostic.code = TLV_ERR_VISITOR;
        EXPECT_EQ(result == TLV_VISIT_STOP ? TLV_OK : TLV_ERR_VISITOR,
                  tlv_reader_visit_diag(&reader, collect, &visits, &diagnostic));
        EXPECT_EQ(TLV_OK, diagnostic.diagnostic.code);
        EXPECT_EQ(2u, tlv_reader_offset(&reader));
        EXPECT_EQ(TLV_OK, tlv_reader_visit(&reader, collect, &visits));
        EXPECT_EQ(2u, visits.count);
    }
}

TEST(Unit_Tlv_Visitor, TreeStopAndErrorResumeAtChildrenAndMatchPull) {
    const uint8_t data[] = {0xE1, 2, 1, 0, 2, 0};
    auto          format = tree_format();
    for (auto result : {TLV_VISIT_STOP, TLV_VISIT_ERROR, static_cast<tlv_visit_result_t>(99)}) {
        tlv_tree_frame_t  frames[1], pull_frames[1];
        tlv_tree_reader_t reader, pull;
        ASSERT_EQ(TLV_OK,
                  tlv_tree_reader_init(&reader, data, sizeof(data), &format, frames, 1, 1, 3));
        ASSERT_EQ(TLV_OK,
                  tlv_tree_reader_init(&pull, data, sizeof(data), &format, pull_frames, 1, 1, 3));
        struct Context {
            tlv_tree_reader_t* pull;
            tlv_visit_result_t result;
            size_t             count;
        } ctx{&pull, result, 0};
        auto callback = [](const tlv_element_t* element, size_t depth, size_t offset,
                           void* opaque) {
            auto&           c = *static_cast<Context*>(opaque);
            tlv_tree_item_t item{};
            EXPECT_EQ(TLV_OK, tlv_tree_reader_next(c.pull, &item));
            EXPECT_EQ(item.depth, depth);
            EXPECT_EQ(item.offset, offset);
            EXPECT_EQ(item.element.tag.data, element->tag.data);
            EXPECT_EQ(item.element.value.data, element->value.data);
            EXPECT_EQ(item.element.value.size, element->value.size);
            return ++c.count == 1 ? c.result : TLV_VISIT_CONTINUE;
        };
        size_t offset = 99;
        EXPECT_EQ(result == TLV_VISIT_STOP ? TLV_OK : TLV_ERR_VISITOR,
                  tlv_tree_reader_visit(&reader, callback, &ctx, &offset));
        EXPECT_EQ(result == TLV_VISIT_STOP ? 99u : 0u, offset);
        EXPECT_EQ(1u, ctx.count);
        EXPECT_EQ(TLV_OK, tlv_tree_reader_visit(&reader, callback, &ctx, &offset));
        EXPECT_EQ(3u, ctx.count);
        EXPECT_TRUE(tlv_tree_reader_at_end(&reader));
    }
}

TEST(Unit_Tlv_Visitor, IncrementalSequentialResumeAndAbsoluteDiagnostics) {
    const uint8_t initial[] = {1, 0, 2};
    const uint8_t replacement[] = {2, 1, 0xAB};
    tlv_reader_t  reader;
    ASSERT_EQ(TLV_OK,
              tlv_reader_init_incremental(&reader, initial, sizeof(initial), &controlled::format));
    Visits                  visits;
    tlv_reader_diagnostic_t diagnostic{};
    EXPECT_EQ(TLV_NEED_MORE_DATA, tlv_reader_visit_diag(&reader, collect, &visits, &diagnostic));
    EXPECT_EQ(1u, visits.count);
    EXPECT_EQ(3u, diagnostic.diagnostic.offset);
    ASSERT_EQ(TLV_OK, tlv_reader_set_input(&reader, replacement, 1, 2, 0));
    EXPECT_EQ(TLV_NEED_MORE_DATA, tlv_reader_visit_diag(&reader, collect, &visits, &diagnostic));
    EXPECT_EQ(3u, diagnostic.diagnostic.offset);
    ASSERT_EQ(TLV_OK, tlv_reader_set_input(&reader, replacement, sizeof(replacement), 0, 1));
    EXPECT_EQ(TLV_OK, tlv_reader_visit_diag(&reader, collect, &visits, &diagnostic));
    EXPECT_EQ(TLV_OK, diagnostic.diagnostic.code);
    EXPECT_EQ(2u, visits.count);
    EXPECT_EQ(replacement + 2, visits.elements[1].value.data);
    EXPECT_EQ(5u, tlv_reader_offset(&reader));
}

TEST(Unit_Tlv_Visitor, IncrementalTreePublishesCompleteParentsAndPreservesOffsets) {
    const uint8_t     initial[] = {0xE1, 2, 1, 0};
    const uint8_t     replacement[] = {2, 1, 0xAB};
    auto              format = tree_format();
    tlv_tree_frame_t  frames[1];
    tlv_tree_reader_t reader;
    ASSERT_EQ(TLV_OK,
              tlv_tree_reader_init_incremental(&reader, initial, 3, &format, frames, 1, 1, 3));
    std::vector<size_t> offsets;
    auto                callback = [](const tlv_element_t*, size_t, size_t offset, void* context) {
        static_cast<std::vector<size_t>*>(context)->push_back(offset);
        return TLV_VISIT_CONTINUE;
    };
    size_t                  error = 99;
    tlv_reader_diagnostic_t diagnostic{};
    EXPECT_EQ(TLV_NEED_MORE_DATA,
              tlv_tree_reader_visit_diag(&reader, callback, &offsets, &error, &diagnostic));
    EXPECT_TRUE(offsets.empty());
    ASSERT_EQ(TLV_OK, tlv_tree_reader_set_input(&reader, initial, sizeof(initial), 0, 0));
    EXPECT_EQ(TLV_NEED_MORE_DATA, tlv_tree_reader_visit(&reader, callback, &offsets, &error));
    EXPECT_EQ((std::vector<size_t>{0, 2}), offsets);
    ASSERT_EQ(TLV_OK, tlv_tree_reader_set_input(&reader, replacement, 2, 4, 0));
    EXPECT_EQ(TLV_NEED_MORE_DATA,
              tlv_tree_reader_visit_diag(&reader, callback, &offsets, &error, &diagnostic));
    EXPECT_EQ(4u, error);
    EXPECT_EQ(6u, diagnostic.diagnostic.offset);
    ASSERT_EQ(TLV_OK, tlv_tree_reader_set_input(&reader, replacement, sizeof(replacement), 0, 1));
    EXPECT_EQ(TLV_OK, tlv_tree_reader_visit_diag(&reader, callback, &offsets, &error, &diagnostic));
    EXPECT_EQ((std::vector<size_t>{0, 2, 4}), offsets);
    EXPECT_EQ(TLV_OK, diagnostic.diagnostic.code);
}

TEST(Unit_Tlv_Visitor, CallerFramesAllowDepthBeyondDefaultDepth) {
    const size_t         depth = TLV_TREE_DEFAULT_DEPTH + 32;
    std::vector<uint8_t> data;
    for (size_t i = 0; i <= depth; ++i) {
        data.push_back(0x80);
        data.push_back(static_cast<uint8_t>(2 * (depth - i)));
    }
    auto                          format = tree_format();
    std::vector<tlv_tree_frame_t> frames(depth);
    tlv_tree_reader_t             reader;
    ASSERT_EQ(TLV_OK, tlv_tree_reader_init(&reader, data.data(), data.size(), &format,
                                           frames.data(), depth, depth, depth + 1));
    size_t count = 0;
    auto   callback = [](const tlv_element_t*, size_t d, size_t offset, void* context) {
        auto& n = *static_cast<size_t*>(context);
        EXPECT_EQ(n, d);
        EXPECT_EQ(2 * n, offset);
        ++n;
        return TLV_VISIT_CONTINUE;
    };
    EXPECT_EQ(TLV_OK, tlv_tree_reader_visit(&reader, callback, &count, nullptr));
    EXPECT_EQ(depth + 1, count);
}

TEST(Unit_Tlv_Visitor, TreeDiagnosticsDecodeOnceAndResourceErrorsRemainClear) {
    const uint8_t malformed[] = {0xE1, 3, 1, 2, 0xAB};
    size_t        reads = 0;
    auto          layout = controlled::format_layout;
    layout.context = &reads;
    layout.read_tag = [](const void* context, const uint8_t* data, size_t size, tlv_tag_t* tag,
                         size_t* used) {
        ++*static_cast<size_t*>(const_cast<void*>(context));
        return controlled::read_tag(nullptr, data, size, tag, used);
    };
    auto format = tree_format();
    format.context = &layout;
    tlv_tree_frame_t  frames[1];
    tlv_tree_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_tree_reader_init(&reader, malformed, sizeof(malformed), &format, frames,
                                           1, 1, 2));
    tlv_reader_diagnostic_t diagnostic{};
    size_t                  offset = 99;
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              tlv_tree_reader_visit_diag(&reader, nullptr, nullptr, &offset, &diagnostic));
    EXPECT_EQ(2u, reads);
    EXPECT_EQ(2u, offset);
    EXPECT_EQ(4u, diagnostic.diagnostic.offset);
    EXPECT_EQ(5u, diagnostic.enclosing_end);
    EXPECT_EQ(2u, diagnostic.required);
    EXPECT_EQ(1u, diagnostic.available);
    for (size_t capacity : {size_t(0), size_t(1)}) {
        ASSERT_EQ(TLV_OK, tlv_tree_reader_init(&reader, malformed, sizeof(malformed), &format,
                                               frames, capacity, 1, 1));
        reads = 0;
        EXPECT_EQ(TLV_ERR_LIMIT,
                  tlv_tree_reader_visit_diag(&reader, nullptr, nullptr, &offset, &diagnostic));
        EXPECT_EQ(1u, reads);
        EXPECT_EQ(2u, offset);
        EXPECT_EQ(TLV_OK, diagnostic.diagnostic.code);
        EXPECT_EQ(TLV_OK, tlv_tree_reader_skip_subtree(&reader));
        EXPECT_EQ(TLV_OK, tlv_tree_reader_visit(&reader, nullptr, nullptr, &offset));
    }
}
