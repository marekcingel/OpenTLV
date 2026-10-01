#include "controlled_format.h"
#include "tlv++/query/query.hpp"
#include "tlv/config.h"
#if OPENTLV_DOCUMENT
#include "tlv++/document/document.hpp"
#endif
#include <gtest/gtest.h>
#include <vector>

namespace {
int constructed(const void*, const tlv_tag_t* tag) {
    return tag->size == 1 && (tag->data[0] == 0x6F || tag->data[0] == 0xA5);
}
tlv_format_t make_format() {
    auto result = controlled::format;
    result.is_constructed = constructed;
    return result;
}
const tlv_format_t format = make_format();
// A dead-end root followed by two matching branches and an unrelated root.
const uint8_t input[] = {0x6F, 2, 0x84, 0, 0x6F, 8, 0xA5, 6, 0x50, 1, 1, 0x50, 1, 2, 0x50, 1, 9};
tlv::bytes    bytes(const uint8_t* data, size_t size) {
    return {reinterpret_cast<const tlv::byte*>(data), size};
}
} // namespace

TEST(Unit_Tlvpp_QueryRanges, OrderedMatchesAndOwnedQuery) {
    tlv::tree_frame     frames[3]{};
    tlv::tree_reader    reader(bytes(input, sizeof(input)), format, {frames, 3}, 3, 100);
    auto                selected = reader.select("6F/A5/50");
    auto                moved = std::move(selected);
    std::vector<size_t> offsets;
    for (const auto& item : moved) {
        offsets.push_back(item.offset);
        EXPECT_EQ(2u, item.depth);
        EXPECT_EQ(tlv::tag_bytes<0x50>(), item.element.tag());
    }
    EXPECT_EQ((std::vector<size_t>{8, 11}), offsets);
}

TEST(Unit_Tlvpp_QueryRanges, EmptyAndCompilationErrors) {
    tlv::tree_frame  frames[3]{};
    tlv::tree_reader reader(bytes(input, sizeof(input)), format, {frames, 3}, 3, 100);
    auto             selected = reader.select("6F/A5/51");
    EXPECT_EQ(selected.end(), selected.begin());
    try {
        reader.select("6F//50");
        FAIL();
    } catch (const tlv::query_error& error) {
        EXPECT_EQ(TLV_ERR_INVALID_ARG, error.code());
        EXPECT_EQ(3u, error.offset());
    }
    size_t offset = 0;
    EXPECT_FALSE(tlv::query::parse("6F//50", &offset));
    EXPECT_EQ(3u, offset);
}

TEST(Unit_Tlvpp_QueryRanges, MalformedTailIsNotEnd) {
    const uint8_t    broken[] = {0x50, 0, 0x51, 2};
    tlv::tree_frame  frames[1]{};
    tlv::tree_reader reader(bytes(broken, sizeof(broken)), format, {frames, 1}, 1, 10);
    auto             selected = reader.select("50");
    auto             it = selected.begin();
    ASSERT_NE(it, selected.end());
    try {
        ++it;
        FAIL();
    } catch (const tlv::parse_error& error) {
        EXPECT_NE(TLV_ERR_END_OF_BUFFER, error.code());
        EXPECT_EQ(2u, error.offset());
    }
}

TEST(Unit_Tlvpp_QueryRanges, IncrementalResumeAndIteratorCopies) {
    const uint8_t    flat[] = {0x50, 1, 1, 0x50, 1, 2};
    tlv::tree_frame  frames[1]{};
    tlv::tree_reader reader(bytes(flat, 3), format, {frames, 1}, 1, 10,
                            tlv::input_mode::incremental);
    auto             selected = reader.select("50");
    auto             it = selected.begin();
    auto             copy = it;
    EXPECT_EQ(0u, it->offset);
    EXPECT_THROW(++it, tlv::parse_error);
    EXPECT_EQ(copy, selected.end());
    ASSERT_TRUE(reader.set_input(bytes(flat, sizeof(flat)), 0, tlv::input_mode::final));
    auto next = selected.next();
    ASSERT_TRUE(next);
    EXPECT_EQ(3u, next->offset);
    auto end = selected.next();
    ASSERT_FALSE(end);
    EXPECT_EQ(TLV_ERR_END_OF_BUFFER, end.error().code);
}

TEST(Unit_Tlvpp_QueryRanges, LimitsApplyToUnmatchedItems) {
    tlv::tree_frame  frames[3]{};
    tlv::tree_reader reader(bytes(input, sizeof(input)), format, {frames, 3}, 3, 1);
    auto             selected = reader.select("51");
    auto             result = selected.next();
    ASSERT_FALSE(result);
    EXPECT_EQ(TLV_ERR_LIMIT, result.error().code);
}

#if OPENTLV_DOCUMENT
TEST(Unit_Tlvpp_QueryRanges, DocumentSnapshotHandlesSurviveMoveAndInvalidateSafely) {
    auto parsed = tlv::document::parse(bytes(input, sizeof(input)), tlv::document_format(format));
    ASSERT_TRUE(parsed);
    auto selected = parsed->select("6F/A5/50");
    ASSERT_EQ(2u, selected.size());
    EXPECT_EQ(1u, static_cast<unsigned>(selected[0].value()[0]));
    EXPECT_EQ(2u, static_cast<unsigned>(selected[1].value()[0]));
    EXPECT_TRUE(parsed->select("6F/A5/51").empty());
    auto moved = std::move(*parsed);
    EXPECT_TRUE(selected[0]);
    selected[0].erase();
    EXPECT_FALSE(selected[0]);
    EXPECT_TRUE(selected[1]);
    EXPECT_EQ(1u, moved.select(tlv::query::compile("6F/A5/50")).size());
    EXPECT_THROW(moved.select("6F/"), tlv::query_error);
}

TEST(Unit_Tlvpp_QueryRanges, DocumentDestructionInvalidatesResults) {
    std::vector<tlv::node> selected;
    {
        auto parsed =
            tlv::document::parse(bytes(input, sizeof(input)), tlv::document_format(format));
        ASSERT_TRUE(parsed);
        selected = parsed->select("6F/A5/50");
    }
    ASSERT_EQ(2u, selected.size());
    EXPECT_FALSE(selected[0]);
    EXPECT_FALSE(selected[1]);
}

TEST(Unit_Tlvpp_QueryRanges, DocumentSnapshotExcludesInsertionAndInvalidatesReplacedChildren) {
    auto parsed = tlv::document::parse(bytes(input, sizeof(input)), tlv::document_format(format));
    ASSERT_TRUE(parsed);
    auto selected = parsed->select("6F/A5/50");
    auto parent = parsed->find(tlv::query::compile("6F/A5"));
    ASSERT_TRUE(parent);
    ASSERT_TRUE(parent.insert(tlv::tag_bytes<0x50>(), tlv::bytes()));
    EXPECT_EQ(2u, selected.size());
    EXPECT_EQ(3u, parsed->select("6F/A5/50").size());
    const uint8_t replacement[] = {0x50, 0};
    ASSERT_TRUE(parent.set(bytes(replacement, sizeof(replacement))));
    EXPECT_FALSE(selected[0]);
    EXPECT_FALSE(selected[1]);
    EXPECT_TRUE(parent);
    EXPECT_EQ(1u, parsed->select("6F/A5/50").size());
}
#endif
