#include "tlv/config.h"
#include "tlv/reader/tree.h"
#include "tlv/formats/fixed.h"
#if OPENTLV_FORMAT_BER
#include "tlv/builtins/asn1/ber.h"
#endif
#if OPENTLV_LLDP
#include "tlv/builtins/lldp/lldp.h"
#endif
#include <gtest/gtest.h>
#include <vector>

TEST(Integration_Tlv_Tree, FixedLtvUsesFormatOwnedOrderAndConstruction) {
    const tlv_fixed_format_t config = {1, 1, TLV_BYTE_ORDER_BIG_ENDIAN, TLV_ELEMENT_ORDER_LTV,
                                       TLV_LENGTH_SCOPE_VALUE};
    tlv_format_t             format;
    ASSERT_EQ(TLV_OK, tlv_fixed_format_init(&format, &config));
    format.is_constructed = [](const void*, const tlv_tag_t* tag) -> int {
        return tag->data[0] == 0xE1;
    };
    const uint8_t     wire[] = {2, 0xE1, 0, 1, 0, 2};
    tlv_tree_frame_t  frame;
    tlv_tree_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_tree_reader_init(&reader, wire, sizeof(wire), &format, &frame, 1, 1, 3));
    tlv_tree_item_t item{};
    for (size_t offset : {size_t(0), size_t(2), size_t(4)}) {
        ASSERT_EQ(TLV_OK, tlv_tree_reader_next(&reader, &item));
        EXPECT_EQ(offset, item.offset);
        EXPECT_EQ(wire + offset + 1, item.element.tag.data);
        EXPECT_EQ(1u, item.source.tag.offset);
        EXPECT_EQ(offset == 2 ? 1u : 0u, item.depth);
    }
    EXPECT_TRUE(tlv_tree_reader_at_end(&reader));
}

#if OPENTLV_FORMAT_BER
TEST(Integration_Tlv_Tree, NestedTrailersAndSkippingResumeOutsideEnclosingValues) {
    const uint8_t wire[] = {0x30, 0x80, 0x30, 0x80, 4, 0, 0, 0, 4, 0, 0, 0, 4, 0};
    for (bool skip : {false, true}) {
        tlv_tree_frame_t  frames[2];
        tlv_tree_reader_t reader;
        ASSERT_EQ(TLV_OK, tlv_tree_reader_init(&reader, wire, sizeof(wire), &tlv_format_ber, frames,
                                               2, 2, 5));
        tlv_tree_item_t item{};
        ASSERT_EQ(TLV_OK, tlv_tree_reader_next(&reader, &item));
        EXPECT_EQ(2u, item.source.trailer.size);
        ASSERT_EQ(TLV_OK, tlv_tree_reader_next(&reader, &item));
        EXPECT_EQ(2u, item.offset);
        if (skip) {
            ASSERT_EQ(TLV_OK, tlv_tree_reader_skip_subtree(&reader));
        } else {
            ASSERT_EQ(TLV_OK, tlv_tree_reader_next(&reader, &item));
            EXPECT_EQ(4u, item.offset);
            EXPECT_EQ(2u, item.depth);
        }
        ASSERT_EQ(TLV_OK, tlv_tree_reader_next(&reader, &item));
        EXPECT_EQ(8u, item.offset);
        EXPECT_EQ(1u, item.depth);
        ASSERT_EQ(TLV_OK, tlv_tree_reader_next(&reader, &item));
        EXPECT_EQ(12u, item.offset);
        EXPECT_EQ(0u, item.depth);
        EXPECT_EQ(sizeof(wire), tlv_tree_reader_consumed(&reader));
        EXPECT_TRUE(tlv_tree_reader_at_end(&reader));
    }
}

TEST(Integration_Tlv_Tree, IncrementalIndefiniteParentWaitsForEocThenAllowsCompaction) {
    const std::vector<uint8_t> wire = {0x30, 0x80, 0x30, 0x80, 4, 0, 0, 0, 0, 0};
    for (size_t split = 0; split < wire.size(); ++split) {
        tlv_tree_frame_t  frames[2];
        tlv_tree_reader_t reader;
        ASSERT_EQ(TLV_OK, tlv_tree_reader_init_incremental(&reader, wire.data(), split,
                                                           &tlv_format_ber, frames, 2, 2, 4));
        tlv_tree_item_t item{};
        EXPECT_EQ(TLV_NEED_MORE_DATA, tlv_tree_reader_next(&reader, &item));
        ASSERT_EQ(TLV_OK, tlv_tree_reader_set_input(&reader, wire.data(), wire.size(), 0, 0));
        ASSERT_EQ(TLV_OK, tlv_tree_reader_next(&reader, &item));
        std::vector<uint8_t> remaining(wire.begin() + 2, wire.end());
        ASSERT_EQ(TLV_OK,
                  tlv_tree_reader_set_input(&reader, remaining.data(), remaining.size(), 2, 0));
        ASSERT_EQ(TLV_OK, tlv_tree_reader_next(&reader, &item));
        EXPECT_EQ(2u, item.offset);
        ASSERT_EQ(TLV_OK, tlv_tree_reader_skip_subtree(&reader));
        EXPECT_EQ(wire.size(), tlv_tree_reader_offset(&reader));
        EXPECT_EQ(TLV_NEED_MORE_DATA, tlv_tree_reader_next(&reader, &item));
        const uint8_t final[] = {4, 0};
        ASSERT_EQ(TLV_OK,
                  tlv_tree_reader_set_input(&reader, final, sizeof(final), remaining.size(), 1));
        ASSERT_EQ(TLV_OK, tlv_tree_reader_next(&reader, &item));
        EXPECT_EQ(10u, item.offset);
        EXPECT_EQ(0u, item.depth);
        EXPECT_TRUE(tlv_tree_reader_at_end(&reader));
    }
}
#endif

#if OPENTLV_LLDP
TEST(Integration_Tlv_Tree, PackedFormatKeepsTransformedBorrowedTags) {
    const uint8_t     wire[] = {0x0A, 2, 'A', 'B'};
    tlv_tree_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_tree_reader_init(&reader, wire, sizeof(wire), &tlv_format_lldp, nullptr,
                                           0, 0, 1));
    tlv_tree_item_t item{};
    ASSERT_EQ(TLV_OK, tlv_tree_reader_next(&reader, &item));
    EXPECT_EQ(TLV_TAG_BINDING_FORMAT, item.source.tag_binding);
    EXPECT_EQ(5u, item.element.tag.data[0]);
    EXPECT_EQ(wire + 2, item.element.value.data);
    EXPECT_FALSE(item.constructed);
    EXPECT_TRUE(tlv_tree_reader_at_end(&reader));
}
#endif
