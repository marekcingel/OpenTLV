#include "tlv/config.h"
#if OPENTLV_FORMAT_BER
#include "tlv/builtins/asn1/ber.h"
#endif
#include "tlv/builtins/asn1/cer.h"
#include "tlv/builtins/asn1/cer_profile.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#include <gtest/gtest.h>
#include <cstring>
#include <vector>

namespace {
struct Visit {
    size_t  offset;
    size_t  depth;
    uint8_t tag;
};
tlv_visit_result_t collect(const tlv_view_t* view, size_t depth, size_t offset, void* context) {
    static_cast<std::vector<Visit>*>(context)->push_back({offset, depth, view->tag.data[0]});
    return TLV_VISIT_CONTINUE;
}
struct Segment {
    tlv_tag_t   tag;
    tlv_value_t value;
};
tlv_visit_result_t collect_segment(const tlv_view_t* view, void* context) {
    static_cast<std::vector<Segment>*>(context)->push_back({view->tag, view->value});
    return TLV_VISIT_CONTINUE;
}
} // namespace

TEST(Integration_Tlv_Cer, NestedIndefiniteContainersPostorderVisitOrder) {
    /* SEQUENCE(indefinite) { INTEGER 5, SEQUENCE(indefinite) { OCTET STRING [0,0] } } */
    const uint8_t      data[] = {0x30, 0x80, 0x02, 1, 5, 0x30, 0x80, 0x04, 2, 0, 0, 0, 0, 0, 0};
    std::vector<Visit> visits;
    size_t             offset = 99;
    ASSERT_EQ(TLV_OK, tlv_cer_walk(data, sizeof(data), nullptr, collect, &visits, &offset));
    ASSERT_EQ(4u, visits.size());
    /* Primitive leaves visited immediately (preorder among siblings);
     * constructed containers visited only once their EOC is found. */
    const size_t  offsets[] = {2, 7, 5, 0};
    const size_t  depths[] = {1, 2, 1, 0};
    const uint8_t tags[] = {0x02, 0x04, 0x30, 0x30};
    for (size_t i = 0; i < visits.size(); ++i) {
        EXPECT_EQ(offsets[i], visits[i].offset);
        EXPECT_EQ(depths[i], visits[i].depth);
        EXPECT_EQ(tags[i], visits[i].tag);
    }
    EXPECT_EQ(99u, offset);

    tlv_view_t view{};
    size_t     consumed;
    ASSERT_EQ(TLV_OK, tlv_cer_read(data, sizeof(data), nullptr, &view, &consumed, nullptr));
    EXPECT_EQ(sizeof(data), consumed);
    EXPECT_EQ(11u, view.value.length);
    EXPECT_EQ(data + 2, view.value.data);
}

TEST(Integration_Tlv_Cer, PrimitiveContentContainingEocAndIndefiniteMarkerDoesNotAffectNesting) {
    for (uint8_t filler : {static_cast<uint8_t>(0x00), static_cast<uint8_t>(0x80)}) {
        const uint8_t data[] = {0x30, 0x80, 0x04, 2, filler, filler, 0, 0};
        tlv_view_t    view{};
        size_t        consumed = 0;
        SCOPED_TRACE(static_cast<int>(filler));
        ASSERT_EQ(TLV_OK, tlv_cer_read(data, sizeof(data), nullptr, &view, &consumed, nullptr));
        EXPECT_EQ(sizeof(data), consumed);
        EXPECT_EQ(4u, view.value.length);
    }
}

TEST(Integration_Tlv_Cer, EmptyIndefiniteContainer) {
    const uint8_t data[] = {0x30, 0x80, 0, 0};
    tlv_view_t    view{};
    size_t        consumed = 0;
    ASSERT_EQ(TLV_OK, tlv_cer_read(data, sizeof(data), nullptr, &view, &consumed, nullptr));
    EXPECT_EQ(sizeof(data), consumed);
    EXPECT_EQ(0u, view.value.length);
}

TEST(Integration_Tlv_Cer, MissingTruncatedAndUnexpectedEoc) {
    struct Case {
        std::vector<uint8_t> bytes;
        tlv_result_t         error;
        size_t               offset;
    };
    const std::vector<Case> cases = {
        {{0x30, 0x80, 0x02, 1, 5}, TLV_ERR_BUFFER_TOO_SHORT, 1},    /* missing EOC */
        {{0x30, 0x80, 0x02, 1, 5, 0}, TLV_ERR_BUFFER_TOO_SHORT, 5}, /* truncated EOC */
        {{0, 0}, TLV_ERR_INVALID_TAG, 0},                           /* unexpected EOC */
        {{0x30, 0x80, 0, 0, 0, 0}, TLV_ERR_INVALID_TAG, 4},         /* trailing stray EOC */
    };
    for (const auto& item : cases) {
        SCOPED_TRACE(::testing::PrintToString(item.bytes));
        size_t offset = 99;
        EXPECT_EQ(item.error, tlv_cer_walk(item.bytes.data(), item.bytes.size(), nullptr, nullptr,
                                           nullptr, &offset));
        EXPECT_EQ(item.offset, offset);
    }
}

TEST(Integration_Tlv_Cer, SingleElementReadLeavesFollowingElementUnconsumed) {
    const uint8_t data[] = {0x30, 0x80, 0, 0, 0x02, 1, 5};
    tlv_view_t    view{};
    size_t        consumed = 0, offset = 99;
    ASSERT_EQ(TLV_OK, tlv_cer_read(data, sizeof(data), nullptr, &view, &consumed, nullptr));
    EXPECT_EQ(4u, consumed);
    std::vector<Visit> visits;
    ASSERT_EQ(TLV_OK, tlv_cer_walk(data, sizeof(data), nullptr, collect, &visits, &offset));
    ASSERT_EQ(2u, visits.size());
    EXPECT_EQ(0u, visits[0].offset);
    EXPECT_EQ(4u, visits[1].offset);
}

TEST(Integration_Tlv_Cer, DepthLimitBoundary) {
    std::vector<uint8_t> data = {0x02, 1, 5};
    for (size_t depth = 1; depth <= TLV_CER_MAX_DEPTH + 1; ++depth) {
        std::vector<uint8_t> outer = {0xA0, 0x80};
        outer.insert(outer.end(), data.begin(), data.end());
        outer.push_back(0);
        outer.push_back(0);
        data.swap(outer);
        auto limits = tlv_cer_default_limits;
        limits.max_depth = TLV_CER_MAX_DEPTH;
        EXPECT_EQ(depth <= TLV_CER_MAX_DEPTH ? TLV_OK : TLV_ERR_LIMIT,
                  tlv_cer_walk(data.data(), data.size(), &limits, nullptr, nullptr, nullptr));
    }
}

TEST(Integration_Tlv_Cer, ConstructedFormRejectedStructurallyEvenWithoutStrict) {
    /* SEQUENCE(indefinite) { constructed INTEGER(indefinite) { INTEGER 5 } } --
     * INTEGER is not segmentable and not in the always-constructed set, so
     * this is a framing defect caught even by the non-strict walk. */
    const uint8_t data[] = {0x30, 0x80, 0x22, 0x80, 0x02, 1, 5, 0, 0, 0, 0};
    size_t        offset = 99;
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
              tlv_cer_walk(data, sizeof(data), nullptr, nullptr, nullptr, &offset));
    EXPECT_EQ(3u, offset);
}

TEST(Integration_Tlv_Cer, StrictReadRejectsNoncanonicalContentButNonStrictAccepts) {
    /* SEQUENCE(indefinite) { OCTET STRING "x", BOOLEAN 0x01 (noncanonical) } */
    const uint8_t data[] = {0x30, 0x80, 0x04, 1, 'x', 0x01, 1, 0x01, 0, 0};
    tlv_view_t    view{};
    size_t        consumed = 0, offset = 99;
    ASSERT_EQ(TLV_OK, tlv_cer_read(data, sizeof(data), nullptr, &view, &consumed, nullptr));
    EXPECT_EQ(sizeof(data), consumed);
    EXPECT_EQ(TLV_ERR_INVALID_VALUE,
              tlv_cer_read_strict(data, sizeof(data), nullptr, &view, &consumed, &offset));
    EXPECT_EQ(7u, offset);
}

TEST(Integration_Tlv_Cer, StrictRejectsUnsupportedUniversalTypeIncludingConstructed) {
    /* TeletexString(20) primitive, and constructed (segmented) form. */
    const uint8_t primitive[] = {0x14, 1, 'x'};
    tlv_view_t    view{};
    size_t        consumed = 0, offset = 99;
    EXPECT_EQ(TLV_ERR_UNSUPPORTED_TYPE, tlv_cer_read_strict(primitive, sizeof(primitive), nullptr,
                                                            &view, &consumed, &offset));
    EXPECT_EQ(2u, offset); /* value start, matching DER's content-error offset convention */

    std::vector<uint8_t> constructed = {0x34, 0x80};
    std::vector<uint8_t> seg1(1004, 'z'); /* tag + 3-byte length + 1000 content octets */
    seg1[0] = 0x14;
    seg1[1] = 0x82;
    seg1[2] = 0x03;
    seg1[3] = 0xE8; /* tag, len=1000 */
    constructed.insert(constructed.end(), seg1.begin(), seg1.end());
    constructed.push_back(0x14);
    constructed.push_back(1);
    constructed.push_back('y');
    constructed.push_back(0);
    constructed.push_back(0);
    EXPECT_EQ(TLV_ERR_UNSUPPORTED_TYPE, tlv_cer_read_strict(constructed.data(), constructed.size(),
                                                            nullptr, &view, &consumed, &offset));
}

TEST(Integration_Tlv_Cer, WriteConstructedProducesCanonicalIndefiniteFraming) {
    const uint8_t children[] = {0x02, 1, 5, 0x04, 1, 'x'};
    uint8_t       output[64];
    size_t        required = 0, written = 0;
    ASSERT_EQ(TLV_OK, tlv_cer_write(nullptr, 0, (TLV_TAG(0x30)), children, sizeof(children),
                                    nullptr, &required, nullptr));
    ASSERT_EQ(TLV_OK, tlv_cer_write(output, sizeof(output), (TLV_TAG(0x30)), children,
                                    sizeof(children), nullptr, &written, nullptr));
    EXPECT_EQ(required, written);
    ASSERT_EQ(sizeof(children) + 4, written); /* tag + 0x80 + children + EOC */
    EXPECT_EQ(0x30, output[0]);
    EXPECT_EQ(0x80, output[1]);
    EXPECT_EQ(0, std::memcmp(output + 2, children, sizeof(children)));
    EXPECT_EQ(0, output[written - 2]);
    EXPECT_EQ(0, output[written - 1]);

    tlv_view_t view{};
    size_t     consumed = 0;
    ASSERT_EQ(TLV_OK, tlv_cer_read(output, written, nullptr, &view, &consumed, nullptr));
    EXPECT_EQ(written, consumed);
}

TEST(Integration_Tlv_Cer, WriteRejectsOversizedPrimitiveForSegmentableTypeEvenNonStrict) {
    std::vector<uint8_t> value(1001, 'a');
    size_t               written = 99, offset = 99;
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_cer_write(nullptr, 0, (TLV_TAG(0x04)), value.data(),
                                                    value.size(), nullptr, &written, &offset));
    EXPECT_EQ(99u, written);
}

TEST(Integration_Tlv_Cer, FailedWritePreservesOutputAndSize) {
    const uint8_t children[] = {0x02, 1, 5};
    uint8_t       output[8];
    std::memset(output, 0xEE, sizeof(output));
    size_t written = 99, offset = 99;
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              tlv_cer_write(output, 1, (TLV_TAG(0x30)), children, sizeof(children), nullptr,
                            &written, &offset));
    EXPECT_EQ(99u, written);
    for (auto byte : output) EXPECT_EQ(0xEE, byte);
}

TEST(Integration_Tlv_Cer, WriteSegmentedStringSingleAndMultiSegment) {
    /* Content at or under the threshold: a single canonical primitive. */
    {
        std::vector<uint8_t> content(1000, 'a');
        uint8_t              output[1010];
        size_t               required = 0, written = 0;
        ASSERT_EQ(TLV_OK,
                  tlv_cer_write_segmented_string(nullptr, 0, (TLV_TAG(0x04)), content.data(),
                                                 content.size(), nullptr, &required, nullptr));
        ASSERT_EQ(TLV_OK, tlv_cer_write_segmented_string(output, sizeof(output), (TLV_TAG(0x04)),
                                                         content.data(), content.size(), nullptr,
                                                         &written, nullptr));
        EXPECT_EQ(required, written);
        EXPECT_EQ(0x04, output[0]);
        EXPECT_EQ(0x82, output[1]); /* long-form length: 1000 needs two octets */
        tlv_view_t view{};
        size_t     consumed;
        ASSERT_EQ(TLV_OK, tlv_cer_read(output, written, nullptr, &view, &consumed, nullptr));
        EXPECT_EQ(written, consumed);
        EXPECT_FALSE(tlv_cer_tag_is_constructed(&view.tag));
        EXPECT_EQ(1000u, view.value.length);
    }
    /* Content over the threshold: constructed, segmented, zero-copy segments. */
    {
        std::vector<uint8_t> content(1001, 'b');
        uint8_t              output[1050];
        size_t               required = 0, written = 0;
        ASSERT_EQ(TLV_OK,
                  tlv_cer_write_segmented_string(nullptr, 0, (TLV_TAG(0x04)), content.data(),
                                                 content.size(), nullptr, &required, nullptr));
        ASSERT_EQ(TLV_OK, tlv_cer_write_segmented_string(output, sizeof(output), (TLV_TAG(0x04)),
                                                         content.data(), content.size(), nullptr,
                                                         &written, nullptr));
        EXPECT_EQ(required, written);
        tlv_view_t view{};
        size_t     consumed;
        ASSERT_EQ(TLV_OK, tlv_cer_read(output, written, nullptr, &view, &consumed, nullptr));
        EXPECT_EQ(written, consumed);
        EXPECT_TRUE(tlv_cer_tag_is_constructed(&view.tag));
        /* Zero-copy segment iteration: view.value already excludes the outer EOC. */
        std::vector<Segment> segments;
        ASSERT_EQ(TLV_OK, tlv_walk(view.value.data, static_cast<size_t>(view.value.length),
                                   &tlv_reader_format_cer, collect_segment, &segments));
        ASSERT_EQ(2u, segments.size());
        EXPECT_EQ(0x04, segments[0].tag.data[0]);
        EXPECT_EQ(0x04, segments[1].tag.data[0]);
        EXPECT_EQ(1000u, segments[0].value.length);
        EXPECT_EQ(1u, segments[1].value.length);
        EXPECT_EQ(0, std::memcmp(segments[0].value.data, content.data(), 1000));
        EXPECT_EQ(content[1000], segments[1].value.data[0]);
        /* Strict validation confirms the canonical 1000/1-octet split. */
        ASSERT_EQ(TLV_OK, tlv_cer_read_strict(output, written, nullptr, &view, &consumed, nullptr));
    }
}
