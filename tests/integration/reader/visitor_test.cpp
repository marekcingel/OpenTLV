#include "visitor_input.h"
#include "controlled_format.h"
#include "tlv/builtins/asn1/ber.h"
#include "tlv/reader/visitor.h"
#include <gtest/gtest.h>

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

TEST(Integration_Tlv_Visitor, VisitsSequentialElementsAndBorrowsValues) {
    const uint8_t data[] = {1, 2, 0xAB, 0xCD, 2, 0, 3, 1, 0xEF};
    Visits        visits;
    ASSERT_EQ(TLV_OK, visit_input(data, sizeof(data), &controlled::format, collect, &visits));
    ASSERT_EQ(3u, visits.count);
    for (size_t i = 0; i < visits.count; ++i) {
        EXPECT_EQ(1u, visits.elements[i].tag.size);
        EXPECT_EQ(i + 1, visits.elements[i].tag.data[0]);
    }
    EXPECT_EQ(data + 2, visits.elements[0].value.data);
    EXPECT_EQ(2u, visits.elements[0].value.size);
    EXPECT_EQ(data + 6, visits.elements[1].value.data);
    EXPECT_EQ(0u, visits.elements[1].value.size);
    EXPECT_EQ(data + 8, visits.elements[2].value.data);
    EXPECT_EQ(1u, visits.elements[2].value.size);
}

TEST(Integration_Tlv_Visitor, StopsOrFailsBeforeReadingMalformedTail) {
    const uint8_t data[] = {1, 0, 2, 0, 3};
    for (auto result : {TLV_VISIT_STOP, TLV_VISIT_ERROR}) {
        Visits visits;
        visits.finish_after = 2;
        visits.result = result;
        EXPECT_EQ(result == TLV_VISIT_STOP ? TLV_OK : TLV_ERR_VISITOR,
                  visit_input(data, sizeof(data), &controlled::format, collect, &visits));
        EXPECT_EQ(2u, visits.count);
    }
    EXPECT_STREQ("visitor error", tlv_strerror(TLV_ERR_VISITOR));
}

TEST(Integration_Tlv_Visitor, PropagatesTruncatedInputAfterSuccessfulVisits) {
    const uint8_t data[] = {1, 0, 2, 2, 0xAB, 0xCD};
    for (size_t size = 3; size < sizeof(data); ++size) {
        SCOPED_TRACE(size);
        Visits visits;
        EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
                  visit_input(data, size, &controlled::format, collect, &visits));
        EXPECT_EQ(1u, visits.count);
    }
}

TEST(Integration_Tlv_Visitor, UsesSelectedFormatWithoutRecursingIntoValues) {
    // BER length; the first value is a TLV, the second is an invalid TLV.
    const uint8_t data[] = {1, 0x81, 2, 3, 0, 2, 0x81, 1, 0xFF};
    Visits        visits;
    ASSERT_EQ(TLV_OK, visit_input(data, sizeof(data), &tlv_format_ber, collect, &visits));
    ASSERT_EQ(2u, visits.count);
    EXPECT_EQ(1u, visits.elements[0].tag.data[0]);
    EXPECT_EQ(data + 3, visits.elements[0].value.data);
    EXPECT_EQ(2u, visits.elements[0].value.size);
    EXPECT_EQ(2u, visits.elements[1].tag.data[0]);
    EXPECT_EQ(1u, visits.elements[1].value.size);
}

TEST(Integration_Tlv_Visitor, BerIndefiniteParentCanStopThenResumeThroughTrailer) {
    const uint8_t     data[] = {0x30, 0x80, 0x04, 1, 0xAB, 0, 0, 0x04, 0};
    tlv_tree_frame_t  frames[1];
    tlv_tree_reader_t reader;
    ASSERT_EQ(TLV_OK,
              tlv_tree_reader_init(&reader, data, sizeof(data), &tlv_format_ber, frames, 1, 1, 3));
    struct Context {
        size_t count = 0;
    } ctx;
    auto callback = [](const tlv_element_t* element, size_t depth, size_t offset, void* context) {
        auto&        c = *static_cast<Context*>(context);
        const size_t offsets[] = {0, 2, 7};
        const size_t depths[] = {0, 1, 0};
        EXPECT_LT(c.count, 3u);
        if (c.count >= 3) return TLV_VISIT_ERROR;
        EXPECT_EQ(offsets[c.count], offset);
        EXPECT_EQ(depths[c.count], depth);
        EXPECT_EQ(c.count == 0 ? 0x30 : 0x04, element->tag.data[0]);
        return ++c.count == 1 ? TLV_VISIT_STOP : TLV_VISIT_CONTINUE;
    };
    ASSERT_EQ(TLV_OK, tlv_tree_reader_visit(&reader, callback, &ctx, nullptr));
    EXPECT_EQ(1u, ctx.count);
    ASSERT_EQ(TLV_OK, tlv_tree_reader_visit(&reader, callback, &ctx, nullptr));
    EXPECT_EQ(3u, ctx.count);
    EXPECT_TRUE(tlv_tree_reader_at_end(&reader));
}
