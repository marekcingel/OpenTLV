#include "tlv/walker.h"
#include <gtest/gtest.h>

namespace {
struct Visits {
    tlv_view_t views[4]{};
    size_t count = 0;
    size_t finish_after = 4;
    tlv_visit_result_t result = TLV_VISIT_CONTINUE;
};

tlv_visit_result_t collect(const tlv_view_t* view, void* context) {
    auto& visits = *static_cast<Visits*>(context);
    if (visits.count >= 4) return TLV_VISIT_ERROR;
    visits.views[visits.count++] = *view;
    return visits.count == visits.finish_after ? visits.result : TLV_VISIT_CONTINUE;
}
}

TEST(Walker, VisitsSequentialElementsAndBorrowsValues) {
    const uint8_t data[] = {1, 2, 0xAB, 0xCD, 2, 0, 3, 1, 0xEF};
    Visits visits;
    ASSERT_EQ(TLV_OK, tlv_walk(data, sizeof(data), &tlv_format_fixed_1byte, collect, &visits));
    ASSERT_EQ(3u, visits.count);
    for (size_t i = 0; i < visits.count; ++i) {
        EXPECT_EQ(1u, visits.views[i].tag.size);
        EXPECT_EQ(i + 1, visits.views[i].tag.data[0]);
    }
    EXPECT_EQ(data + 2, visits.views[0].value.data);
    EXPECT_EQ(2u, visits.views[0].value.length);
    EXPECT_EQ(data + 6, visits.views[1].value.data);
    EXPECT_EQ(0u, visits.views[1].value.length);
    EXPECT_EQ(data + 8, visits.views[2].value.data);
    EXPECT_EQ(1u, visits.views[2].value.length);
}

TEST(Walker, StopsOrFailsBeforeReadingMalformedTail) {
    const uint8_t data[] = {1, 0, 2, 0, 3};
    for (auto result : {TLV_VISIT_STOP, TLV_VISIT_ERROR}) {
        Visits visits;
        visits.finish_after = 2;
        visits.result = result;
        EXPECT_EQ(result == TLV_VISIT_STOP ? TLV_OK : TLV_ERR_VISITOR,
                  tlv_walk(data, sizeof(data), &tlv_format_fixed_1byte, collect, &visits));
        EXPECT_EQ(2u, visits.count);
    }
    EXPECT_STREQ("visitor error", tlv_strerror(TLV_ERR_VISITOR));
}

TEST(Walker, PropagatesTruncatedInputAfterSuccessfulVisits) {
    const uint8_t data[] = {1, 0, 2, 2, 0xAB, 0xCD};
    for (size_t size = 3; size < sizeof(data); ++size) {
        SCOPED_TRACE(size);
        Visits visits;
        EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
                  tlv_walk(data, size, &tlv_format_fixed_1byte, collect, &visits));
        EXPECT_EQ(1u, visits.count);
    }
}

TEST(Walker, UsesSelectedFormatWithoutRecursingIntoValues) {
    // BER length; the first value is a TLV, the second is an invalid TLV.
    const uint8_t data[] = {1, 0x81, 2, 3, 0, 2, 0x81, 1, 0xFF};
    Visits visits;
    ASSERT_EQ(TLV_OK, tlv_walk(data, sizeof(data), &tlv_format_default, collect, &visits));
    ASSERT_EQ(2u, visits.count);
    EXPECT_EQ(1u, visits.views[0].tag.data[0]);
    EXPECT_EQ(data + 3, visits.views[0].value.data);
    EXPECT_EQ(2u, visits.views[0].value.length);
    EXPECT_EQ(2u, visits.views[1].tag.data[0]);
    EXPECT_EQ(1u, visits.views[1].value.length);
}

TEST(Walker, PropagatesCustomReaderErrorsIncludingEndOfBuffer) {
    const uint8_t data[] = {1, 0};
    for (auto error : {TLV_ERR_INVALID_TAG, TLV_ERR_INVALID_LENGTH, TLV_ERR_END_OF_BUFFER}) {
        for (bool fail_tag : {false, true}) {
            auto format = tlv_format_fixed_1byte;
            format.context = &error;
            if (fail_tag) {
                format.read_tag = [](const void* ctx, const uint8_t*, size_t, tlv_tag_t*, size_t*) {
                    return *static_cast<const tlv_result_t*>(ctx);
                };
            } else {
                format.read_length = [](const void* ctx, const uint8_t*, size_t, size_t*, size_t*) {
                    return *static_cast<const tlv_result_t*>(ctx);
                };
            }
            Visits visits;
            EXPECT_EQ(error, tlv_walk(data, sizeof(data), &format, collect, &visits));
            EXPECT_EQ(0u, visits.count);
        }
    }
}

TEST(Walker, EmptyInputSucceedsAndNullContextIsAllowed) {
    const uint8_t data[] = {1, 0};
    Visits visits;
    EXPECT_EQ(TLV_OK, tlv_walk(nullptr, 0, &tlv_format_fixed_1byte, collect, &visits));
    EXPECT_EQ(TLV_OK, tlv_walk(data, 0, &tlv_format_fixed_1byte, collect, &visits));
    EXPECT_EQ(0u, visits.count);
    EXPECT_EQ(TLV_OK, tlv_walk(data, sizeof(data), &tlv_format_fixed_1byte,
        [](const tlv_view_t* view, void* ctx) {
            EXPECT_EQ(nullptr, ctx);
            EXPECT_EQ(1u, view->tag.data[0]);
            return TLV_VISIT_CONTINUE;
        }, nullptr));
}

TEST(Walker, RejectsInvalidArgumentsEvenForEmptyInput) {
    const uint8_t data[] = {1, 0};
    Visits visits;
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_walk(nullptr, 1, &tlv_format_fixed_1byte, collect, &visits));
    for (size_t size : {size_t(0), sizeof(data)}) {
        EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_walk(data, size, nullptr, collect, &visits));
        EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_walk(data, size, &tlv_format_fixed_1byte, nullptr, &visits));
        auto format = tlv_format_fixed_1byte;
        format.read_tag = nullptr;
        EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_walk(data, size, &format, collect, &visits));
        format = tlv_format_fixed_1byte;
        format.read_length = nullptr;
        EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_walk(data, size, &format, collect, &visits));
    }
    EXPECT_EQ(0u, visits.count);
}
