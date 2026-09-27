#include "controlled_format.h"
#include "tlv/reader/walker.h"
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

TEST(Unit_Tlv_Walker, PropagatesCustomReaderErrorsIncludingEndOfBuffer) {
    const uint8_t data[] = {1, 0};
    for (auto error : {TLV_ERR_INVALID_TAG, TLV_ERR_INVALID_LENGTH, TLV_ERR_END_OF_BUFFER}) {
        for (bool fail_tag : {false, true}) {
            auto format = controlled::format;
            format.context = &error;
            if (fail_tag) {
                format.read_tag = [](const void* ctx, const uint8_t*, size_t, tlv_tag_t*, size_t*) {
                    return *static_cast<const tlv_result_t*>(ctx);
                };
            } else {
                format.read_length = [](const void* ctx, const uint8_t*, size_t, tlv_size_t*,
                                        size_t*) { return *static_cast<const tlv_result_t*>(ctx); };
            }
            Visits visits;
            EXPECT_EQ(error, tlv_walk(data, sizeof(data), &format, collect, &visits));
            EXPECT_EQ(0u, visits.count);
        }
    }
}

TEST(Unit_Tlv_Walker, EmptyInputSucceedsAndNullContextIsAllowed) {
    const uint8_t data[] = {1, 0};
    Visits        visits;
    EXPECT_EQ(TLV_OK, tlv_walk(nullptr, 0, &controlled::format, collect, &visits));
    EXPECT_EQ(TLV_OK, tlv_walk(data, 0, &controlled::format, collect, &visits));
    EXPECT_EQ(0u, visits.count);
    EXPECT_EQ(TLV_OK, tlv_walk(
                          data, sizeof(data), &controlled::format,
                          [](const tlv_element_t* element, void* ctx) {
                              EXPECT_EQ(nullptr, ctx);
                              EXPECT_EQ(1u, element->tag.data[0]);
                              return TLV_VISIT_CONTINUE;
                          },
                          nullptr));
}

TEST(Unit_Tlv_Walker, RejectsInvalidArgumentsEvenForEmptyInput) {
    const uint8_t data[] = {1, 0};
    Visits        visits;
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_walk(nullptr, 1, &controlled::format, collect, &visits));
    for (size_t size : {size_t(0), sizeof(data)}) {
        EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_walk(data, size, nullptr, collect, &visits));
        EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_walk(data, size, &controlled::format, nullptr, &visits));
        auto format = controlled::format;
        format.read_tag = nullptr;
        EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_walk(data, size, &format, collect, &visits));
        format = controlled::format;
        format.read_length = nullptr;
        EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_walk(data, size, &format, collect, &visits));
    }
    EXPECT_EQ(0u, visits.count);
}
