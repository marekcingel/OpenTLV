#include "controlled_format.h"
#include "tlv/copy.h"
#include "tlv/reader/reader.h"
#include <gtest/gtest.h>
#include <cstring>
#include <limits>

TEST(Unit_Copy, InsufficientCapacityLeavesOutputsUnchanged) {
    const uint8_t value[] = {0xAB, 0xCD};
    const tlv_view_t view = {{{1}, 1}, {value, sizeof(value)}};
    for (size_t capacity = 0; capacity < 4; ++capacity) {
        uint8_t output[] = {0xEE, 0xEE, 0xEE, 0xEE};
        size_t written = 99;
        EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
                  tlv_copy_view(&view, &controlled::writer, output, capacity, &written));
        if (capacity < sizeof(value)) {
            EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_copy_value(&view, output, capacity, &written));
            EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_copy_encoded(view.value, output, capacity, &written));
        }
        EXPECT_EQ(99u, written);
        for (auto byte : output) EXPECT_EQ(0xEE, byte);
    }
}

TEST(Unit_Copy, EmptyValuesAndOverlappingByteRanges) {
    const tlv_view_t empty = {{{1}, 1}, {nullptr, 0}};
    size_t written = 99;
    uint8_t output[2] = {};
    EXPECT_EQ(TLV_OK, tlv_copy_value(&empty, nullptr, 0, &written));
    EXPECT_EQ(0u, written);
    EXPECT_EQ(TLV_OK, tlv_copy_value(&empty, output, 0, &written));
    EXPECT_EQ(TLV_OK, tlv_copy_encoded({nullptr, 0}, output, 0, &written));
    EXPECT_EQ(TLV_OK, tlv_copy_view(&empty, &controlled::writer, output, 2, &written));
    EXPECT_EQ(2u, written);
    EXPECT_EQ(1, output[0]);
    EXPECT_EQ(0, output[1]);
    uint8_t bytes[] = {1, 2, 3, 4};
    EXPECT_EQ(TLV_OK, tlv_copy_encoded({bytes, 3}, bytes + 1, 3, &written));
    const uint8_t expected[] = {1, 1, 2, 3};
    EXPECT_EQ(0, std::memcmp(expected, bytes, 4));
    const tlv_view_t view = {{}, {bytes + 1, 3}};
    EXPECT_EQ(TLV_OK, tlv_copy_value(&view, bytes, 3, &written));
    EXPECT_EQ(2, bytes[1]);
    EXPECT_EQ(3, bytes[2]);
}

TEST(Unit_Copy, InvalidArgumentsAndEncodingErrors) {
    uint8_t byte = 0xEE;
    tlv_view_t view = {{{1}, 1}, {&byte, 1}};
    size_t written = 99;
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_copy_value(nullptr, &byte, 1, &written));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_copy_value(&view, nullptr, 1, &written));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_copy_value(&view, &byte, 1, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_copy_encoded({nullptr, 1}, nullptr, 0, &written));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_copy_view(nullptr, &controlled::writer, nullptr, 0, &written));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_copy_view(&view, nullptr, nullptr, 0, &written));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_copy_view(&view, &controlled::writer, nullptr, 1, &written));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_copy_view(&view, &controlled::writer, nullptr, 0, nullptr));
    view.value.data = nullptr;
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_copy_value(&view, nullptr, 0, &written));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_copy_view(&view, &controlled::writer, nullptr, 0, &written));
    view.value = {&byte, 1};
    view.tag.size = 0;
    EXPECT_EQ(TLV_ERR_INVALID_TAG, tlv_copy_view(&view, &controlled::writer, nullptr, 0, &written));
    view.tag.size = 1;
    view.value.length = std::numeric_limits<size_t>::max();
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_copy_view(&view, &controlled::writer, nullptr, 0, &written));
    EXPECT_EQ(99u, written);
    EXPECT_EQ(0xEE, byte);
}
