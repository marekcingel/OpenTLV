#include "tlv/copy.h"
#include "tlv/reader.h"
#include <gtest/gtest.h>
#include <cstring>
#include <limits>

TEST(Copy, ValueOutlivesInputWhileReaderRemainsZeroCopy) {
    uint8_t input[] = {1, 2, 0xAB, 0xCD};
    tlv_view_t view{};
    size_t consumed = 0, written = 99;
    ASSERT_EQ(TLV_OK, tlv_read(input, sizeof(input), &tlv_format_fixed_1byte,
                              &view, &consumed));
    EXPECT_EQ(input + 2, view.value.data);
    ASSERT_EQ(TLV_OK, tlv_copy_value(&view, nullptr, 0, &written));
    EXPECT_EQ(2u, written);
    uint8_t owned[3] = {};
    ASSERT_EQ(TLV_OK, tlv_copy_value(&view, owned, sizeof(owned), &written));
    EXPECT_EQ(2u, written);
    std::memset(input, 0, sizeof(input));
    EXPECT_EQ(0u, view.value.data[0]);
    EXPECT_EQ(0xAB, owned[0]);
    EXPECT_EQ(0xCD, owned[1]);
    EXPECT_EQ(0, owned[2]);
}

TEST(Copy, EncodedRangePreservesHeaderWhileViewUsesSelectedFormat) {
    uint8_t input[] = {0x5A, 0x81, 1, 0xAB}; // Nonminimal BER length.
    tlv_view_t view{};
    size_t consumed = 0, written = 99;
    ASSERT_EQ(TLV_OK, tlv_read(input, sizeof(input), &tlv_format_ber, &view, &consumed));
    const tlv_buffer_t range = {input, consumed};
    ASSERT_EQ(TLV_OK, tlv_copy_encoded(range, nullptr, 0, &written));
    EXPECT_EQ(sizeof(input), written);
    uint8_t exact[4] = {}, encoded[3] = {};
    ASSERT_EQ(TLV_OK, tlv_copy_encoded(range, exact, sizeof(exact), &written));
    EXPECT_EQ(0, std::memcmp(input, exact, sizeof(input)));
    ASSERT_EQ(TLV_OK, tlv_copy_view(&view, &tlv_format_ber, nullptr, 0, &written));
    EXPECT_EQ(sizeof(encoded), written);
    ASSERT_EQ(TLV_OK, tlv_copy_view(&view, &tlv_format_ber, encoded, sizeof(encoded), &written));
    EXPECT_EQ(sizeof(encoded), written);
    const uint8_t expected[] = {0x5A, 1, 0xAB};
    EXPECT_EQ(0, std::memcmp(expected, encoded, sizeof(expected)));
    std::memset(input, 0, sizeof(input));
    EXPECT_EQ(0xAB, exact[3]);
    EXPECT_EQ(0xAB, encoded[2]);
}

TEST(Copy, InsufficientCapacityLeavesOutputsUnchanged) {
    const uint8_t value[] = {0xAB, 0xCD};
    const tlv_view_t view = {{{1}, 1}, {value, sizeof(value)}};
    for (size_t capacity = 0; capacity < 4; ++capacity) {
        uint8_t output[] = {0xEE, 0xEE, 0xEE, 0xEE};
        size_t written = 99;
        EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
                  tlv_copy_view(&view, &tlv_format_fixed_1byte, output, capacity, &written));
        if (capacity < sizeof(value)) {
            EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_copy_value(&view, output, capacity, &written));
            EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_copy_encoded(view.value, output, capacity, &written));
        }
        EXPECT_EQ(99u, written);
        for (auto byte : output) EXPECT_EQ(0xEE, byte);
    }
}

TEST(Copy, EmptyValuesAndOverlappingByteRanges) {
    const tlv_view_t empty = {{{1}, 1}, {nullptr, 0}};
    size_t written = 99;
    uint8_t output[2] = {};
    EXPECT_EQ(TLV_OK, tlv_copy_value(&empty, nullptr, 0, &written));
    EXPECT_EQ(0u, written);
    EXPECT_EQ(TLV_OK, tlv_copy_value(&empty, output, 0, &written));
    EXPECT_EQ(TLV_OK, tlv_copy_encoded({nullptr, 0}, output, 0, &written));
    EXPECT_EQ(TLV_OK, tlv_copy_view(&empty, &tlv_format_fixed_1byte, output, 2, &written));
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

TEST(Copy, InvalidArgumentsAndEncodingErrors) {
    uint8_t byte = 0xEE;
    tlv_view_t view = {{{1}, 1}, {&byte, 1}};
    size_t written = 99;
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_copy_value(nullptr, &byte, 1, &written));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_copy_value(&view, nullptr, 1, &written));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_copy_value(&view, &byte, 1, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_copy_encoded({nullptr, 1}, nullptr, 0, &written));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_copy_view(nullptr, &tlv_format_ber, nullptr, 0, &written));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_copy_view(&view, nullptr, nullptr, 0, &written));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_copy_view(&view, &tlv_format_ber, nullptr, 1, &written));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_copy_view(&view, &tlv_format_ber, nullptr, 0, nullptr));
    view.value.data = nullptr;
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_copy_value(&view, nullptr, 0, &written));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_copy_view(&view, &tlv_format_ber, nullptr, 0, &written));
    view.value = {&byte, 1};
    view.tag.size = 0;
    EXPECT_EQ(TLV_ERR_INVALID_TAG, tlv_copy_view(&view, &tlv_format_ber, nullptr, 0, &written));
    view.tag.size = 1;
    view.value.length = std::numeric_limits<size_t>::max();
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_copy_view(&view, &tlv_format_ber, nullptr, 0, &written));
    EXPECT_EQ(99u, written);
    EXPECT_EQ(0xEE, byte);
}
