#include "tlv/types.h"

#include <gtest/gtest.h>

TEST(Unit_TLVTypes, zero_initialization_produces_empty_view) {
    tlv_view_t empty{};
    EXPECT_EQ(0, empty.tag.size);
    EXPECT_EQ(nullptr, empty.value.data);
    EXPECT_EQ(0u, empty.value.length);
}

TEST(Unit_TLVTypes, tag_stores_raw_bytes_at_every_supported_size) {
    tlv_tag_t tag{};
    ASSERT_EQ(TLV_TAG_MAX_SIZE, sizeof(tag.data));

    for (size_t size = 1; size <= TLV_TAG_MAX_SIZE; ++size) {
        SCOPED_TRACE(size);
        for (size_t i = 0; i < size; ++i) {
            tag.data[i] = static_cast<uint8_t>(0x9F + i);
        }
        tag.size = static_cast<uint8_t>(size);
        tlv_tag_t copy = tag;
        tag.data[0] = 0;
        EXPECT_EQ(size, copy.size);
        for (size_t i = 0; i < size; ++i) {
            EXPECT_EQ(static_cast<uint8_t>(0x9F + i), copy.data[i]);
        }
    }
}

TEST(Unit_TLVTypes, buffer_borrows_byte_range) {
    uint8_t storage[] = {0x12, 0x34, 0x56};
    tlv_buffer_t buffer = {storage + 1, 2};
    EXPECT_EQ(storage + 1, buffer.data);
    EXPECT_EQ(2u, buffer.length);
    storage[1] = 0xAB;
    EXPECT_EQ(0xAB, buffer.data[0]);
    EXPECT_EQ(0x56, buffer.data[1]);
}

TEST(Unit_TLVTypes, copying_view_copies_tag_and_borrows_value) {
    uint8_t storage[] = {0x12, 0x34, 0x56};
    tlv_view_t view = {{{0x81}, 1}, {storage + 1, 2}};
    tlv_view_t copy = view;
    EXPECT_EQ(1, copy.tag.size);
    EXPECT_EQ(0x81, copy.tag.data[0]);
    EXPECT_EQ(storage + 1, copy.value.data);
    EXPECT_EQ(2u, copy.value.length);
    storage[1] = 0xAB;
    EXPECT_EQ(0xAB, copy.value.data[0]);
    EXPECT_EQ(0x56, copy.value.data[1]);
    view.tag.data[0] = 0;
    EXPECT_EQ(0x81, copy.tag.data[0]);
}

TEST(Unit_TLVTypes, result_distinguishes_success_from_error) {
    tlv_result_t result = TLV_OK;
    EXPECT_EQ(0, result);
    EXPECT_NE(TLV_OK, TLV_ERR_NULL_ARG);
}
