#include "tlv/view.h"

#include <gtest/gtest.h>

#include <vector>

TEST(Unit_TLVView, zero_initialization_produces_empty_view) {
    tlv_view_t empty{};
    EXPECT_EQ(nullptr, empty.tag.data);
    EXPECT_EQ(0u, empty.tag.size);
    EXPECT_EQ(nullptr, empty.value.data);
    EXPECT_EQ(0u, empty.value.length);
}

TEST(Unit_TLVView, tag_borrows_raw_bytes_of_any_size) {
    std::vector<uint8_t> bytes(300);
    for (size_t i = 0; i < bytes.size(); ++i) bytes[i] = static_cast<uint8_t>(0x9F + i);

    for (size_t size : {size_t(1), size_t(2), size_t(8), size_t(9), size_t(16), size_t(300)}) {
        SCOPED_TRACE(size);
        tlv_tag_t tag = tlv_tag(bytes.data(), size);
        tlv_tag_t copy = tag;
        // A copy refers to the same bytes: nothing is stored inline.
        EXPECT_EQ(bytes.data(), copy.data);
        EXPECT_EQ(size, copy.size);
        bytes[0] = static_cast<uint8_t>(bytes[0] + 1);
        EXPECT_EQ(bytes[0], copy.data[0]);
        bytes[0] = static_cast<uint8_t>(bytes[0] - 1);
    }
}

TEST(Unit_TLVView, copying_view_copies_the_descriptors_and_borrows_the_bytes) {
    uint8_t    tag_bytes[] = {0x81};
    uint8_t    storage[] = {0x12, 0x34, 0x56};
    tlv_view_t view = {tlv_tag(tag_bytes, sizeof(tag_bytes)), {storage + 1, 2}};
    tlv_view_t copy = view;
    EXPECT_EQ(1u, copy.tag.size);
    EXPECT_EQ(tag_bytes, copy.tag.data);
    EXPECT_EQ(storage + 1, copy.value.data);
    EXPECT_EQ(2u, copy.value.length);
    storage[1] = 0xAB;
    EXPECT_EQ(0xAB, copy.value.data[0]);
    EXPECT_EQ(0x56, copy.value.data[1]);
    // The tag is borrowed as well, so a change of the bytes shows in every copy.
    tag_bytes[0] = 0x00;
    EXPECT_EQ(0x00, copy.tag.data[0]);
}

TEST(Unit_TLVView, result_distinguishes_success_from_error) {
    tlv_result_t result = TLV_OK;
    EXPECT_EQ(0, result);
    EXPECT_NE(TLV_OK, TLV_ERR_NULL_ARG);
}
