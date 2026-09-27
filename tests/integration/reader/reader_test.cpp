#include "tlv/builtins/fixed/default.h"
#include "tlv/reader/reader.h"
#include <gtest/gtest.h>
#include <limits>

TEST(Integration_Tlv_Reader, EmptyValueAndBerLength) {
    const uint8_t data[] = {0x42, 0x82, 0, 0};
    tlv_element_t element{};
    size_t        consumed = 0;
    ASSERT_EQ(TLV_OK, tlv_read(data, sizeof(data), &tlv_format_default, &element, &consumed));
    EXPECT_EQ(data + sizeof(data), element.value.data);
    EXPECT_EQ(0u, element.value.size);
    EXPECT_EQ(sizeof(data), consumed);
}

namespace {
void expect_failure(const uint8_t* data, size_t size, const tlv_format_t* format,
                    tlv_result_t error) {
    tlv_element_t element = {TLV_TAG(0xEE), {}, {data, 42}};
    size_t        consumed = 99;
    EXPECT_EQ(error, tlv_read(data, size, format, &element, &consumed));
    EXPECT_EQ(99u, consumed);
    EXPECT_EQ(1u, element.tag.size);
    EXPECT_EQ(0xEE, element.tag.data[0]);
    EXPECT_EQ(data, element.value.data);
    EXPECT_EQ(42u, element.value.size);
}
} // namespace

TEST(Integration_Tlv_Reader, DetectsTruncatedBerLengthAndValue) {
    const uint8_t data[] = {1, 0x82, 0, 2, 0xAB, 0xCD};
    for (size_t size = 1; size < sizeof(data); ++size)
        expect_failure(data, size, &tlv_format_default, TLV_ERR_BUFFER_TOO_SHORT);
    const uint8_t invalid[] = {1, 0x80};
    expect_failure(invalid, sizeof(invalid), &tlv_format_default, TLV_ERR_INVALID_LENGTH);
}
