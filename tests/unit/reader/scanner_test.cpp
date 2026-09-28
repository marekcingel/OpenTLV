#include "controlled_format.h"
#include "tlv/reader/scanner.h"
#include "tlv/reader/reader.h"
#include <gtest/gtest.h>

namespace {
tlv_result_t read_pair_tag(const void* context, const uint8_t* data, size_t size, tlv_tag_t* tag,
                           size_t* used) {
    if (size < 2) return TLV_ERR_BUFFER_TOO_SHORT;
    if (data[0] != *static_cast<const uint8_t*>(context) || data[1] != 0x1C)
        return TLV_ERR_INVALID_TAG;
    *tag = tlv_tag(data, 2);
    *used = 2;
    return TLV_OK;
}

class Unit_Tlv_Scanner : public ::testing::Test {
protected:
    tlv_element_t element = {TLV_TAG(0xAA), {nullptr, 99}};
    size_t        offset = 88;
    size_t        consumed = 77;

    tlv_result_t scan(const uint8_t* data, size_t size, size_t start = 0,
                      const tlv_schema_t* filter = nullptr,
                      const tlv_format_t* format = &controlled::format) {
        return tlv_scan(data, size, start, format, filter, &element, &offset, &consumed);
    }

    void unchanged() {
        EXPECT_EQ(0xAA, element.tag.data[0]);
        EXPECT_EQ(1, element.tag.size);
        EXPECT_EQ(nullptr, element.value.data);
        EXPECT_EQ(99u, element.value.size);
        EXPECT_EQ(88u, offset);
        EXPECT_EQ(77u, consumed);
    }
};
} // namespace

TEST_F(Unit_Tlv_Scanner, HandlesNoMatchEmptyInputAndOutOfRangeStart) {
    const uint8_t data[] = {0xFF, 0xFF, 0xFF};
    EXPECT_EQ(TLV_ERR_END_OF_BUFFER, scan(data, sizeof(data)));
    EXPECT_EQ(TLV_ERR_END_OF_BUFFER, scan(nullptr, 0));
    EXPECT_EQ(TLV_ERR_END_OF_BUFFER, scan(data, sizeof(data), sizeof(data)));
    EXPECT_EQ(TLV_ERR_END_OF_BUFFER, scan(data, sizeof(data), SIZE_MAX));
    unchanged();
}

TEST_F(Unit_Tlv_Scanner, ValidatesArgumentsWithoutChangingOutputs) {
    const uint8_t data[] = {1, 0};
    EXPECT_EQ(TLV_ERR_NULL_ARG, scan(nullptr, 1));
    EXPECT_EQ(TLV_ERR_NULL_ARG, scan(data, sizeof(data), 0, nullptr, nullptr));
    tlv_format_t format = controlled::format;
    format.decode = nullptr;
    EXPECT_EQ(TLV_ERR_NULL_ARG, scan(data, sizeof(data), 0, nullptr, &format));
    format = controlled::format;
    format.decode = nullptr;
    EXPECT_EQ(TLV_ERR_NULL_ARG, scan(nullptr, 0, 0, nullptr, &format));
    const tlv_schema_t invalid = {nullptr, 1};
    EXPECT_EQ(TLV_ERR_NULL_ARG, scan(data, sizeof(data), 0, &invalid));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_scan(data, sizeof(data), 0, &controlled::format, nullptr,
                                         nullptr, &offset, &consumed));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_scan(data, sizeof(data), 0, &controlled::format, nullptr,
                                         &element, nullptr, &consumed));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_scan(data, sizeof(data), 0, &controlled::format, nullptr,
                                         &element, &offset, nullptr));
    unchanged();
}

TEST_F(Unit_Tlv_Scanner, UsesCustomTagCallbackAndContext) {
    const uint8_t      prefix = 0x9F;
    tlv_format_t       format = controlled::format;
    tlv_field_layout_t layout = controlled::format_layout;
    layout.context = &prefix;
    layout.read_tag = read_pair_tag;
    format.context = &layout;
    const uint8_t            data[] = {0xFF, 0xFF, 0x9F, 0x1C, 1, 0xAA};
    const tlv_schema_entry_t rule = {TLV_TAG(0x9F, 0x1C), 1, 1, 0, nullptr, 0};
    const tlv_schema_t       filter = {&rule, 1};
    ASSERT_EQ(TLV_OK, scan(data, sizeof(data), 1, &filter, &format));
    EXPECT_EQ(2u, offset);
    EXPECT_EQ(4u, consumed);
    EXPECT_EQ(2, element.tag.size);
    EXPECT_EQ(data + 2, element.tag.data);
    EXPECT_EQ(0x9F, element.tag.data[0]);
    EXPECT_EQ(0x1C, element.tag.data[1]);
    EXPECT_EQ(data + 5, element.value.data);
}
