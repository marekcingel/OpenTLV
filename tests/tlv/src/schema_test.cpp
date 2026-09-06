#include "tlv/schema.h"
#include "tlv/reader.h"
#include <gtest/gtest.h>

namespace {
static const tlv_schema_entry_t entries[] = {
    {{{2}, 1}, 2, 4, 0},
    {{{1}, 1}, 3, 3, 0},
    {{{0x9F, 0x02}, 2}, 0, SIZE_MAX, UINT32_MAX},
    {{{2}, 1}, 9, 9, 0},
    {{{0}, 0}, 0, 0, 0}
};
static const tlv_schema_t schema = {entries, sizeof(entries) / sizeof(entries[0])};
}

TEST(Schema, FindsUnsortedTagsAndReturnsFirstDuplicate) {
    tlv_tag_t tag = {{1}, 1};
    EXPECT_EQ(&entries[1], tlv_schema_find(&schema, &tag));
    tag.data[0] = 2;
    EXPECT_EQ(&entries[0], tlv_schema_find(&schema, &tag));
    tag = {{0x9F, 0x02}, 2};
    EXPECT_EQ(&entries[2], tlv_schema_find(&schema, &tag));
    tag.size = 1;
    EXPECT_EQ(nullptr, tlv_schema_find(&schema, &tag));
    tag = {{1, 0xFF}, 1}; // Inactive bytes do not participate in comparison.
    EXPECT_EQ(&entries[1], tlv_schema_find(&schema, &tag));
    tag.size = 0;
    EXPECT_EQ(&entries[4], tlv_schema_find(&schema, &tag));
}

TEST(Schema, HandlesEmptyMissingAndInvalidInputs) {
    tlv_tag_t tag = {{7}, 1};
    EXPECT_EQ(nullptr, tlv_schema_find(&schema, &tag));
    EXPECT_EQ(nullptr, tlv_schema_find(nullptr, &tag));
    EXPECT_EQ(nullptr, tlv_schema_find(&schema, nullptr));
    const tlv_schema_t empty = {nullptr, 0};
    const tlv_schema_t missing = {nullptr, 1};
    EXPECT_EQ(nullptr, tlv_schema_find(&empty, &tag));
    EXPECT_EQ(nullptr, tlv_schema_find(&missing, &tag));
#if TLV_TAG_MAX_SIZE < 255
    tag.size = TLV_TAG_MAX_SIZE + 1;
    EXPECT_EQ(nullptr, tlv_schema_find(&schema, &tag));
    const tlv_schema_entry_t invalid_entries[] = {
        {tag, 0, 0, 0}, entries[0]
    };
    const tlv_schema_t invalid = {invalid_entries, 2};
    tag = {{2}, 1};
    EXPECT_EQ(&invalid_entries[1], tlv_schema_find(&invalid, &tag));
#endif
}

TEST(Schema, ValidatesExactAndInclusiveRangeLengths) {
    for (size_t length = 0; length <= 5; ++length) {
        EXPECT_EQ(length >= 2 && length <= 4 ? TLV_OK : TLV_ERR_INVALID_LENGTH,
                  tlv_schema_validate_length(&entries[0], length));
        EXPECT_EQ(length == 3 ? TLV_OK : TLV_ERR_INVALID_LENGTH,
                  tlv_schema_validate_length(&entries[1], length));
    }
    EXPECT_EQ(TLV_OK, tlv_schema_validate_length(&entries[2], 0));
    EXPECT_EQ(TLV_OK, tlv_schema_validate_length(&entries[2], SIZE_MAX));
    EXPECT_EQ(TLV_OK, tlv_schema_validate_length(&entries[4], 0));
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_schema_validate_length(&entries[4], 1));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_schema_validate_length(nullptr, 0));
    const tlv_schema_entry_t reversed = {{{1}, 1}, 4, 2, 0};
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_schema_validate_length(&reversed, 3));
}

TEST(Schema, ReaderParsesUnknownTagsAndLengthsOutsideSchema) {
    const uint8_t data[] = {7, 0, 1, 0};
    tlv_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data), &tlv_format_fixed_1byte));
    tlv_view_t view;
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &view));
    EXPECT_EQ(nullptr, tlv_schema_find(&schema, &view.tag));
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &view));
    const auto* entry = tlv_schema_find(&schema, &view.tag);
    ASSERT_NE(nullptr, entry);
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_schema_validate_length(entry, view.value.length));
}
