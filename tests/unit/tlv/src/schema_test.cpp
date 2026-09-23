#include "tlv/schema/schema.h"
#include "tlv/reader/reader.h"
#include <gtest/gtest.h>

namespace {
static const tlv_schema_entry_t entries[] = {
    {TLV_TAG(2), 2, 4, 0, "two"},
    {TLV_TAG(1), 3, 3, 0, nullptr},
    {TLV_TAG(0x9F, 0x02), 0, SIZE_MAX, UINT32_MAX, nullptr},
    {TLV_TAG(2), 9, 9, 0, nullptr},
    {tlv_tag(nullptr, 0), 0, 0, 0, nullptr}};
static const tlv_schema_t schema = {entries, sizeof(entries) / sizeof(entries[0])};
} // namespace

TEST(Unit_Schema, FindsUnsortedTagsAndReturnsFirstDuplicate) {
    tlv_tag_t tag = TLV_TAG(1);
    EXPECT_EQ(&entries[1], tlv_schema_find(&schema, &tag));
    tag = TLV_TAG(2);
    EXPECT_EQ(&entries[0], tlv_schema_find(&schema, &tag));
    tag = TLV_TAG(0x9F, 0x02);
    EXPECT_EQ(&entries[2], tlv_schema_find(&schema, &tag));
    tag = TLV_TAG(0x9F);
    EXPECT_EQ(nullptr, tlv_schema_find(&schema, &tag));
    // A tag matches by contents, whatever memory backs it or follows it.
    const uint8_t other_memory[] = {1, 0xFF};
    tag = tlv_tag(other_memory, 1);
    EXPECT_EQ(&entries[1], tlv_schema_find(&schema, &tag));
    tag = tlv_tag(nullptr, 0);
    EXPECT_EQ(&entries[4], tlv_schema_find(&schema, &tag));
}

TEST(Unit_Schema, NameIsBorrowedAndOptional) {
    tlv_tag_t tag = TLV_TAG(2);
    EXPECT_STREQ("two", tlv_schema_find(&schema, &tag)->name);
    tag = TLV_TAG(1);
    EXPECT_EQ(nullptr, tlv_schema_find(&schema, &tag)->name);
}

TEST(Unit_Schema, HandlesEmptyMissingAndInvalidInputs) {
    tlv_tag_t tag = TLV_TAG(7);
    EXPECT_EQ(nullptr, tlv_schema_find(&schema, &tag));
    EXPECT_EQ(nullptr, tlv_schema_find(nullptr, &tag));
    EXPECT_EQ(nullptr, tlv_schema_find(&schema, nullptr));
    const tlv_schema_t empty = {nullptr, 0};
    const tlv_schema_t missing = {nullptr, 1};
    EXPECT_EQ(nullptr, tlv_schema_find(&empty, &tag));
    EXPECT_EQ(nullptr, tlv_schema_find(&missing, &tag));
}

TEST(Unit_Schema, ValidatesExactAndInclusiveRangeLengths) {
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
    const tlv_schema_entry_t reversed = {TLV_TAG(1), 4, 2, 0, nullptr};
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_schema_validate_length(&reversed, 3));
}
