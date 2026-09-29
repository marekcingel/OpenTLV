#include "tlv/schema/schema.h"
#include "tlv/schema/number.h"
#include "tlv/reader/reader.h"
#include <gtest/gtest.h>

namespace {
static const tlv_schema_entry_t entries[] = {
    {TLV_TAG(2), 2, 4, 0, "two", 0},
    {TLV_TAG(1), 3, 3, 0, nullptr, 0},
    {TLV_TAG(0x9F, 0x02), 0, SIZE_MAX, UINT32_MAX & ~TLV_SCHEMA_LENGTH_ENDPOINTS, nullptr, 0},
    {TLV_TAG(2), 9, 9, 0, nullptr, 0},
    {tlv_tag(nullptr, 0), 0, 0, 0, nullptr, 0}};
static const tlv_schema_t schema = {entries, sizeof(entries) / sizeof(entries[0])};
} // namespace

TEST(Unit_Tlv_Schema, LengthMultipleCombinesWithBoundsWithoutOverflow) {
    tlv_schema_entry_t rule = {TLV_TAG(1), 0, SIZE_MAX, 0, nullptr, 16};
    EXPECT_EQ(TLV_OK, tlv_schema_validate_length(&rule, 0));
    EXPECT_EQ(TLV_OK, tlv_schema_validate_length(&rule, 32));
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_schema_validate_length(&rule, 31));
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_schema_validate_length(&rule, SIZE_MAX));
    rule.length_multiple = SIZE_MAX;
    EXPECT_EQ(TLV_OK, tlv_schema_validate_length(&rule, SIZE_MAX));
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_schema_validate_length(&rule, SIZE_MAX - 1));
    rule.length_multiple = 4;
    rule.min_length = 5;
    rule.max_length = 9;
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_schema_validate_length(&rule, 4));
    EXPECT_EQ(TLV_OK, tlv_schema_validate_length(&rule, 8));
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_schema_validate_length(&rule, 9));
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_schema_validate_length(&rule, 12));
    rule.length_multiple = 0;
    EXPECT_EQ(TLV_OK, tlv_schema_validate_length(&rule, 9));
    rule.length_multiple = 1;
    EXPECT_EQ(TLV_OK, tlv_schema_validate_length(&rule, 9));
}

TEST(Unit_Tlv_Schema, LengthEndpointsCombineWithMultipleAndBoundaryValues) {
    tlv_schema_entry_t rule = {TLV_TAG(1), 4, 8, TLV_SCHEMA_LENGTH_ENDPOINTS, nullptr, 0};
    for (size_t length = 0; length <= 10; ++length)
        EXPECT_EQ(length == 4 || length == 8 ? TLV_OK : TLV_ERR_INVALID_LENGTH,
                  tlv_schema_validate_length(&rule, length));
    rule.length_multiple = 8;
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_schema_validate_length(&rule, 4));
    EXPECT_EQ(TLV_OK, tlv_schema_validate_length(&rule, 8));
    rule.length_multiple = 0;
    rule.min_length = rule.max_length = 4;
    EXPECT_EQ(TLV_OK, tlv_schema_validate_length(&rule, 4));
    rule.min_length = 5;
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_schema_validate_length(&rule, 4));
    rule.min_length = 0;
    rule.max_length = SIZE_MAX;
    EXPECT_EQ(TLV_OK, tlv_schema_validate_length(&rule, 0));
    EXPECT_EQ(TLV_OK, tlv_schema_validate_length(&rule, SIZE_MAX));
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_schema_validate_length(&rule, 1));
    rule.flags = UINT32_MAX & ~TLV_SCHEMA_LENGTH_ENDPOINTS;
    EXPECT_EQ(TLV_OK, tlv_schema_validate_length(&rule, 1));
}

TEST(Unit_Tlv_Schema, FindsUnsortedTagsAndReturnsFirstDuplicate) {
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

TEST(Unit_Tlv_Schema, NameIsBorrowedAndOptional) {
    tlv_tag_t tag = TLV_TAG(2);
    EXPECT_STREQ("two", tlv_schema_find(&schema, &tag)->name);
    tag = TLV_TAG(1);
    EXPECT_EQ(nullptr, tlv_schema_find(&schema, &tag)->name);
}

TEST(Unit_Tlv_Schema, HandlesEmptyMissingAndInvalidInputs) {
    tlv_tag_t tag = TLV_TAG(7);
    EXPECT_EQ(nullptr, tlv_schema_find(&schema, &tag));
    EXPECT_EQ(nullptr, tlv_schema_find(nullptr, &tag));
    EXPECT_EQ(nullptr, tlv_schema_find(&schema, nullptr));
    const tlv_schema_t empty = {nullptr, 0};
    const tlv_schema_t missing = {nullptr, 1};
    EXPECT_EQ(nullptr, tlv_schema_find(&empty, &tag));
    EXPECT_EQ(nullptr, tlv_schema_find(&missing, &tag));
}

TEST(Unit_Tlv_Schema, ValidatesExactAndInclusiveRangeLengths) {
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
    const tlv_schema_entry_t reversed = {TLV_TAG(1), 4, 2, 0, nullptr, 0};
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_schema_validate_length(&reversed, 3));
}

TEST(Unit_Tlv_Schema, NumberCompositionSelectsSchemaWidthsWithoutCopyingPolicy) {
    const tlv_schema_entry_t  field = {TLV_TAG(1), 1, 3, TLV_SCHEMA_LENGTH_ENDPOINTS, nullptr, 0};
    const tlv_schema_number_t config = {&field, {TLV_NUMBER_BINARY_BE, 0, 0}};
    const auto                codec = tlv_schema_number_codec(&config);
    const uint64_t            number = 256;
    uint8_t                   wire[3] = {0xAA, 0xAA, 0xAA};
    size_t                    written = 99;
    ASSERT_EQ(TLV_CODEC_OK,
              tlv_codec_encode(&codec, &number, sizeof(number), wire, sizeof(wire), &written));
    EXPECT_EQ(3u, written);
    EXPECT_EQ(0, wire[0]);
    EXPECT_EQ(1, wire[1]);
    EXPECT_EQ(0, wire[2]);
    uint64_t decoded = 99;
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_decode(&codec, wire + 1, 2, &decoded, sizeof(decoded)));
    EXPECT_EQ(99u, decoded);
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_decode(&codec, wire, 3, &decoded, sizeof(decoded)));
    EXPECT_EQ(number, decoded);
    EXPECT_EQ(TLV_CODEC_ERR_BUFFER_TOO_SHORT,
              tlv_codec_encode(&codec, &number, sizeof(number), wire, 2, &written));
    EXPECT_EQ(0u, written);
    EXPECT_EQ(1, wire[1]);
    const tlv_schema_number_t fixed = {&field, {TLV_NUMBER_BINARY_BE, 2, 0}};
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_schema_number_encode(&fixed, &number, sizeof(number), nullptr, 0, &written));
    EXPECT_EQ(0u, written);
    const tlv_schema_entry_t  impossible = {TLV_TAG(1), 9, 12, 0, nullptr, 0};
    const tlv_schema_number_t unsupported = {&impossible, {TLV_NUMBER_BINARY_BE, 0, 0}};
    EXPECT_EQ(
        TLV_CODEC_ERR_INVALID_VALUE,
        tlv_schema_number_encode(&unsupported, &number, sizeof(number), nullptr, 0, &written));
    EXPECT_EQ(TLV_CODEC_ERR_NULL_ARG,
              tlv_schema_number_decode(nullptr, wire, 3, &decoded, sizeof(decoded)));
    EXPECT_EQ(TLV_CODEC_ERR_NULL_ARG,
              tlv_schema_number_encode(nullptr, &number, sizeof(number), nullptr, 0, &written));
}
