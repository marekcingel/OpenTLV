#include "tlv/formats/fixed/fixed_1byte.h"
#include "tlv/schemas/schema.h"
#include "tlv/reader/reader.h"
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

TEST(Integration_Schema, ReaderParsesUnknownTagsAndLengthsOutsideSchema) {
    const uint8_t data[] = {7, 0, 1, 0};
    tlv_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data), &tlv_reader_format_fixed_1byte));
    tlv_view_t view;
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &view));
    EXPECT_EQ(nullptr, tlv_schema_find(&schema, &view.tag));
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &view));
    const auto* entry = tlv_schema_find(&schema, &view.tag);
    ASSERT_NE(nullptr, entry);
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_schema_validate_length(entry, view.value.length));
}
