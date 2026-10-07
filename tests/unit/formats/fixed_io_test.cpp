// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/formats/fixed.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"

#include <gtest/gtest.h>

#include <cstring>

namespace {
const tlv_fixed_format_t fixed_config = {
    {1}, {1, TLV_BYTE_ORDER_BIG_ENDIAN}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
const tlv_format_t fixed_format = [] {
    tlv_format_t format{};
    (void)tlv_fixed_format_init(&format, &fixed_config);
    return format;
}();
} // namespace

TEST(Unit_Tlv, ReaderDetectsBufferTooShortForValue) {
    /* claims the value has 5 bytes, but the buffer has only 2 */
    const uint8_t data[] = {0x01, 0x05, 'a', 'b'};
    tlv_reader_t  reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data), &fixed_format));

    tlv_element_t element;
    ASSERT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_reader_next(&reader, &element));
}

TEST(Unit_Tlv, ReaderDetectsEndOfBuffer) {
    const uint8_t data[] = {0x01, 0x00};
    tlv_reader_t  reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data), &fixed_format));

    tlv_element_t element;
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
    ASSERT_EQ(0, element.value.size);
    ASSERT_TRUE(tlv_reader_at_end(&reader));
    ASSERT_EQ(TLV_ERR_END_OF_BUFFER, tlv_reader_next(&reader, &element));
}

TEST(Unit_Tlv, ReaderRejectsNullArgs) {
    ASSERT_EQ(TLV_ERR_NULL_ARG, tlv_reader_init(NULL, NULL, 0, &fixed_format));
}

/* ---------- Writer tests ---------- */

TEST(Unit_Tlv, ReaderBorrowsTagAndValue) {
    uint8_t      data[] = {0x01, 0x01, 0xAB};
    tlv_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data), &fixed_format));
    tlv_element_t element{};
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
    EXPECT_EQ(1, element.tag.size);
    EXPECT_EQ(data, element.tag.data);
    EXPECT_EQ(data + 2, element.value.data);
    // Nothing is copied: changing the input shows through the tag and the value.
    data[0] = 0x02;
    data[2] = 0xCD;
    EXPECT_EQ(0x02, element.tag.data[0]);
    EXPECT_EQ(0xCD, element.value.data[0]);
}

TEST(Unit_Tlv, WriterRejectsUnsupportedTagSizesWithoutWriting) {
    uint8_t buf[8];
    std::memset(buf, 0xAA, sizeof(buf));
    tlv_writer_t writer;
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, buf, sizeof(buf), &fixed_format));
    // The format, not the tag type, limits tags to one byte, however long the tag is.
    const std::vector<uint8_t> tag_bytes(300, 0x42);
    for (size_t size = 0; size <= tag_bytes.size(); ++size) {
        if (size == 1) continue;
        SCOPED_TRACE(size);
        const tlv_tag_t tag = tlv_tag(size ? tag_bytes.data() : nullptr, size);
        EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE, tlv_writer_write(&writer, tag, nullptr, 0));
        EXPECT_EQ(0u, tlv_writer_size(&writer));
        for (uint8_t byte : buf) EXPECT_EQ(0xAA, byte);
    }
    // A tag that claims a byte but has no pointer is rejected before the format sees it.
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_writer_write(&writer, tlv_tag(nullptr, 1), nullptr, 0));
    EXPECT_EQ(0u, tlv_writer_size(&writer));
    for (uint8_t byte : buf) EXPECT_EQ(0xAA, byte);
    EXPECT_EQ(12, TLV_ERR_INVALID_BYTE_ORDER);
    EXPECT_STREQ("invalid byte order", tlv_strerror(TLV_ERR_INVALID_BYTE_ORDER));
    EXPECT_EQ(11, TLV_ERR_INVALID_TAG_SIZE);
    EXPECT_STREQ("invalid tag size", tlv_strerror(TLV_ERR_INVALID_TAG_SIZE));
    EXPECT_STREQ("invalid tag", tlv_strerror(TLV_ERR_INVALID_TAG));
}

TEST(Unit_Tlv, WriterDetectsBufferTooShort) {
    uint8_t      buf[3];
    tlv_writer_t writer;
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, buf, sizeof(buf), &fixed_format));

    const uint8_t value[] = {'a', 'b', 'c', 'd'};
    ASSERT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              tlv_writer_write(&writer, (TLV_TAG(0x01)), value, sizeof(value)));
}
