#include "tlv/formats/default/default.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"

#include <gtest/gtest.h>

#include <cstring>

TEST(Unit_TLV, reader_detects_buffer_too_short_for_value) {
  /* claims the value has 5 bytes, but the buffer has only 2 */
  const uint8_t data[] = {0x01, 0x05, 'a', 'b'};
  tlv_reader_t reader;
  ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data), &tlv_reader_format_default));

  tlv_view_t entry;
  ASSERT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_reader_next(&reader, &entry));
}

TEST(Unit_TLV, reader_detects_end_of_buffer) {
  const uint8_t data[] = {0x01, 0x00};
  tlv_reader_t reader;
  ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data), &tlv_reader_format_default));

  tlv_view_t entry;
  ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &entry));
  ASSERT_EQ(0, entry.value.length);
  ASSERT_TRUE(tlv_reader_at_end(&reader));
  ASSERT_EQ(TLV_ERR_END_OF_BUFFER, tlv_reader_next(&reader, &entry));
}

TEST(Unit_TLV, reader_rejects_null_args) {
  ASSERT_EQ(TLV_ERR_NULL_ARG, tlv_reader_init(NULL, NULL, 0, &tlv_reader_format_default));
}

/* ---------- Writer tests ---------- */

TEST(Unit_TLV, reader_copies_tag_and_borrows_value) {
  uint8_t data[] = {0x01, 0x01, 0xAB};
  tlv_reader_t reader;
  ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data), &tlv_reader_format_default));
  tlv_view_t view{};
  ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &view));
  EXPECT_EQ(1, view.tag.size);
  EXPECT_EQ(data + 2, view.value.data);
  data[0] = 0x02;
  data[2] = 0xCD;
  EXPECT_EQ(0x01, view.tag.data[0]);
  EXPECT_EQ(0xCD, view.value.data[0]);
}

TEST(Unit_TLV, writer_rejects_unsupported_tag_sizes_without_writing) {
  uint8_t buf[8];
  std::memset(buf, 0xAA, sizeof(buf));
  tlv_writer_t writer;
  ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, buf, sizeof(buf), &tlv_writer_format_default));
  for (unsigned size = 0; size <= 255; ++size) {
    if (size == 1) continue;
    SCOPED_TRACE(size);
    tlv_tag_t tag{};
    tag.size = static_cast<uint8_t>(size);
    EXPECT_EQ(TLV_ERR_INVALID_TAG, tlv_writer_write(&writer, tag, nullptr, 0));
    EXPECT_EQ(0u, tlv_writer_size(&writer));
    for (uint8_t byte : buf) EXPECT_EQ(0xAA, byte);
  }
  EXPECT_STREQ("invalid tag", tlv_strerror(TLV_ERR_INVALID_TAG));
}

TEST(Unit_TLV, writer_detects_buffer_too_short) {
  uint8_t buf[3];
  tlv_writer_t writer;
  ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, buf, sizeof(buf), &tlv_writer_format_default));

  const uint8_t value[] = {'a', 'b', 'c', 'd'};
  ASSERT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
            tlv_writer_write(&writer, (tlv_tag_t{{0x01}, 1}), value, sizeof(value)));
}

