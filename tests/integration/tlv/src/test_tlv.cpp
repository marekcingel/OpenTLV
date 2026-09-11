#include "tlv/formats/default/default.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"

#include <gtest/gtest.h>

#include <cstring>

TEST(Integration_TLV, reader_parses_single_short_form_entry) {
  /* tag=0x01, len=0x03 (short form), value = "abc" */
  const uint8_t data[] = {0x01, 0x03, 'a', 'b', 'c'};
  tlv_reader_t reader;
  ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data), &tlv_reader_format_default));

  tlv_view_t entry;
  ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &entry));
  ASSERT_EQ(1, entry.tag.size);
  ASSERT_EQ(0x01, entry.tag.data[0]);
  ASSERT_EQ(3, entry.value.length);
  ASSERT_EQ(0, std::memcmp("abc", entry.value.data, 3));
  ASSERT_TRUE(tlv_reader_at_end(&reader));
}

TEST(Integration_TLV, reader_parses_multiple_entries) {
  const uint8_t data[] = {0x01, 0x02, 'h', 'i', 0x02, 0x01, 'x'};
  tlv_reader_t reader;
  ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data), &tlv_reader_format_default));

  tlv_view_t e1, e2;
  ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &e1));
  ASSERT_EQ(0x01, e1.tag.data[0]);
  ASSERT_EQ(2, e1.value.length);

  ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &e2));
  ASSERT_EQ(0x02, e2.tag.data[0]);
  ASSERT_EQ(1, e2.value.length);
  ASSERT_EQ('x', e2.value.data[0]);

  ASSERT_TRUE(tlv_reader_at_end(&reader));
}

TEST(Integration_TLV, reader_parses_ber_long_form_1byte_length) {
  /* length 200 -> 0x81 0xC8, value of 200 'A' bytes */
  uint8_t data[3 + 200];
  data[0] = 0x05;
  data[1] = 0x81;
  data[2] = 200;
  std::memset(data + 3, 'A', 200);

  tlv_reader_t reader;
  ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data), &tlv_reader_format_default));

  tlv_view_t entry;
  ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &entry));
  ASSERT_EQ(0x05, entry.tag.data[0]);
  ASSERT_EQ(200, entry.value.length);
  ASSERT_EQ('A', entry.value.data[0]);
  ASSERT_EQ('A', entry.value.data[199]);
}

TEST(Integration_TLV, reader_parses_ber_long_form_2byte_length) {
  /* length 300 -> 0x82 0x01 0x2C */
  size_t len = 300;
  uint8_t data[4 + 300];
  data[0] = 0x07;
  data[1] = 0x82;
  data[2] = 0x01;
  data[3] = 0x2C;
  std::memset(data + 4, 'Z', len);

  tlv_reader_t reader;
  ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data), &tlv_reader_format_default));

  tlv_view_t entry;
  ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &entry));
  ASSERT_EQ(0x07, entry.tag.data[0]);
  ASSERT_EQ(300, entry.value.length);
}

/* ---------- Writer tests ---------- */

TEST(Integration_TLV, writer_writes_short_form_entry) {
  uint8_t buf[16];
  tlv_writer_t writer;
  ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, buf, sizeof(buf), &tlv_writer_format_default));

  const uint8_t value[] = {'a', 'b', 'c'};
  ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, (tlv_tag_t{{0x01}, 1}), value, sizeof(value)));

  ASSERT_EQ(5, tlv_writer_size(&writer));
  ASSERT_EQ(0x01, buf[0]);
  ASSERT_EQ(0x03, buf[1]);
  ASSERT_EQ(0, std::memcmp("abc", buf + 2, 3));
}

TEST(Integration_TLV, writer_writes_long_form_1byte_length) {
  uint8_t buf[512];
  tlv_writer_t writer;
  ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, buf, sizeof(buf), &tlv_writer_format_default));

  uint8_t value[200];
  memset(value, 'A', sizeof(value));
  ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, (tlv_tag_t{{0x05}, 1}), value, sizeof(value)));

  ASSERT_EQ(1 + 2 + 200, tlv_writer_size(&writer));
  ASSERT_EQ(0x05, buf[0]);
  ASSERT_EQ(0x81, buf[1]);
  ASSERT_EQ(200, buf[2]);
}

TEST(Integration_TLV, writer_reader_roundtrip) {
  uint8_t buf[64];
  tlv_writer_t writer;
  ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, buf, sizeof(buf), &tlv_writer_format_default));

  ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, (tlv_tag_t{{0x01}, 1}), (const uint8_t *)"hi", 2));
  ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, (tlv_tag_t{{0x02}, 1}), (const uint8_t *)"x", 1));

  tlv_reader_t reader;
  ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, buf, tlv_writer_size(&writer), &tlv_reader_format_default));

  tlv_view_t e1, e2;
  ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &e1));
  ASSERT_EQ(0x01, e1.tag.data[0]);
  ASSERT_EQ(0, std::memcmp("hi", e1.value.data, 2));

  ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &e2));
  ASSERT_EQ(0x02, e2.tag.data[0]);
  ASSERT_EQ(0, std::memcmp("x", e2.value.data, 1));

  ASSERT_TRUE(tlv_reader_at_end(&reader));
}
