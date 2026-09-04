#include "tlv/reader.h"
#include "tlv/writer.h"

#include <gtest/gtest.h>


TEST(TLV, dhcp_option_1_test) {
  const uint8_t data[] = {0x01, 0x04, 0xFF, 0xFF, 0xFF, 0x00};

  tlv_reader_t reader;
  ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data)));

  tlv_entry_t entry;
  ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &entry));
  ASSERT_EQ(1, entry.tag.length);
  ASSERT_EQ(0x01, entry.tag.data[0]);
  ASSERT_EQ(4, entry.value.length);
}

TEST(TLV, dhcp_option_3_test) {
  const uint8_t data[] = {0x03, 0x04, 0xC0, 0xA8, 0x01, 0x01};

  tlv_reader_t reader;
  ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data)));

  tlv_entry_t entry;
  ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &entry));
  ASSERT_EQ(1, entry.tag.length);
  ASSERT_EQ(0x03, entry.tag.data[0]);
  ASSERT_EQ(4, entry.value.length);
}

TEST(TLV, dhcp_option_6_test) {
  const uint8_t data[] = {0x06, 0x08, 0x08, 0x08, 0x08,
                          0x08, 0x01, 0x01, 0x01, 0x01};

  tlv_reader_t reader;
  ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data)));

  tlv_entry_t entry;
  ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &entry));
  ASSERT_EQ(1, entry.tag.length);
  ASSERT_EQ(0x06, entry.tag.data[0]);
  ASSERT_EQ(8, entry.value.length);
}

TEST(TLV, dhcp_option_12_test) {
  const uint8_t data[] = {0x0C, 0x09, 0x6D, 0x79, 0x2D, 0x72,
                          0x6F, 0x75, 0x74, 0x65, 0x72};

  tlv_reader_t reader;
  ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data)));

  tlv_entry_t entry;
  ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &entry));
  ASSERT_EQ(1, entry.tag.length);
  ASSERT_EQ(0x0C, entry.tag.data[0]);
  ASSERT_EQ(9, entry.value.length);
}
