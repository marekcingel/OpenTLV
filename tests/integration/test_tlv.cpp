#include "tlv/builtins/fixed/default.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"

#include <gtest/gtest.h>

#include <cstring>

TEST(Integration_Tlv, ReaderParsesSingleShortFormEntry) {
    /* tag=0x01, len=0x03 (short form), value = "abc" */
    const uint8_t data[] = {0x01, 0x03, 'a', 'b', 'c'};
    tlv_reader_t  reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data), &tlv_format_default));

    tlv_element_t element;
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
    ASSERT_EQ(1, element.tag.size);
    ASSERT_EQ(0x01, element.tag.data[0]);
    ASSERT_EQ(3, element.value.size);
    ASSERT_EQ(0, std::memcmp("abc", element.value.data, 3));
    ASSERT_TRUE(tlv_reader_at_end(&reader));
}

TEST(Integration_Tlv, ReaderParsesMultipleEntries) {
    const uint8_t data[] = {0x01, 0x02, 'h', 'i', 0x02, 0x01, 'x'};
    tlv_reader_t  reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data), &tlv_format_default));

    tlv_element_t e1, e2;
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &e1));
    ASSERT_EQ(0x01, e1.tag.data[0]);
    ASSERT_EQ(2, e1.value.size);

    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &e2));
    ASSERT_EQ(0x02, e2.tag.data[0]);
    ASSERT_EQ(1, e2.value.size);
    ASSERT_EQ('x', e2.value.data[0]);

    ASSERT_TRUE(tlv_reader_at_end(&reader));
}

TEST(Integration_Tlv, ReaderParsesBerLongForm1ByteLength) {
    /* length 200 -> 0x81 0xC8, value of 200 'A' bytes */
    uint8_t data[3 + 200];
    data[0] = 0x05;
    data[1] = 0x81;
    data[2] = 200;
    std::memset(data + 3, 'A', 200);

    tlv_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data), &tlv_format_default));

    tlv_element_t element;
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
    ASSERT_EQ(0x05, element.tag.data[0]);
    ASSERT_EQ(200, element.value.size);
    ASSERT_EQ('A', element.value.data[0]);
    ASSERT_EQ('A', element.value.data[199]);
}

TEST(Integration_Tlv, ReaderParsesBerLongForm2ByteLength) {
    /* length 300 -> 0x82 0x01 0x2C */
    size_t  len = 300;
    uint8_t data[4 + 300];
    data[0] = 0x07;
    data[1] = 0x82;
    data[2] = 0x01;
    data[3] = 0x2C;
    std::memset(data + 4, 'Z', len);

    tlv_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data), &tlv_format_default));

    tlv_element_t element;
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
    ASSERT_EQ(0x07, element.tag.data[0]);
    ASSERT_EQ(300, element.value.size);
}

/* ---------- Writer tests ---------- */

TEST(Integration_Tlv, WriterWritesShortFormEntry) {
    uint8_t      buf[16];
    tlv_writer_t writer;
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, buf, sizeof(buf), &tlv_format_default));

    const uint8_t value[] = {'a', 'b', 'c'};
    ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, (TLV_TAG(0x01)), value, sizeof(value)));

    ASSERT_EQ(5, tlv_writer_size(&writer));
    ASSERT_EQ(0x01, buf[0]);
    ASSERT_EQ(0x03, buf[1]);
    ASSERT_EQ(0, std::memcmp("abc", buf + 2, 3));
}

TEST(Integration_Tlv, WriterWritesLongForm1ByteLength) {
    uint8_t      buf[512];
    tlv_writer_t writer;
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, buf, sizeof(buf), &tlv_format_default));

    uint8_t value[200];
    memset(value, 'A', sizeof(value));
    ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, (TLV_TAG(0x05)), value, sizeof(value)));

    ASSERT_EQ(1 + 2 + 200, tlv_writer_size(&writer));
    ASSERT_EQ(0x05, buf[0]);
    ASSERT_EQ(0x81, buf[1]);
    ASSERT_EQ(200, buf[2]);
}

TEST(Integration_Tlv, WriterReaderRoundtrip) {
    uint8_t      buf[64];
    tlv_writer_t writer;
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, buf, sizeof(buf), &tlv_format_default));

    ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, (TLV_TAG(0x01)), (const uint8_t*)"hi", 2));
    ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, (TLV_TAG(0x02)), (const uint8_t*)"x", 1));

    tlv_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, buf, tlv_writer_size(&writer), &tlv_format_default));

    tlv_element_t e1, e2;
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &e1));
    ASSERT_EQ(0x01, e1.tag.data[0]);
    ASSERT_EQ(0, std::memcmp("hi", e1.value.data, 2));

    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &e2));
    ASSERT_EQ(0x02, e2.tag.data[0]);
    ASSERT_EQ(0, std::memcmp("x", e2.value.data, 1));

    ASSERT_TRUE(tlv_reader_at_end(&reader));
}
