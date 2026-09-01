#include <string.h>
#include "test_framework.h"
#include "tlv/reader.h"
#include "tlv/writer.h"

/* ---------- Reader tests ---------- */

TLV_TEST(reader_parses_single_short_form_entry) {
    /* tag=0x01, len=0x03 (short form), value = "abc" */
    const uint8_t data[] = { 0x01, 0x03, 'a', 'b', 'c' };
    tlv_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data)));

    tlv_entry_t entry;
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &entry));
    ASSERT_EQ(0x01, entry.tag);
    ASSERT_EQ(3, entry.length);
    ASSERT_MEM_EQ("abc", entry.value, 3);
    ASSERT_TRUE(tlv_reader_at_end(&reader));
}

TLV_TEST(reader_parses_multiple_entries) {
    const uint8_t data[] = {
        0x01, 0x02, 'h', 'i',
        0x02, 0x01, 'x'
    };
    tlv_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data)));

    tlv_entry_t e1, e2;
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &e1));
    ASSERT_EQ(0x01, e1.tag);
    ASSERT_EQ(2, e1.length);

    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &e2));
    ASSERT_EQ(0x02, e2.tag);
    ASSERT_EQ(1, e2.length);
    ASSERT_EQ('x', e2.value[0]);

    ASSERT_TRUE(tlv_reader_at_end(&reader));
}

TLV_TEST(reader_parses_ber_long_form_1byte_length) {
    /* length 200 -> 0x81 0xC8, value of 200 'A' bytes */
    uint8_t data[3 + 200];
    data[0] = 0x05;
    data[1] = 0x81;
    data[2] = 200;
    memset(data + 3, 'A', 200);

    tlv_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data)));

    tlv_entry_t entry;
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &entry));
    ASSERT_EQ(0x05, entry.tag);
    ASSERT_EQ(200, entry.length);
    ASSERT_EQ('A', entry.value[0]);
    ASSERT_EQ('A', entry.value[199]);
}

TLV_TEST(reader_parses_ber_long_form_2byte_length) {
    /* length 300 -> 0x82 0x01 0x2C */
    size_t len = 300;
    uint8_t data[4 + 300];
    data[0] = 0x07;
    data[1] = 0x82;
    data[2] = 0x01;
    data[3] = 0x2C;
    memset(data + 4, 'Z', len);

    tlv_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data)));

    tlv_entry_t entry;
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &entry));
    ASSERT_EQ(0x07, entry.tag);
    ASSERT_EQ(300, entry.length);
}

TLV_TEST(reader_detects_buffer_too_short_for_value) {
    /* claims the value has 5 bytes, but the buffer has only 2 */
    const uint8_t data[] = { 0x01, 0x05, 'a', 'b' };
    tlv_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data)));

    tlv_entry_t entry;
    ASSERT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_reader_next(&reader, &entry));
}

TLV_TEST(reader_detects_end_of_buffer) {
    const uint8_t data[] = { 0x01, 0x00 };
    tlv_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data)));

    tlv_entry_t entry;
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &entry));
    ASSERT_EQ(0, entry.length);
    ASSERT_TRUE(tlv_reader_at_end(&reader));
    ASSERT_EQ(TLV_ERR_END_OF_BUFFER, tlv_reader_next(&reader, &entry));
}

TLV_TEST(reader_rejects_null_args) {
    ASSERT_EQ(TLV_ERR_NULL_ARG, tlv_reader_init(NULL, NULL, 0));
}

/* ---------- Writer tests ---------- */

TLV_TEST(writer_writes_short_form_entry) {
    uint8_t buf[16];
    tlv_writer_t writer;
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, buf, sizeof(buf)));

    const uint8_t value[] = { 'a', 'b', 'c' };
    ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, 0x01, value, sizeof(value)));

    ASSERT_EQ(5, tlv_writer_size(&writer));
    ASSERT_EQ(0x01, buf[0]);
    ASSERT_EQ(0x03, buf[1]);
    ASSERT_MEM_EQ("abc", buf + 2, 3);
}

TLV_TEST(writer_writes_long_form_1byte_length) {
    uint8_t buf[512];
    tlv_writer_t writer;
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, buf, sizeof(buf)));

    uint8_t value[200];
    memset(value, 'A', sizeof(value));
    ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, 0x05, value, sizeof(value)));

    ASSERT_EQ(1 + 2 + 200, tlv_writer_size(&writer));
    ASSERT_EQ(0x05, buf[0]);
    ASSERT_EQ(0x81, buf[1]);
    ASSERT_EQ(200, buf[2]);
}

TLV_TEST(writer_detects_buffer_too_short) {
    uint8_t buf[3];
    tlv_writer_t writer;
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, buf, sizeof(buf)));

    const uint8_t value[] = { 'a', 'b', 'c', 'd' };
    ASSERT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_writer_write(&writer, 0x01, value, sizeof(value)));
}

TLV_TEST(writer_reader_roundtrip) {
    uint8_t buf[64];
    tlv_writer_t writer;
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, buf, sizeof(buf)));

    ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, 0x01, (const uint8_t*)"hi", 2));
    ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, 0x02, (const uint8_t*)"x", 1));

    tlv_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, buf, tlv_writer_size(&writer)));

    tlv_entry_t e1, e2;
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &e1));
    ASSERT_EQ(0x01, e1.tag);
    ASSERT_MEM_EQ("hi", e1.value, 2);

    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &e2));
    ASSERT_EQ(0x02, e2.tag);
    ASSERT_MEM_EQ("x", e2.value, 1);

    ASSERT_TRUE(tlv_reader_at_end(&reader));
}

int main(void) {
    printf("OpenTLV C core tests\n");

    RUN_TEST(reader_parses_single_short_form_entry);
    RUN_TEST(reader_parses_multiple_entries);
    RUN_TEST(reader_parses_ber_long_form_1byte_length);
    RUN_TEST(reader_parses_ber_long_form_2byte_length);
    RUN_TEST(reader_detects_buffer_too_short_for_value);
    RUN_TEST(reader_detects_end_of_buffer);
    RUN_TEST(reader_rejects_null_args);

    RUN_TEST(writer_writes_short_form_entry);
    RUN_TEST(writer_writes_long_form_1byte_length);
    RUN_TEST(writer_detects_buffer_too_short);
    RUN_TEST(writer_reader_roundtrip);

    return TEST_SUMMARY();
}
