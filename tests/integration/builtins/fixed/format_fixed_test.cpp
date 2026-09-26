#include "tlv/builtins/fixed/fixed.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#include <gtest/gtest.h>
#include <cstring>

TEST(Integration_Tlv_Fixed, ExampleWireBytesTwoByteTagOneByteLength) {
    /* [tag: 2 bytes][length: 1 byte][value: N bytes], from the issue's example use case. */
    const tlv_fixed_config_t config = {2, 1, TLV_BYTE_ORDER_BIG_ENDIAN};
    tlv_writer_format_t      writer_format{};
    ASSERT_EQ(TLV_OK, tlv_fixed_writer_format_init(&writer_format, &config));

    const uint8_t expected[] = {0x12, 0x34, 0x03, 0xAA, 0xBB, 0xCC};
    uint8_t       data[sizeof(expected)] = {};
    tlv_writer_t  writer;
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, data, sizeof(data), &writer_format));
    ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, (TLV_TAG(0x12, 0x34)), expected + 3, 3));
    EXPECT_EQ(sizeof(expected), tlv_writer_size(&writer));
    EXPECT_EQ(0, std::memcmp(expected, data, sizeof(data)));

    tlv_reader_format_t reader_format{};
    ASSERT_EQ(TLV_OK, tlv_fixed_reader_format_init(&reader_format, &config));
    tlv_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, writer.pos, &reader_format));
    tlv_view_t entry{};
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &entry));
    EXPECT_EQ(2, entry.tag.size);
    EXPECT_EQ(0x12, entry.tag.data[0]);
    EXPECT_EQ(0x34, entry.tag.data[1]);
    EXPECT_EQ(3u, entry.value.length);
    EXPECT_EQ(0, std::memcmp(expected + 3, entry.value.data, 3));
    EXPECT_TRUE(tlv_reader_at_end(&reader));
}

TEST(Integration_Tlv_Fixed, ExampleWireBytesTwoByteLittleEndianLength) {
    /* Matches tlv::fixed_format<2, 2, TLV_BYTE_ORDER_LITTLE_ENDIAN>, documented in
     * docs/formats/fixed/configurable.md: 12 34 03 00 AA BB CC. */
    const tlv_fixed_config_t config = {2, 2, TLV_BYTE_ORDER_LITTLE_ENDIAN};
    tlv_writer_format_t      writer_format{};
    tlv_reader_format_t      reader_format{};
    ASSERT_EQ(TLV_OK, tlv_fixed_writer_format_init(&writer_format, &config));
    ASSERT_EQ(TLV_OK, tlv_fixed_reader_format_init(&reader_format, &config));

    const uint8_t expected[] = {0x12, 0x34, 0x03, 0x00, 0xAA, 0xBB, 0xCC};
    uint8_t       data[sizeof(expected)] = {};
    tlv_writer_t  writer;
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, data, sizeof(data), &writer_format));
    ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, (TLV_TAG(0x12, 0x34)), expected + 4, 3));
    EXPECT_EQ(0, std::memcmp(expected, data, sizeof(data)));

    tlv_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, writer.pos, &reader_format));
    tlv_view_t entry{};
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &entry));
    EXPECT_EQ(3u, entry.value.length);
    EXPECT_EQ(0, std::memcmp(expected + 4, entry.value.data, 3));
}

TEST(Integration_Tlv_Fixed, EveryLengthByteRoundTripsOneByteTagOneByteLength) {
    const tlv_fixed_config_t config = {1, 1, TLV_BYTE_ORDER_BIG_ENDIAN};
    tlv_writer_format_t      writer_format{};
    tlv_reader_format_t      reader_format{};
    ASSERT_EQ(TLV_OK, tlv_fixed_writer_format_init(&writer_format, &config));
    ASSERT_EQ(TLV_OK, tlv_fixed_reader_format_init(&reader_format, &config));

    uint8_t value[255];
    std::memset(value, 0xAB, sizeof(value));
    for (size_t byte = 0; byte <= 255; ++byte) {
        SCOPED_TRACE(byte);
        uint8_t      data[259] = {};
        tlv_writer_t writer;
        ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, data, sizeof(data), &writer_format));
        const uint8_t   tag_byte = static_cast<uint8_t>(byte);
        const tlv_tag_t tag = tlv_tag(&tag_byte, 1);
        ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, tag, value, byte));
        EXPECT_EQ(byte + 2, tlv_writer_size(&writer));
        EXPECT_EQ(byte, data[0]);
        EXPECT_EQ(byte, data[1]);

        tlv_reader_t reader;
        ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, writer.pos, &reader_format));
        tlv_view_t entry{};
        ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &entry));
        EXPECT_EQ(1, entry.tag.size);
        EXPECT_EQ(byte, entry.tag.data[0]);
        EXPECT_EQ(byte, entry.value.length);
        EXPECT_EQ(0, std::memcmp(value, entry.value.data, byte));
        EXPECT_TRUE(tlv_reader_at_end(&reader));
    }
}

TEST(Integration_Tlv_Fixed, RejectsLengthThatOverflowsConfiguredWidth) {
    const tlv_fixed_config_t config = {1, 1, TLV_BYTE_ORDER_BIG_ENDIAN};
    tlv_writer_format_t      writer_format{};
    ASSERT_EQ(TLV_OK, tlv_fixed_writer_format_init(&writer_format, &config));
    uint8_t      data[260] = {};
    tlv_writer_t writer;
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, data, sizeof(data), &writer_format));
    uint8_t value[256] = {};
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_writer_write(&writer, (TLV_TAG(1)), value, 256));
}
