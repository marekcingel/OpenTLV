#include "tlv/formats/fixed/fixed_1byte.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#include <gtest/gtest.h>
#include <cstring>
#include <limits>

TEST(Integration_Fixed1Byte, ExampleWireBytes) {
    const uint8_t expected[] = {0x01, 0x03, 0xAA, 0xBB, 0xCC};
    uint8_t data[sizeof(expected)] = {};
    tlv_writer_t writer;
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, data, sizeof(data), &tlv_writer_format_fixed_1byte));
    ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, (tlv_tag_t{{1}, 1}), expected + 2, 3));
    EXPECT_EQ(sizeof(expected), tlv_writer_size(&writer));
    EXPECT_EQ(0, std::memcmp(expected, data, sizeof(data)));
}

TEST(Integration_Fixed1Byte, EveryTagAndLengthRoundTrip) {
    uint8_t value[255];
    std::memset(value, 0xAB, sizeof(value));
    for (size_t byte = 0; byte <= 255; ++byte) {
        SCOPED_TRACE(byte);
        uint8_t data[259] = {};
        tlv_writer_t writer;
        ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, data, sizeof(data), &tlv_writer_format_fixed_1byte));
        const tlv_tag_t tag = {{static_cast<uint8_t>(byte)}, 1};
        ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, tag, value, byte));
        ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, (tlv_tag_t{{0}, 1}), nullptr, 0));
        EXPECT_EQ(byte + 4, tlv_writer_size(&writer));
        EXPECT_EQ(byte, data[0]);
        EXPECT_EQ(byte, data[1]);
        tlv_reader_t reader;
        ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, writer.pos, &tlv_reader_format_fixed_1byte));
        tlv_view_t entry{};
        ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &entry));
        EXPECT_EQ(1, entry.tag.size);
        EXPECT_EQ(byte, entry.tag.data[0]);
        EXPECT_EQ(byte, entry.value.length);
        EXPECT_EQ(data + 2, entry.value.data);
        EXPECT_EQ(0, std::memcmp(value, entry.value.data, byte));
        ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &entry));
        EXPECT_EQ(0, entry.tag.data[0]);
        EXPECT_EQ(0u, entry.value.length);
        EXPECT_TRUE(tlv_reader_at_end(&reader));
        EXPECT_EQ(TLV_ERR_END_OF_BUFFER, tlv_reader_next(&reader, &entry));
    }
}

