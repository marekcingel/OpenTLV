#include "tlv/formats/fixed/fixed_1byte.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#include <gtest/gtest.h>
#include <cstring>
#include <limits>

TEST(Fixed1Byte, ExampleWireBytes) {
    const uint8_t expected[] = {0x01, 0x03, 0xAA, 0xBB, 0xCC};
    uint8_t data[sizeof(expected)] = {};
    tlv_writer_t writer;
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, data, sizeof(data), &tlv_writer_format_fixed_1byte));
    ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, (tlv_tag_t{{1}, 1}), expected + 2, 3));
    EXPECT_EQ(sizeof(expected), tlv_writer_size(&writer));
    EXPECT_EQ(0, std::memcmp(expected, data, sizeof(data)));
}

TEST(Fixed1Byte, EveryTagAndLengthRoundTrip) {
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

TEST(Fixed1Byte, TruncationPreservesReaderAndOutput) {
    const uint8_t data[] = {1, 3, 0xAA, 0xBB, 0xCC};
    for (size_t size = 0; size < sizeof(data); ++size) {
        tlv_reader_t reader;
        ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, size, &tlv_reader_format_fixed_1byte));
        tlv_view_t entry = {tlv_tag_t{{0xEE}, 1}, {nullptr, 42}};
        EXPECT_EQ(size ? TLV_ERR_BUFFER_TOO_SHORT : TLV_ERR_END_OF_BUFFER,
                  tlv_reader_next(&reader, &entry));
        EXPECT_EQ(0u, reader.pos);
        EXPECT_EQ(0xEE, entry.tag.data[0]);
        EXPECT_EQ(nullptr, entry.value.data);
        EXPECT_EQ(42u, entry.value.length);
    }
}

TEST(Fixed1Byte, InvalidWritesPreserveBufferAndPosition) {
    uint8_t data[258];
    std::memset(data, 0xEE, sizeof(data));
    uint8_t value[256] = {};
    tlv_writer_t writer;
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, data, sizeof(data), &tlv_writer_format_fixed_1byte));
    const tlv_tag_t tag = {{1}, 1};
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_writer_write(&writer, tag, value, 256));
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
              tlv_writer_write(&writer, tag, value, std::numeric_limits<size_t>::max()));
    EXPECT_EQ(TLV_ERR_INVALID_TAG, tlv_writer_write(&writer, (tlv_tag_t{{0}, 0}), nullptr, 0));
    EXPECT_EQ(TLV_ERR_INVALID_TAG, tlv_writer_write(&writer, (tlv_tag_t{{0}, 2}), nullptr, 0));
    EXPECT_EQ(0u, writer.pos);
    for (auto byte : data) EXPECT_EQ(0xEE, byte);
    for (size_t capacity = 0; capacity < 5; ++capacity) {
        ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, data, capacity, &tlv_writer_format_fixed_1byte));
        EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_writer_write(&writer, tag, value, 3));
        EXPECT_EQ(0u, writer.pos);
        for (auto byte : data) EXPECT_EQ(0xEE, byte);
    }
}

TEST(Fixed1Byte, CallbacksRejectMissingBytes) {
    const auto& format = tlv_reader_format_fixed_1byte;
    tlv_tag_t tag = {{0xFF}, 1};
    size_t used = 0, length = 0;
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, format.read_tag(nullptr, nullptr, 0, &tag, &used));
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, format.read_length(nullptr, nullptr, 0, &length, &used));
    ASSERT_EQ(TLV_OK, tlv_writer_format_fixed_1byte.write_tag(nullptr, nullptr, 0, &tag, &used));
    EXPECT_EQ(1u, used);
    uint8_t data = 0xEE;
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_writer_format_fixed_1byte.write_tag(nullptr, &data, 0, &tag, &used));
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_writer_format_fixed_1byte.write_length(nullptr, &data, 0, 255, &used));
    EXPECT_EQ(0xEE, data);
}
