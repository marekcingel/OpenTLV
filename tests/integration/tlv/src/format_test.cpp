#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#include <gtest/gtest.h>
#include <cstring>
#include <limits>

#if TLV_TAG_MAX_SIZE >= 2

namespace {
// Two raw tag bytes, and a configurable fixed-width little-endian length.
const size_t width = 2;
tlv_result_t read_tag(const void*, const uint8_t* data, size_t size,
                      tlv_tag_t* tag, size_t* used) {
    if (size < 2) return TLV_ERR_BUFFER_TOO_SHORT;
    *tag = tlv_tag_t{{data[0], data[1]}, 2};
    *used = 2;
    return TLV_OK;
}
tlv_result_t write_tag(const void*, uint8_t* data, size_t size,
                       const tlv_tag_t* tag, size_t* used) {
    if (tag->size != 2) return TLV_ERR_INVALID_TAG;
    *used = 2;
    if (!data) return TLV_OK;
    if (size < 2) return TLV_ERR_BUFFER_TOO_SHORT;
    std::memcpy(data, tag->data, 2);
    return TLV_OK;
}
tlv_result_t length_size(const void* ctx, size_t length, size_t* used) {
    if (length > 65535) return TLV_ERR_INVALID_LENGTH;
    *used = *static_cast<const size_t*>(ctx);
    return TLV_OK;
}
tlv_result_t read_length(const void* ctx, const uint8_t* data, size_t size,
                         size_t* length, size_t* used) {
    *used = *static_cast<const size_t*>(ctx);
    if (size < *used) return TLV_ERR_BUFFER_TOO_SHORT;
    *length = data[0] | (static_cast<size_t>(data[1]) << 8);
    return TLV_OK;
}
tlv_result_t write_length(const void* ctx, uint8_t* data, size_t size,
                          size_t length, size_t* used) {
    const auto rc = length_size(ctx, length, used);
    if (rc != TLV_OK) return rc;
    if (size < *used) return TLV_ERR_BUFFER_TOO_SHORT;
    data[0] = static_cast<uint8_t>(length);
    data[1] = static_cast<uint8_t>(length >> 8);
    return TLV_OK;
}
const tlv_reader_format_t fixed = {&width, read_tag, read_length, nullptr};
const tlv_writer_format_t fixed_writer = {&width, write_tag, write_length, length_size};
}

TEST(Integration_Format, CustomFormatRoundTripAndWireBytes) {
    uint8_t data[308] = {};
    uint8_t value[300];
    std::memset(value, 0xAB, sizeof(value));
    tlv_writer_t writer;
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, data, sizeof(data), &fixed_writer));
    ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, (tlv_tag_t{{0x9F, 0x02}, 2}), value, sizeof(value)));
    ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, (tlv_tag_t{{0xAA, 0xBB}, 2}), nullptr, 0));
    EXPECT_EQ(sizeof(data), tlv_writer_size(&writer));
    const uint8_t header[] = {0x9F, 0x02, 0x2C, 0x01};
    EXPECT_EQ(0, std::memcmp(header, data, sizeof(header)));
    size_t required = 0, written = 0;
    const tlv_tag_t tag = {{0x9F, 0x02}, 2};
    ASSERT_EQ(TLV_OK, tlv_encoded_size(tag, sizeof(value), &fixed_writer, &required));
    EXPECT_EQ(304u, required);
    uint8_t direct[304] = {};
    ASSERT_EQ(TLV_OK, tlv_write(direct, sizeof(direct), &fixed_writer, tag,
                                value, sizeof(value), &written));
    EXPECT_EQ(required, written);
    EXPECT_EQ(0, std::memcmp(direct, data, sizeof(direct)));
    tlv_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data), &fixed));
    tlv_view_t entry{};
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &entry));
    EXPECT_EQ(2, entry.tag.size);
    EXPECT_EQ(0x9F, entry.tag.data[0]);
    EXPECT_EQ(0x02, entry.tag.data[1]);
    EXPECT_EQ(data + 4, entry.value.data);
    EXPECT_EQ(sizeof(value), entry.value.length);
    EXPECT_EQ(0, std::memcmp(value, entry.value.data, sizeof(value)));
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &entry));
    EXPECT_EQ(0xBB, entry.tag.data[1]);
    EXPECT_EQ(0u, entry.value.length);
    EXPECT_TRUE(tlv_reader_at_end(&reader));
}

#endif // TLV_TAG_MAX_SIZE >= 2
