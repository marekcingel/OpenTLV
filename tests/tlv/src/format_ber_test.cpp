#include "tlv/formats/asn1/ber.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#include <gtest/gtest.h>
#include <cstring>
#include <vector>

namespace {
const auto& ber = tlv_reader_format_ber;
const auto& ber_writer = tlv_writer_format_ber;
}

TEST(Ber, TagsAndLengthsRoundTrip) {
    const std::vector<std::vector<uint8_t>> tags = {{0x5A}, {0x5F, 0x2A},
        {0x9F, 0x1C}, {0x9F, 0x81, 0x01}, {0xBF, 0x81, 0x80, 0x00}};
    for (const auto& bytes : tags) {
        if (bytes.size() > TLV_TAG_MAX_SIZE) continue;
        tlv_tag_t tag{};
        tag.size = static_cast<uint8_t>(bytes.size());
        std::memcpy(tag.data, bytes.data(), bytes.size());
        for (size_t length : {0u, 1u, 127u, 128u, 255u, 256u, 65535u, 65536u}) {
            SCOPED_TRACE(length);
            std::vector<uint8_t> value(length, 0xAB);
            size_t required = 0;
            ASSERT_EQ(TLV_OK, tlv_encoded_size(tag, length, &ber_writer, &required));
            std::vector<uint8_t> data(required + 2);
            tlv_writer_t writer;
            ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, data.data(), data.size(), &ber_writer));
            ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, tag, value.data(), length));
            EXPECT_EQ(required, writer.pos);
            ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, (tlv_tag_t{{0x5A}, 1}), nullptr, 0));
            EXPECT_EQ(0, std::memcmp(bytes.data(), data.data(), bytes.size()));
            tlv_reader_t reader;
            ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data.data(), data.size(), &ber));
            tlv_view_t view{};
            ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &view));
            EXPECT_EQ(bytes.size(), view.tag.size);
            EXPECT_EQ(0, std::memcmp(bytes.data(), view.tag.data, bytes.size()));
            EXPECT_EQ(length, view.value.length);
            if (length) EXPECT_EQ(0, std::memcmp(value.data(), view.value.data, length));
            ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &view));
            EXPECT_EQ(0x5A, view.tag.data[0]);
            EXPECT_EQ(TLV_ERR_END_OF_BUFFER, tlv_reader_next(&reader, &view));
        }
    }
}

TEST(Ber, LengthWireBytesAndBounds) {
    struct LengthCase {
        size_t value;
        std::vector<uint8_t> bytes;
    };
    std::vector<uint8_t> max_length_bytes(sizeof(size_t) + 1, 0xFF);
    max_length_bytes[0] = 0x80 | sizeof(size_t);
    const LengthCase cases[] = {
        {0, {0}}, {127, {0x7F}}, {128, {0x81, 0x80}}, {255, {0x81, 0xFF}},
        {256, {0x82, 1, 0}}, {65535, {0x82, 0xFF, 0xFF}}, {65536, {0x83, 1, 0, 0}},
        {SIZE_MAX, max_length_bytes}};
    for (const auto& item : cases) {
        size_t used = 0, length = 0;
        ASSERT_EQ(TLV_OK, ber_writer.length_size(nullptr, item.value, &used));
        EXPECT_EQ(item.bytes.size(), used);
        std::vector<uint8_t> data(used, 0xEE);
        for (size_t capacity = 0; capacity < data.size(); ++capacity) {
            EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
                      ber_writer.write_length(nullptr, data.data(), capacity, item.value, &used));
            for (auto byte : data) EXPECT_EQ(0xEE, byte);
        }
        ASSERT_EQ(TLV_OK, ber_writer.write_length(nullptr, data.data(), data.size(), item.value, &used));
        EXPECT_EQ(item.bytes, data);
        ASSERT_EQ(TLV_OK, ber.read_length(nullptr, data.data(), data.size(), &length, &used));
        EXPECT_EQ(item.value, length);
        for (size_t size = 0; size < data.size(); ++size)
            EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
                      ber.read_length(nullptr, data.data(), size, &length, &used));
    }
}

TEST(Ber, InvalidAndNonminimalLengths) {
    size_t length = 42, used = 42;
    for (uint8_t prefix : {0x80, 0xFF})
        EXPECT_EQ(TLV_ERR_INVALID_LENGTH, ber.read_length(nullptr, &prefix, 1, &length, &used));
    std::vector<uint8_t> overflow(sizeof(size_t) + 2, 0);
    overflow[0] = 0x80 | (sizeof(size_t) + 1);
    overflow[1] = 1;
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
              ber.read_length(nullptr, overflow.data(), overflow.size(), &length, &used));
    EXPECT_EQ(42u, length);
    EXPECT_EQ(42u, used);
    const uint8_t padded[] = {0x83, 0, 0, 0x7F};
    ASSERT_EQ(TLV_OK, ber.read_length(nullptr, padded, sizeof(padded), &length, &used));
    EXPECT_EQ(127u, length);
    EXPECT_EQ(4u, used);
    size_t total = 42;
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
              tlv_encoded_size((tlv_tag_t{{0x5A}, 1}), SIZE_MAX, &ber_writer, &total));
    EXPECT_EQ(42u, total);
}

TEST(Ber, TagCapacityAndContinuation) {
    std::vector<uint8_t> bytes(TLV_TAG_MAX_SIZE, 0x81);
    bytes.front() = TLV_TAG_MAX_SIZE == 1 ? 0x5A : 0x9F;
    if (TLV_TAG_MAX_SIZE > 1) bytes.back() = 0x01;
    tlv_tag_t tag{};
    size_t used = 0;
    ASSERT_EQ(TLV_OK, ber.read_tag(nullptr, bytes.data(), bytes.size(), &tag, &used));
    EXPECT_EQ(bytes.size(), used);
    ASSERT_EQ(TLV_OK, ber_writer.write_tag(nullptr, nullptr, 0, &tag, &used));
    std::vector<uint8_t> output(bytes.size(), 0xEE);
    for (size_t capacity = 0; capacity < bytes.size(); ++capacity) {
        EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
                  ber_writer.write_tag(nullptr, output.data(), capacity, &tag, &used));
        for (auto byte : output) EXPECT_EQ(0xEE, byte);
    }
    ASSERT_EQ(TLV_OK, ber_writer.write_tag(nullptr, output.data(), output.size(), &tag, &used));
    EXPECT_EQ(bytes, output);
    bytes.assign(TLV_TAG_MAX_SIZE + 1, 0x81);
    bytes[0] = 0x9F;
    bytes.back() = 1;
    EXPECT_EQ(TLV_ERR_INVALID_TAG, ber.read_tag(nullptr, bytes.data(), bytes.size(), &tag, &used));
    EXPECT_EQ(TLV_ERR_INVALID_TAG, ber.read_tag(nullptr, bytes.data(), TLV_TAG_MAX_SIZE, &tag, &used));
    for (size_t size = 0; size < TLV_TAG_MAX_SIZE; ++size)
        EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, ber.read_tag(nullptr, bytes.data(), size, &tag, &used));
}

TEST(Ber, InvalidTagsAndWriterState) {
    const std::vector<std::vector<uint8_t>> invalid = {{}, {0x9F}, {0x5A, 1},
        {0x9F, 0}, {0x9F, 0x80, 1}, {0x9F, 0x81}, {0x9F, 1, 1}};
    for (const auto& bytes : invalid) {
        if (bytes.size() > TLV_TAG_MAX_SIZE) continue;
        tlv_tag_t tag{};
        tag.size = static_cast<uint8_t>(bytes.size());
        if (!bytes.empty()) std::memcpy(tag.data, bytes.data(), bytes.size());
        uint8_t data[16];
        std::memset(data, 0xEE, sizeof(data));
        tlv_writer_t writer;
        ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, data, sizeof(data), &ber_writer));
        EXPECT_EQ(TLV_ERR_INVALID_TAG, tlv_writer_write(&writer, tag, nullptr, 0));
        EXPECT_EQ(0u, writer.pos);
        for (auto byte : data) EXPECT_EQ(0xEE, byte);
    }
    if (TLV_TAG_MAX_SIZE < 255) {
        tlv_tag_t tag{};
        tag.size = static_cast<uint8_t>(TLV_TAG_MAX_SIZE + 1);
        size_t used;
        EXPECT_EQ(TLV_ERR_INVALID_TAG, ber_writer.write_tag(nullptr, nullptr, 0, &tag, &used));
    }
    const uint8_t invalid_tag[] = {0x9F, 0x80, 1};
    tlv_tag_t tag{};
    size_t used;
    EXPECT_EQ(TLV_ERR_INVALID_TAG,
              ber.read_tag(nullptr, invalid_tag, sizeof(invalid_tag), &tag, &used));
}

TEST(Ber, TruncationPreservesReaderOutput) {
    std::vector<uint8_t> data = {0x5A, 0x81, 0x80};
    data.resize(131, 0xAB);
    for (size_t size = 0; size < data.size(); ++size) {
        tlv_reader_t reader;
        ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data.data(), size, &ber));
        tlv_view_t view = {tlv_tag_t{{0xEE}, 1}, {nullptr, 42}};
        EXPECT_EQ(size ? TLV_ERR_BUFFER_TOO_SHORT : TLV_ERR_END_OF_BUFFER,
                  tlv_reader_next(&reader, &view));
        EXPECT_EQ(0u, reader.pos);
        EXPECT_EQ(0xEE, view.tag.data[0]);
        EXPECT_EQ(nullptr, view.value.data);
        EXPECT_EQ(42u, view.value.length);
    }
}
