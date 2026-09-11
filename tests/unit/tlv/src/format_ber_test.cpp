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

TEST(Unit_Ber, InvalidAndNonminimalLengths) {
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

TEST(Unit_Ber, TagCapacityAndContinuation) {
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

TEST(Unit_Ber, InvalidTagsAndWriterState) {
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

TEST(Unit_Ber, TruncationPreservesReaderOutput) {
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

TEST(Unit_Ber, IndefiniteWriterCapacityValidationAndDefault) {
    const tlv_tag_t tag = {{0x30}, 1};
    const uint8_t value[] = {0x04, 2, 0, 0};
    uint8_t output[16];
    size_t written = 999;
    for (size_t capacity = 0; capacity < 8; ++capacity) {
        std::memset(output, 0xEE, sizeof(output));
        EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
            tlv_ber_write_indefinite(output, capacity, tag, value, sizeof(value), &written));
        EXPECT_EQ(999u, written);
        for (auto byte : output) EXPECT_EQ(0xEE, byte);
    }
    const std::vector<std::vector<uint8_t>> invalid = {
        {0, 0}, {0x04}, {0x04, 2, 0}, {0x04, 0x80, 0, 0},
        {0x30, 0x80}, {0x30, 2, 0, 0}
    };
    for (const auto& bytes : invalid) {
        EXPECT_NE(TLV_OK, tlv_ber_write_indefinite(output, sizeof(output), tag,
            bytes.data(), bytes.size(), &written));
        EXPECT_EQ(999u, written);
        for (auto byte : output) EXPECT_EQ(0xEE, byte);
    }
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_ber_indefinite_encoded_size(tag, SIZE_MAX, &written));
    EXPECT_EQ(999u, written);
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_ber_indefinite_encoded_size(tlv_tag_t{{4}, 1}, 0, &written));
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_ber_write_indefinite(output, sizeof(output),
        tlv_tag_t{{4}, 1}, nullptr, 0, &written));
    EXPECT_EQ(999u, written);
    for (auto byte : output) EXPECT_EQ(0xEE, byte);
    EXPECT_EQ(TLV_ERR_INVALID_TAG, tlv_ber_indefinite_encoded_size(tlv_tag_t{{0}, 1}, 0, &written));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_ber_indefinite_encoded_size(tag, 0, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_ber_write_indefinite(nullptr, 4, tag, nullptr, 0, &written));
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_ber_write_indefinite(nullptr, 0, tag, nullptr, 0, &written));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_ber_write_indefinite(output, sizeof(output), tag, nullptr, 1, &written));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_ber_write_indefinite(output, sizeof(output), tag, nullptr, 0, nullptr));
    tlv_writer_t writer{};
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, output, 10, &ber_writer));
    ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, tag, nullptr, 0));
    EXPECT_EQ(0x30, output[0]); EXPECT_EQ(0, output[1]);
    ASSERT_EQ(TLV_OK, tlv_ber_writer_write_indefinite(&writer, tag, value, sizeof(value)));
    EXPECT_EQ(10u, writer.pos);
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_ber_writer_write_indefinite(&writer, tag, nullptr, 0));
    EXPECT_EQ(10u, writer.pos);
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_ber_writer_write_indefinite(nullptr, tag, nullptr, 0));
    writer.format = nullptr;
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_ber_writer_write_indefinite(&writer, tag, nullptr, 0));
}

