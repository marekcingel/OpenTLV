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

TEST(Integration_Ber, TagsAndLengthsRoundTrip) {
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

TEST(Integration_Ber, LengthWireBytesAndBounds) {
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

TEST(Integration_Ber, IndefiniteReferenceEncodingsAndRoundTrip) {
    const std::vector<std::vector<uint8_t>> values = {
        {}, {0x04, 3, 0, 0, 0xFF},
        {0x30, 0x80, 0, 0},
        {0x30, 0x80, 0x04, 2, 0, 0, 0, 0, 0x04, 0},
        {0x30, 6, 0x30, 0x80, 0, 0, 0x04, 0},
        {0x30, 0x80, 0x30, 2, 0x04, 0, 0, 0}
    };
    const tlv_tag_t tag = {{0x30}, 1};
    for (const auto& value : values) {
        std::vector<uint8_t> expected = {0x30, 0x80};
        expected.insert(expected.end(), value.begin(), value.end());
        expected.insert(expected.end(), {0, 0});
        size_t required = 0, written = 999, used = 999;
        ASSERT_EQ(TLV_OK, tlv_ber_indefinite_encoded_size(tag, value.size(), &required));
        EXPECT_EQ(expected.size(), required);
        std::vector<uint8_t> output(required, 0xEE);
        ASSERT_EQ(TLV_OK, tlv_ber_write_indefinite(output.data(), output.size(), tag,
            value.data(), value.size(), &written));
        EXPECT_EQ(expected, output);
        EXPECT_EQ(required, written);
        // A following sibling is outside the outer EOC.
        output.insert(output.end(), {0x04, 0});
        tlv_view_t view{};
        ASSERT_EQ(TLV_OK, tlv_read(output.data(), output.size(), &ber, &view, &used));
        EXPECT_EQ(required, used);
        EXPECT_EQ(value.size(), view.value.length);
        EXPECT_EQ(output.data() + 2, view.value.data);
        if (!value.empty()) EXPECT_EQ(0, std::memcmp(value.data(), view.value.data, value.size()));
        tlv_reader_t reader{};
        ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, output.data(), output.size(), &ber));
        ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &view));
        EXPECT_EQ(required, reader.pos);
        ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &view));
        EXPECT_EQ(4, view.tag.data[0]);
        EXPECT_TRUE(tlv_reader_at_end(&reader));
        // Every proper prefix of a valid outer element is truncated.
        for (size_t size = 1; size < required; ++size) {
            view = tlv_view_t{tlv_tag_t{{0xEE}, 1}, {nullptr, 42}};
            used = 999;
            EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_read(output.data(), size, &ber, &view, &used));
            EXPECT_EQ(999u, used);
            EXPECT_EQ(0xEE, view.tag.data[0]);
            EXPECT_EQ(nullptr, view.value.data);
            EXPECT_EQ(42u, view.value.length);
        }
    }
}

TEST(Integration_Ber, IndefiniteMalformedInputIsAtomic) {
    struct Case { std::vector<uint8_t> wire; tlv_result_t result; };
    const Case cases[] = {
        {{0x04, 0x80, 0, 0}, TLV_ERR_INVALID_LENGTH},
        {{0x30, 0x80, 0x04, 0x80, 0, 0, 0, 0}, TLV_ERR_INVALID_LENGTH},
        {{0, 0}, TLV_ERR_INVALID_TAG},
        {{0, 1, 0}, TLV_ERR_INVALID_TAG},
        {{0x20, 0}, TLV_ERR_INVALID_TAG},
        {{0x30, 0x80, 0, 1, 0, 0, 0}, TLV_ERR_INVALID_LENGTH},
        {{0x30, 0x80, 0, 0x81, 0, 0, 0}, TLV_ERR_INVALID_LENGTH},
        {{0x30, 0x80, 0, 0x80, 0, 0}, TLV_ERR_INVALID_LENGTH},
        {{0x30, 0x80, 0x20, 0, 0, 0}, TLV_ERR_INVALID_TAG},
        {{0x30, 0x80, 0x30, 2, 0, 0, 0, 0}, TLV_ERR_INVALID_TAG},
        // A nested indefinite child cannot borrow EOC from outside its definite parent.
        {{0x30, 0x80, 0x30, 2, 0x30, 0x80, 0, 0, 0, 0}, TLV_ERR_BUFFER_TOO_SHORT},
        {{0x30, 0x80, 0x30, 3, 0x04, 2, 0, 0, 0}, TLV_ERR_BUFFER_TOO_SHORT},
        {{0x30, 0x80, 0x04, 0xFF, 0, 0}, TLV_ERR_INVALID_LENGTH},
        {{0x30, 0x80, 0x04, 2, 0, 0}, TLV_ERR_BUFFER_TOO_SHORT},
        {{0x30, 0x80, 0}, TLV_ERR_BUFFER_TOO_SHORT},
        {{0x30, 0x80, 0x30, 0x80, 0, 0}, TLV_ERR_BUFFER_TOO_SHORT}
    };
    for (const auto& item : cases) {
        tlv_reader_t reader{};
        ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, item.wire.data(), item.wire.size(), &ber));
        tlv_view_t view = {tlv_tag_t{{0xEE}, 1}, {nullptr, 42}};
        EXPECT_EQ(item.result, tlv_reader_next(&reader, &view));
        EXPECT_EQ(0u, reader.pos);
        EXPECT_EQ(0xEE, view.tag.data[0]);
        EXPECT_EQ(nullptr, view.value.data);
        EXPECT_EQ(42u, view.value.length);
    }
}

TEST(Integration_Ber, IndefiniteNestingLimitIncludesDefiniteScopes) {
    for (bool definite_child : {false, true}) {
        std::vector<uint8_t> wire;
        for (size_t depth = 0; depth < TLV_BER_MAX_DEPTH; ++depth)
            wire.insert(wire.end(), {0x30, 0x80});
        wire.resize(wire.size() + 2 * TLV_BER_MAX_DEPTH, 0);
        tlv_view_t view{};
        size_t used = 999;
        ASSERT_EQ(TLV_OK, tlv_read(wire.data(), wire.size(), &ber, &view, &used));
        EXPECT_EQ(wire.size(), used);
        std::vector<uint8_t> out(wire.size());
        ASSERT_EQ(TLV_OK, tlv_ber_write_indefinite(out.data(), out.size(), tlv_tag_t{{0x30}, 1},
            view.value.data, view.value.length, &used));
        EXPECT_EQ(wire, out);
        const size_t midpoint = 2 * TLV_BER_MAX_DEPTH;
        wire.insert(wire.begin() + midpoint, {0x30, static_cast<uint8_t>(definite_child ? 0 : 0x80)});
        if (!definite_child) wire.insert(wire.begin() + midpoint + 2, {0, 0});
        EXPECT_EQ(TLV_ERR_LIMIT, tlv_read(wire.data(), wire.size(), &ber, &view, &used));
        out.assign(wire.size(), 0xEE);
        EXPECT_EQ(TLV_ERR_LIMIT, tlv_ber_write_indefinite(out.data(), out.size(), tlv_tag_t{{0x30}, 1},
            wire.data() + 2, wire.size() - 4, &used));
        for (auto byte : out) EXPECT_EQ(0xEE, byte);
    }
}
