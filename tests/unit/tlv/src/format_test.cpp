#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#include <gtest/gtest.h>
#include <cstring>
#include <limits>
#include <vector>

namespace {
// Two raw tag bytes, and a configurable fixed-width little-endian length.
const size_t width = 2;
tlv_result_t read_tag(const void*, const uint8_t* data, size_t size, tlv_tag_t* tag, size_t* used) {
    if (size < 2) return TLV_ERR_BUFFER_TOO_SHORT;
    *tag = tlv_tag(data, 2);
    *used = 2;
    return TLV_OK;
}
tlv_result_t write_tag(const void*, uint8_t* data, size_t size, const tlv_tag_t* tag,
                       size_t* used) {
    if (tag->size != 2) return TLV_ERR_INVALID_TAG_SIZE;
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
tlv_result_t read_length(const void* ctx, const uint8_t* data, size_t size, size_t* length,
                         size_t* used) {
    *used = *static_cast<const size_t*>(ctx);
    if (size < *used) return TLV_ERR_BUFFER_TOO_SHORT;
    *length = data[0] | (static_cast<size_t>(data[1]) << 8);
    return TLV_OK;
}
tlv_result_t write_length(const void* ctx, uint8_t* data, size_t size, size_t length,
                          size_t* used) {
    const auto rc = length_size(ctx, length, used);
    if (rc != TLV_OK) return rc;
    if (size < *used) return TLV_ERR_BUFFER_TOO_SHORT;
    data[0] = static_cast<uint8_t>(length);
    data[1] = static_cast<uint8_t>(length >> 8);
    return TLV_OK;
}
const tlv_reader_format_t fixed = {&width, read_tag, read_length, nullptr, nullptr};
const tlv_writer_format_t fixed_writer = {&width, write_tag, write_length, length_size, nullptr};
} // namespace

TEST(Unit_Format, TruncationPreservesReaderStateAndOutput) {
    const uint8_t data[] = {0x9F, 0x02, 0x02, 0x00, 0xAB, 0xCD};
    for (size_t size = 1; size < sizeof(data); ++size) {
        tlv_reader_t reader;
        ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, size, &fixed));
        tlv_view_t entry = {TLV_TAG(0xEE), {nullptr, 42}};
        EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_reader_next(&reader, &entry));
        EXPECT_EQ(0u, reader.pos);
        EXPECT_EQ(0xEE, entry.tag.data[0]);
        EXPECT_EQ(42u, entry.value.length);
    }
}

TEST(Unit_Format, WriterPreflightDoesNotModifyBuffer) {
    uint8_t data[5];
    std::memset(data, 0xEE, sizeof(data));
    tlv_writer_t writer;
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, data, sizeof(data), &fixed_writer));
    const tlv_tag_t tag = TLV_TAG(1, 2);
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_writer_write(&writer, tag, data, 2));
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_writer_write(&writer, tag, data, 65536));
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE, tlv_writer_write(&writer, (TLV_TAG(1)), nullptr, 0));
    EXPECT_EQ(0u, writer.pos);
    for (auto byte : data) EXPECT_EQ(0xEE, byte);
}

TEST(Unit_Format, RequiredCallbacksAreValidatedPerDirection) {
    tlv_reader_t reader;
    tlv_writer_t writer;
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_reader_init(&reader, nullptr, 0, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_writer_init(&writer, nullptr, 0, nullptr));
    tlv_reader_format_t format = fixed;
    format.read_tag = nullptr;
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_reader_init(&reader, nullptr, 0, &format));
    EXPECT_EQ(TLV_OK, tlv_writer_init(&writer, nullptr, 0, &fixed_writer));
    format = fixed;
    format.read_length = nullptr;
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_reader_init(&reader, nullptr, 0, &format));
    for (int i = 0; i < 3; ++i) {
        tlv_writer_format_t output_format = fixed_writer;
        if (i == 0) output_format.write_tag = nullptr;
        if (i == 1) output_format.write_length = nullptr;
        if (i == 2) output_format.length_size = nullptr;
        EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_writer_init(&writer, nullptr, 0, &output_format));
        EXPECT_EQ(TLV_OK, tlv_reader_init(&reader, nullptr, 0, &fixed));
    }
}

TEST(Unit_Format, InvalidCallbackSizesAndErrorsDoNotAdvance) {
    uint8_t             data[8] = {};
    tlv_reader_format_t format = fixed;
    format.read_tag = [](const void*, const uint8_t*, size_t, tlv_tag_t*, size_t* used) {
        *used = std::numeric_limits<size_t>::max();
        return TLV_OK;
    };
    tlv_reader_t reader;
    tlv_view_t   entry{};
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data), &format));
    EXPECT_EQ(TLV_ERR_INVALID_TAG, tlv_reader_next(&reader, &entry));
    EXPECT_EQ(0u, reader.pos);
    format = fixed;
    format.read_length = [](const void*, const uint8_t*, size_t, size_t* length, size_t* used) {
        *used = 2;
        *length = std::numeric_limits<size_t>::max();
        return TLV_OK;
    };
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_reader_next(&reader, &entry));
    EXPECT_EQ(0u, reader.pos);
    format.read_length = [](const void*, const uint8_t*, size_t, size_t*, size_t* used) {
        *used = std::numeric_limits<size_t>::max();
        return TLV_OK;
    };
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_reader_next(&reader, &entry));
    tlv_writer_format_t output_format = fixed_writer;
    output_format.write_length = [](const void*, uint8_t*, size_t, size_t, size_t*) {
        return TLV_ERR_INVALID_LENGTH;
    };
    tlv_writer_t writer;
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, data, sizeof(data), &output_format));
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_writer_write(&writer, (TLV_TAG(1, 2)), nullptr, 0));
    EXPECT_EQ(0u, writer.pos);
    output_format.write_length = [](const void*, uint8_t*, size_t, size_t, size_t* used) {
        *used = 3;
        return TLV_OK;
    };
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_writer_write(&writer, (TLV_TAG(1, 2)), nullptr, 0));
    EXPECT_EQ(0u, writer.pos);
}

namespace {
// A format whose tag width is chosen at runtime, as a format loaded from a
// description would: nothing about the width is known when OpenTLV is built.
struct RuntimeTagFormat {
    size_t tag_width;
};

const size_t& width_of(const void* ctx) {
    return static_cast<const RuntimeTagFormat*>(ctx)->tag_width;
}
tlv_result_t runtime_read_tag(const void* ctx, const uint8_t* data, size_t size, tlv_tag_t* tag,
                              size_t* used) {
    if (size < width_of(ctx)) return TLV_ERR_BUFFER_TOO_SHORT;
    *tag = tlv_tag(data, width_of(ctx));
    *used = width_of(ctx);
    return TLV_OK;
}
tlv_result_t runtime_write_tag(const void* ctx, uint8_t* data, size_t size, const tlv_tag_t* tag,
                               size_t* used) {
    if (tag->size != width_of(ctx)) return TLV_ERR_INVALID_TAG_SIZE;
    *used = tag->size;
    if (!data) return TLV_OK;
    if (size < tag->size) return TLV_ERR_BUFFER_TOO_SHORT;
    std::memcpy(data, tag->data, tag->size);
    return TLV_OK;
}
tlv_result_t one_byte_length_size(const void*, size_t length, size_t* used) {
    if (length > 255) return TLV_ERR_INVALID_LENGTH;
    *used = 1;
    return TLV_OK;
}
tlv_result_t one_byte_read_length(const void*, const uint8_t* data, size_t size, size_t* length,
                                  size_t* used) {
    if (size < 1) return TLV_ERR_BUFFER_TOO_SHORT;
    *length = data[0];
    *used = 1;
    return TLV_OK;
}
tlv_result_t one_byte_write_length(const void* ctx, uint8_t* data, size_t size, size_t length,
                                   size_t* used) {
    const auto rc = one_byte_length_size(ctx, length, used);
    if (rc != TLV_OK) return rc;
    if (size < 1) return TLV_ERR_BUFFER_TOO_SHORT;
    data[0] = static_cast<uint8_t>(length);
    return TLV_OK;
}
} // namespace

TEST(Unit_Format, RuntimeDefinedTagWidthsRoundTripWithoutRebuilding) {
    // Widths above the former default capacity of 8, including the 12 bytes of the motivating case.
    for (size_t tag_width :
         {size_t(1), size_t(2), size_t(8), size_t(9), size_t(12), size_t(64), size_t(300)}) {
        SCOPED_TRACE(tag_width);
        const RuntimeTagFormat    context = {tag_width};
        const tlv_reader_format_t reader_format = {&context, runtime_read_tag, one_byte_read_length,
                                                   nullptr, nullptr};
        const tlv_writer_format_t writer_format = {
            &context, runtime_write_tag, one_byte_write_length, one_byte_length_size, nullptr};
        std::vector<uint8_t> tag_bytes(tag_width);
        for (size_t i = 0; i < tag_width; ++i) tag_bytes[i] = static_cast<uint8_t>(0x10 + i);
        const uint8_t value[] = {0xAA, 0xBB};

        std::vector<uint8_t> wire(tag_width + 1 + sizeof(value));
        size_t               written = 0;
        ASSERT_EQ(TLV_OK, tlv_write(wire.data(), wire.size(), &writer_format,
                                    tlv_tag(tag_bytes.data(), tag_bytes.size()), value,
                                    sizeof(value), &written));
        EXPECT_EQ(wire.size(), written);

        tlv_view_t view{};
        size_t     consumed = 0;
        ASSERT_EQ(TLV_OK, tlv_read(wire.data(), wire.size(), &reader_format, &view, &consumed));
        EXPECT_EQ(wire.size(), consumed);
        // The tag is a window onto the input, not a copy.
        EXPECT_EQ(wire.data(), view.tag.data);
        EXPECT_EQ(tag_width, view.tag.size);
        EXPECT_TRUE(tlv_tag_equal(view.tag, tlv_tag(tag_bytes.data(), tag_bytes.size())));
        EXPECT_EQ(sizeof(value), static_cast<size_t>(view.value.length));

        // The format, not the tag type, rejects a tag of another width.
        std::vector<uint8_t> other(tag_width + 1, 0x42);
        EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE,
                  tlv_write(wire.data(), wire.size(), &writer_format,
                            tlv_tag(other.data(), other.size()), value, sizeof(value), &written));
    }
}
