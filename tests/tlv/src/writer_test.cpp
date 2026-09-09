#include "tlv/formats/default/default.h"
#include "tlv/formats/fixed/fixed_1byte.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#include <gtest/gtest.h>
#include <cstring>
#include <limits>
#include <vector>

namespace {
const tlv_tag_t tag = {{0xFF}, 1};
}

TEST(Writer, SizesWireEncodingAndRoundTripsAtLengthBoundaries) {
    for (const auto* format : {&tlv_writer_format_fixed_1byte, &tlv_writer_format_default}) {
        const auto* reader_format = format == &tlv_writer_format_fixed_1byte
            ? &tlv_reader_format_fixed_1byte : &tlv_reader_format_default;
        for (size_t length : {0u, 1u, 127u, 128u, 255u, 256u, 65535u}) {
            if (format == &tlv_writer_format_fixed_1byte && length > 255) continue;
            SCOPED_TRACE(length);
            std::vector<uint8_t> value(length);
            for (size_t i = 0; i < length; ++i) value[i] = static_cast<uint8_t>(i);
            size_t required = 0;
            ASSERT_EQ(TLV_OK, tlv_encoded_size(tag, length, format, &required));
            const size_t length_bytes = format == &tlv_writer_format_fixed_1byte || length < 128
                ? 1 : (length <= 255 ? 2 : 3);
            EXPECT_EQ(1 + length_bytes + length, required);
            std::vector<uint8_t> data(required + 1, 0xEE);
            size_t written = 99;
            ASSERT_EQ(TLV_OK, tlv_write(data.data(), required, format, tag,
                                        length ? value.data() : nullptr, length, &written));
            EXPECT_EQ(required, written);
            EXPECT_EQ(0xEE, data[required]);
            EXPECT_EQ(0xFF, data[0]);
            EXPECT_EQ(length_bytes == 1 ? length : 0x80 + length_bytes - 1, data[1]);
            if (length_bytes == 2) EXPECT_EQ(length, data[2]);
            if (length_bytes == 3) {
                EXPECT_EQ(length >> 8, data[2]);
                EXPECT_EQ(length & 255, data[3]);
            }
            tlv_view_t view{};
            size_t consumed = 0;
            ASSERT_EQ(TLV_OK, tlv_read(data.data(), written, reader_format, &view, &consumed));
            EXPECT_EQ(written, consumed);
            EXPECT_EQ(tag.data[0], view.tag.data[0]);
            EXPECT_EQ(length, view.value.length);
            if (length) EXPECT_EQ(0, std::memcmp(value.data(), view.value.data, length));
        }
    }
}

TEST(Writer, EveryInsufficientCapacityPreservesBufferAndOutput) {
    const uint8_t value[] = {0, 0x80, 0xFF};
    for (size_t capacity = 0; capacity < 5; ++capacity) {
        uint8_t data[6];
        std::memset(data, 0xEE, sizeof(data));
        size_t written = 99;
        EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_write(data, capacity,
            &tlv_writer_format_fixed_1byte, tag, value, sizeof(value), &written));
        EXPECT_EQ(99u, written);
        for (auto byte : data) EXPECT_EQ(0xEE, byte);
    }
}

TEST(Writer, InvalidArgumentsAndFormatsPreserveOutputs) {
    uint8_t data[4] = {};
    size_t size = 99;
    const auto* format = &tlv_writer_format_fixed_1byte;
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_encoded_size(tag, 0, format, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_encoded_size(tag, 0, nullptr, &size));
    EXPECT_EQ(TLV_ERR_INVALID_TAG, tlv_encoded_size(tlv_tag_t{}, 0, format, &size));
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_encoded_size(tag, 256, format, &size));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_write(nullptr, 1, format, tag, nullptr, 0, &size));
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_write(nullptr, 0, format, tag, nullptr, 0, &size));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_write(data, 4, format, tag, nullptr, 1, &size));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_write(data, 4, format, tag, nullptr, 0, nullptr));
    for (int i = 0; i < 3; ++i) {
        auto incomplete = *format;
        if (i == 0) incomplete.write_tag = nullptr;
        if (i == 1) incomplete.write_length = nullptr;
        if (i == 2) incomplete.length_size = nullptr;
        EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_encoded_size(tag, 0, &incomplete, &size));
        EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_write(data, 4, &incomplete, tag, nullptr, 0, &size));
    }
    EXPECT_EQ(99u, size);
}

TEST(Writer, OverflowAndCallbackFailuresPreserveOutput) {
    auto format = tlv_writer_format_fixed_1byte;
    size_t size = 99;
    uint8_t data[4] = {};
    format.length_size = [](const void*, size_t, size_t* used) {
        *used = std::numeric_limits<size_t>::max();
        return TLV_OK;
    };
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_encoded_size(tag, 0, &format, &size));
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_write(data, 4, &format, tag, nullptr, 0, &size));
    format.length_size = [](const void*, size_t, size_t* used) {
        *used = 0;
        return TLV_OK;
    };
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_encoded_size(tag,
        std::numeric_limits<size_t>::max(), &format, &size));
    format = tlv_writer_format_fixed_1byte;
    format.write_tag = [](const void*, uint8_t* dst, size_t,
                          const tlv_tag_t*, size_t* used) {
        *used = dst ? 2 : 1;
        return TLV_OK;
    };
    EXPECT_EQ(TLV_ERR_INVALID_TAG, tlv_write(data, 4, &format, tag, nullptr, 0, &size));
    format.write_tag = [](const void*, uint8_t*, size_t, const tlv_tag_t*, size_t*) {
        return TLV_ERR_END_OF_BUFFER;
    };
    EXPECT_EQ(TLV_ERR_END_OF_BUFFER, tlv_encoded_size(tag, 0, &format, &size));
    EXPECT_EQ(99u, size);
}

TEST(Writer, StatefulAppendFailureAndRetry) {
    uint8_t data[5] = {};
    const uint8_t value = 0xAB;
    tlv_writer_t writer;
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, data, sizeof(data), &tlv_writer_format_fixed_1byte));
    ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, tag, nullptr, 0));
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_writer_write(&writer, tag, data, 2));
    EXPECT_EQ(2u, tlv_writer_size(&writer));
    ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, tag, &value, 1));
    tlv_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, tlv_writer_size(&writer), &tlv_reader_format_fixed_1byte));
    tlv_view_t view{};
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &view));
    EXPECT_EQ(0u, view.value.length);
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &view));
    ASSERT_EQ(1u, view.value.length);
    EXPECT_EQ(value, view.value.data[0]);
    EXPECT_TRUE(tlv_reader_at_end(&reader));
}

TEST(Writer, ImplicitZeroByteLength) {
    auto format = tlv_writer_format_fixed_1byte;
    format.length_size = [](const void*, size_t length, size_t* used) {
        *used = 0;
        return length == 0 ? TLV_OK : TLV_ERR_INVALID_LENGTH;
    };
    format.write_length = [](const void*, uint8_t*, size_t capacity, size_t, size_t* used) {
        EXPECT_EQ(0u, capacity);
        *used = 0;
        return TLV_OK;
    };
    auto reader_format = tlv_reader_format_fixed_1byte;
    reader_format.read_length = [](const void*, const uint8_t*, size_t, size_t* length, size_t* used) {
        *length = 0;
        *used = 0;
        return TLV_OK;
    };
    uint8_t data = 0;
    size_t size = 0;
    ASSERT_EQ(TLV_OK, tlv_encoded_size(tag, 0, &format, &size));
    EXPECT_EQ(1u, size);
    ASSERT_EQ(TLV_OK, tlv_write(&data, 1, &format, tag, nullptr, 0, &size));
    tlv_view_t view{};
    ASSERT_EQ(TLV_OK, tlv_read(&data, size, &reader_format, &view, &size));
    EXPECT_EQ(1u, size);
    EXPECT_EQ(tag.data[0], view.tag.data[0]);
    EXPECT_EQ(0u, view.value.length);
}
