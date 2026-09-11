#include "controlled_format.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#include <gtest/gtest.h>
#include <cstring>
#include <limits>
#include <vector>

namespace {
const tlv_tag_t tag = {{0xFF}, 1};
}

TEST(Unit_Writer, EveryInsufficientCapacityPreservesBufferAndOutput) {
    const uint8_t value[] = {0, 0x80, 0xFF};
    for (size_t capacity = 0; capacity < 5; ++capacity) {
        uint8_t data[6];
        std::memset(data, 0xEE, sizeof(data));
        size_t written = 99;
        EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_write(data, capacity,
            &controlled::writer, tag, value, sizeof(value), &written));
        EXPECT_EQ(99u, written);
        for (auto byte : data) EXPECT_EQ(0xEE, byte);
    }
}

TEST(Unit_Writer, InvalidArgumentsAndFormatsPreserveOutputs) {
    uint8_t data[4] = {};
    size_t size = 99;
    const auto* format = &controlled::writer;
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

TEST(Unit_Writer, OverflowAndCallbackFailuresPreserveOutput) {
    auto format = controlled::writer;
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
    format = controlled::writer;
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

TEST(Unit_Writer, StatefulAppendFailureAndRetry) {
    uint8_t data[5] = {};
    const uint8_t value = 0xAB;
    tlv_writer_t writer;
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, data, sizeof(data), &controlled::writer));
    ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, tag, nullptr, 0));
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_writer_write(&writer, tag, data, 2));
    EXPECT_EQ(2u, tlv_writer_size(&writer));
    ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, tag, &value, 1));
    tlv_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, tlv_writer_size(&writer), &controlled::reader));
    tlv_view_t view{};
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &view));
    EXPECT_EQ(0u, view.value.length);
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &view));
    ASSERT_EQ(1u, view.value.length);
    EXPECT_EQ(value, view.value.data[0]);
    EXPECT_TRUE(tlv_reader_at_end(&reader));
}

TEST(Unit_Writer, ImplicitZeroByteLength) {
    auto format = controlled::writer;
    format.length_size = [](const void*, size_t length, size_t* used) {
        *used = 0;
        return length == 0 ? TLV_OK : TLV_ERR_INVALID_LENGTH;
    };
    format.write_length = [](const void*, uint8_t*, size_t capacity, size_t, size_t* used) {
        EXPECT_EQ(0u, capacity);
        *used = 0;
        return TLV_OK;
    };
    auto reader_format = controlled::reader;
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
