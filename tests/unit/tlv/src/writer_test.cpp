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

TEST(Unit_Writer, EveryInsufficientCapacityReportsRequiredSizeAndPreservesBuffer) {
    const uint8_t value[] = {0, 0x80, 0xFF};
    const size_t  required = 1 /* tag */ + 1 /* length */ + sizeof(value);
    for (size_t capacity = 0; capacity < required; ++capacity) {
        uint8_t data[6];
        std::memset(data, 0xEE, sizeof(data));
        size_t written = 99;
        EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_write(data, capacity, &controlled::writer, tag,
                                                      value, sizeof(value), &written));
        EXPECT_EQ(required, written);
        size_t encoded_size = 0;
        ASSERT_EQ(TLV_OK, tlv_encoded_size(tag, sizeof(value), &controlled::writer, &encoded_size));
        EXPECT_EQ(encoded_size, written);
        for (auto byte : data) EXPECT_EQ(0xEE, byte);
    }
}

// Regression for a fuzz_roundtrip crash on the empty input (0 bytes, matching
// tests/fuzz/corpus/roundtrip/empty.bin): with a zero-length value, the harness's
// undersized tlv_write() still asserted the pre-#108 contract (written left
// untouched on TLV_ERR_BUFFER_TOO_SHORT). Reproduces that exact call shape here so
// the size-feedback contract for a zero-length value is covered without fuzzing.
TEST(Unit_Writer, ZeroLengthValueUndersizedWriteThenRoundTripRegression) {
    const tlv_tag_t primitive = {{0x04}, 1};
    size_t          total = 0;
    ASSERT_EQ(TLV_OK, tlv_encoded_size(primitive, 0, &controlled::writer, &total));
    std::vector<uint8_t> encoded(total, 0xA5);
    size_t               written = 99;
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_write(encoded.data(), total - 1, &controlled::writer,
                                                  primitive, nullptr, 0, &written));
    EXPECT_EQ(total, written);
    for (auto byte : encoded) EXPECT_EQ(0xA5, byte);
    ASSERT_EQ(TLV_OK, tlv_write(encoded.data(), total, &controlled::writer, primitive, nullptr, 0,
                                &written));
    EXPECT_EQ(total, written);
    tlv_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, encoded.data(), written, &controlled::reader));
    tlv_view_t view{};
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &view));
    EXPECT_EQ(primitive.size, view.tag.size);
    EXPECT_EQ(primitive.data[0], view.tag.data[0]);
    EXPECT_EQ(0u, view.value.length);
    EXPECT_TRUE(tlv_reader_at_end(&reader));
}

TEST(Unit_Writer, InvalidArgumentsAndFormatsPreserveOutputs) {
    uint8_t     data[4] = {};
    size_t      size = 99;
    const auto* format = &controlled::writer;
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_encoded_size(tag, 0, format, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_encoded_size(tag, 0, nullptr, &size));
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE, tlv_encoded_size(tlv_tag_t{}, 0, format, &size));
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_encoded_size(tag, 256, format, &size));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_write(nullptr, 1, format, tag, nullptr, 0, &size));
    // capacity 0 with a NULL data is a real (insufficient) destination for tlv_write, not a
    // size query, so the required size (tag + length, both 1 byte here) is reported.
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_write(nullptr, 0, format, tag, nullptr, 0, &size));
    EXPECT_EQ(2u, size);
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
    EXPECT_EQ(2u, size);
}

TEST(Unit_Writer, OverflowAndCallbackFailuresPreserveOutput) {
    auto    format = controlled::writer;
    size_t  size = 99;
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
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
              tlv_encoded_size(tag, std::numeric_limits<size_t>::max(), &format, &size));
    format = controlled::writer;
    format.write_tag = [](const void*, uint8_t* dst, size_t, const tlv_tag_t*, size_t* used) {
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
    uint8_t       data[5] = {};
    const uint8_t value = 0xAB;
    tlv_writer_t  writer;
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, data, sizeof(data), &controlled::writer));
    ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, tag, nullptr, 0));
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_writer_write(&writer, tag, data, 2));
    EXPECT_EQ(2u, tlv_writer_size(&writer));
    ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, tag, &value, 1));
    tlv_reader_t reader;
    ASSERT_EQ(TLV_OK,
              tlv_reader_init(&reader, data, tlv_writer_size(&writer), &controlled::reader));
    tlv_view_t view{};
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &view));
    EXPECT_EQ(0u, view.value.length);
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &view));
    ASSERT_EQ(1u, view.value.length);
    EXPECT_EQ(value, view.value.data[0]);
    EXPECT_TRUE(tlv_reader_at_end(&reader));
}

TEST(Unit_Writer, CopyViewAppendsAtCurrentPositionAndAdvances) {
    uint8_t          data[8];
    const uint8_t    value[] = {0x11, 0x22};
    const tlv_view_t view = {{{0xAB}, 1}, {value, sizeof(value)}};
    tlv_writer_t     writer;
    std::memset(data, 0xEE, sizeof(data));
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, data, sizeof(data), &controlled::writer));
    ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, tag, nullptr, 0));
    EXPECT_EQ(2u, tlv_writer_size(&writer));
    ASSERT_EQ(TLV_OK, tlv_writer_copy_view(&writer, &view));
    EXPECT_EQ(2u + 2u + sizeof(value), tlv_writer_size(&writer));
    EXPECT_EQ(0xAB, data[2]);
    EXPECT_EQ(2, data[3]);
    EXPECT_EQ(0x11, data[4]);
    EXPECT_EQ(0x22, data[5]);
}

TEST(Unit_Writer, CopyViewInsufficientCapacityLeavesPositionAndDoesNotExposeSize) {
    uint8_t          data[3];
    const uint8_t    value[] = {0x11, 0x22};
    const tlv_view_t view = {{{0xAB}, 1}, {value, sizeof(value)}};
    tlv_writer_t     writer;
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, data, sizeof(data), &controlled::writer));
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_writer_copy_view(&writer, &view));
    EXPECT_EQ(0u, tlv_writer_size(&writer));
}

TEST(Unit_Writer, CopyViewInvalidArguments) {
    uint8_t          data[8];
    const uint8_t    byte = 0xAB;
    const tlv_view_t view = {{{0xAB}, 1}, {&byte, 1}};
    tlv_view_t       invalid_view = {{{0xAB}, 1}, {nullptr, 1}};
    tlv_writer_t     writer;
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, data, sizeof(data), &controlled::writer));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_writer_copy_view(nullptr, &view));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_writer_copy_view(&writer, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_writer_copy_view(&writer, &invalid_view));
}

TEST(Unit_Writer, CopyViewNullBufferZeroCapacityIsNotASizeQuery) {
    const uint8_t    value[] = {0x11};
    const tlv_view_t view = {{{0xAB}, 1}, {value, sizeof(value)}};
    tlv_writer_t     writer;
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, nullptr, 0, &controlled::writer));
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_writer_copy_view(&writer, &view));
    EXPECT_EQ(0u, tlv_writer_size(&writer));
}

TEST(Unit_Writer, CopyViewInvalidPositionGreaterThanCapacity) {
    uint8_t          data[8];
    const tlv_view_t view = {{{0xAB}, 1}, {nullptr, 0}};
    tlv_writer_t     writer;
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, data, sizeof(data), &controlled::writer));
    writer.pos = writer.capacity + 1;
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_writer_copy_view(&writer, &view));
    EXPECT_EQ(writer.capacity + 1, writer.pos);
}

TEST(Unit_Writer, CopyEncodedAppendsAtCurrentPositionAndAdvances) {
    uint8_t       data[8];
    const uint8_t encoded[] = {0xAB, 0x02, 0x11, 0x22};
    tlv_writer_t  writer;
    std::memset(data, 0xEE, sizeof(data));
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, data, sizeof(data), &controlled::writer));
    ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, tag, nullptr, 0));
    EXPECT_EQ(2u, tlv_writer_size(&writer));
    ASSERT_EQ(TLV_OK, tlv_writer_copy_encoded(&writer, encoded, sizeof(encoded)));
    EXPECT_EQ(2u + sizeof(encoded), tlv_writer_size(&writer));
    EXPECT_EQ(0, std::memcmp(encoded, data + 2, sizeof(encoded)));
}

TEST(Unit_Writer, CopyEncodedInsufficientCapacityLeavesPosition) {
    uint8_t       data[3];
    const uint8_t encoded[] = {0xAB, 0x02, 0x11, 0x22};
    tlv_writer_t  writer;
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, data, sizeof(data), &controlled::writer));
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_writer_copy_encoded(&writer, encoded, sizeof(encoded)));
    EXPECT_EQ(0u, tlv_writer_size(&writer));
}

TEST(Unit_Writer, CopyEncodedInvalidArguments) {
    uint8_t      data[8];
    tlv_writer_t writer;
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, data, sizeof(data), &controlled::writer));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_writer_copy_encoded(nullptr, data, 1));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_writer_copy_encoded(&writer, nullptr, 1));
}

TEST(Unit_Writer, CopyEncodedNullBufferZeroCapacity) {
    tlv_writer_t writer;
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, nullptr, 0, &controlled::writer));
    EXPECT_EQ(TLV_OK, tlv_writer_copy_encoded(&writer, nullptr, 0));
    EXPECT_EQ(0u, tlv_writer_size(&writer));
    const uint8_t byte = 0xAB;
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_writer_copy_encoded(&writer, &byte, 1));
    EXPECT_EQ(0u, tlv_writer_size(&writer));
}

TEST(Unit_Writer, CopyEncodedInvalidPositionGreaterThanCapacity) {
    uint8_t      data[8];
    tlv_writer_t writer;
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, data, sizeof(data), &controlled::writer));
    writer.pos = writer.capacity + 1;
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_writer_copy_encoded(&writer, nullptr, 0));
    EXPECT_EQ(writer.capacity + 1, writer.pos);
}

TEST(Unit_Writer, CopyEncodedOverlappingByteRangesAndEmptyRange) {
    uint8_t      bytes[] = {1, 2, 3, 4};
    tlv_writer_t writer;
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, bytes, sizeof(bytes), &controlled::writer));
    writer.pos = 1;
    ASSERT_EQ(TLV_OK, tlv_writer_copy_encoded(&writer, bytes, 3));
    const uint8_t expected[] = {1, 1, 2, 3};
    EXPECT_EQ(0, std::memcmp(expected, bytes, sizeof(bytes)));
    EXPECT_EQ(4u, writer.pos);
    ASSERT_EQ(TLV_OK, tlv_writer_copy_encoded(&writer, nullptr, 0));
    EXPECT_EQ(4u, writer.pos);
}

TEST(Unit_Writer, SequentialRoundTripCombiningWriteAndBothCopyHelpers) {
    uint8_t          data[32];
    uint8_t          separately_encoded[8];
    const uint8_t    first_value[] = {0x01, 0x02};
    const uint8_t    view_value[] = {0xAA, 0xBB, 0xCC};
    const tlv_tag_t  view_tag = {{0x22}, 1};
    const tlv_view_t view = {view_tag, {view_value, sizeof(view_value)}};
    size_t           encoded_written = 0;
    tlv_writer_t     writer;

    ASSERT_EQ(TLV_OK, tlv_write(separately_encoded, sizeof(separately_encoded), &controlled::writer,
                                tlv_tag_t{{0x33}, 1}, view_value, 1, &encoded_written));

    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, data, sizeof(data), &controlled::writer));
    ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, tag, first_value, sizeof(first_value)));
    ASSERT_EQ(TLV_OK, tlv_writer_copy_view(&writer, &view));
    ASSERT_EQ(TLV_OK, tlv_writer_copy_encoded(&writer, separately_encoded, encoded_written));

    tlv_reader_t reader;
    ASSERT_EQ(TLV_OK,
              tlv_reader_init(&reader, data, tlv_writer_size(&writer), &controlled::reader));
    tlv_view_t read_view{};
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &read_view));
    ASSERT_EQ(2u, read_view.value.length);
    EXPECT_EQ(first_value[0], read_view.value.data[0]);
    EXPECT_EQ(first_value[1], read_view.value.data[1]);

    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &read_view));
    EXPECT_EQ(0x22, read_view.tag.data[0]);
    ASSERT_EQ(3u, read_view.value.length);
    EXPECT_EQ(0, std::memcmp(view_value, read_view.value.data, sizeof(view_value)));

    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &read_view));
    EXPECT_EQ(0x33, read_view.tag.data[0]);
    ASSERT_EQ(1u, read_view.value.length);
    EXPECT_EQ(view_value[0], read_view.value.data[0]);

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
    reader_format.read_length = [](const void*, const uint8_t*, size_t, size_t* length,
                                   size_t* used) {
        *length = 0;
        *used = 0;
        return TLV_OK;
    };
    uint8_t data = 0;
    size_t  size = 0;
    ASSERT_EQ(TLV_OK, tlv_encoded_size(tag, 0, &format, &size));
    EXPECT_EQ(1u, size);
    ASSERT_EQ(TLV_OK, tlv_write(&data, 1, &format, tag, nullptr, 0, &size));
    tlv_view_t view{};
    ASSERT_EQ(TLV_OK, tlv_read(&data, size, &reader_format, &view, &size));
    EXPECT_EQ(1u, size);
    EXPECT_EQ(tag.data[0], view.tag.data[0]);
    EXPECT_EQ(0u, view.value.length);
}
