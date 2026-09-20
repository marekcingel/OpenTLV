#include "tlv/formats/bluetooth/bluetooth_ltv.h"
#include "tlv/copy.h"
#include "tlv/reader/reader.h"
#include "tlv/reader/scanner.h"
#include "tlv/reader/walker.h"
#include "tlv/schemas/schema.h"
#include "tlv/writer/writer.h"
#include <gtest/gtest.h>
#include <cstring>
#include <vector>

namespace {
const auto& reader_format = tlv_reader_format_bluetooth_ltv;
const auto& writer_format = tlv_writer_format_bluetooth_ltv;

// Flags (01), Complete Local Name "Hi" (09), and an unknown type (FF) with two bytes.
const uint8_t advertising[] = {0x02, 0x01, 0x06, 0x03, 0x09, 'H', 'i', 0x03, 0xFF, 0xDE, 0xAD};

tlv_visit_result_t count_element(const tlv_view_t*, void* context) {
    ++*static_cast<size_t*>(context);
    return TLV_VISIT_CONTINUE;
}

tlv_result_t empty_header(const void*, const uint8_t*, size_t, tlv_tag_t* tag, size_t* header,
                          size_t* value, size_t* trailer) {
    *tag = tlv_tag_t{{1}, 1};
    *header = 0;
    *value = 0;
    *trailer = 0;
    return TLV_OK;
}
} // namespace

TEST(Unit_BluetoothLtv, ReadsLengthBeforeType) {
    tlv_view_t view;
    size_t     consumed = 0;
    ASSERT_EQ(TLV_OK, tlv_read(advertising, sizeof(advertising), &reader_format, &view, &consumed));
    EXPECT_EQ(3u, consumed);
    EXPECT_EQ(1, view.tag.size);
    EXPECT_EQ(0x01, view.tag.data[0]);
    ASSERT_EQ(1u, view.value.length);
    EXPECT_EQ(0x06, view.value.data[0]);
    EXPECT_EQ(advertising + 2, view.value.data);
}

TEST(Unit_BluetoothLtv, ReadsConsecutiveElementsAndSkipsUnknownTypes) {
    tlv_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, advertising, sizeof(advertising), &reader_format));
    const uint8_t expected_types[] = {0x01, 0x09, 0xFF};
    const size_t  expected_lengths[] = {1, 2, 2};
    for (size_t i = 0; i < 3; ++i) {
        tlv_view_t view;
        ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &view));
        EXPECT_EQ(expected_types[i], view.tag.data[0]);
        EXPECT_EQ(expected_lengths[i], view.value.length);
    }
    EXPECT_TRUE(tlv_reader_at_end(&reader));
}

TEST(Unit_BluetoothLtv, AcceptsEmptyAndMaximumValues) {
    const uint8_t type_only[] = {0x01, 0x2A};
    tlv_view_t    view;
    size_t        consumed = 0;
    ASSERT_EQ(TLV_OK, tlv_read(type_only, sizeof(type_only), &reader_format, &view, &consumed));
    EXPECT_EQ(2u, consumed);
    EXPECT_EQ(0x2A, view.tag.data[0]);
    EXPECT_EQ(0u, view.value.length);

    std::vector<uint8_t> maximum(256, 0x55);
    maximum[0] = 0xFF;
    maximum[1] = 0x09;
    ASSERT_EQ(TLV_OK, tlv_read(maximum.data(), maximum.size(), &reader_format, &view, &consumed));
    EXPECT_EQ(256u, consumed);
    EXPECT_EQ(254u, view.value.length);
}

TEST(Unit_BluetoothLtv, RejectsZeroLengthAndTruncation) {
    tlv_view_t    view = {tlv_tag_t{{0xEE}, 1}, {nullptr, 42}};
    size_t        consumed = 42;
    const uint8_t zero[] = {0x00, 0x00};
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
              tlv_read(zero, sizeof(zero), &reader_format, &view, &consumed));
    EXPECT_EQ(42u, consumed);
    EXPECT_EQ(nullptr, view.value.data);
    const uint8_t truncated[] = {0x03, 0x09, 'H', 'i'};
    for (size_t size = 1; size < sizeof(truncated); ++size)
        EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
                  tlv_read(truncated, size, &reader_format, &view, &consumed));
    EXPECT_EQ(TLV_ERR_END_OF_BUFFER, tlv_read(zero, 0, &reader_format, &view, &consumed));
}

TEST(Unit_BluetoothLtv, WritesLengthBeforeType) {
    const tlv_tag_t tag = {{0x09}, 1};
    const uint8_t   value[] = {'H', 'i'};
    uint8_t         out[8] = {};
    size_t          written = 0;
    ASSERT_EQ(TLV_OK, tlv_write(out, sizeof(out), &writer_format, tag, value, 2, &written));
    EXPECT_EQ(4u, written);
    const uint8_t expected[] = {0x03, 0x09, 'H', 'i'};
    EXPECT_EQ(0, std::memcmp(expected, out, sizeof(expected)));
    size_t size = 0;
    ASSERT_EQ(TLV_OK, tlv_encoded_size(tag, 2, &writer_format, &size));
    EXPECT_EQ(4u, size);
}

TEST(Unit_BluetoothLtv, WriterEnforcesLimitsWithoutWriting) {
    uint8_t         out[300];
    uint8_t         value[300] = {};
    size_t          written = 0;
    const tlv_tag_t tag = {{0x01}, 1};
    std::memset(out, 0xEE, sizeof(out));
    EXPECT_EQ(TLV_OK, tlv_write(out, sizeof(out), &writer_format, tag, value, 254, &written));
    EXPECT_EQ(256u, written);
    EXPECT_EQ(0xFF, out[0]);
    std::memset(out, 0xEE, sizeof(out));
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
              tlv_write(out, sizeof(out), &writer_format, tag, value, 255, &written));
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE, tlv_write(out, sizeof(out), &writer_format,
                                                  tlv_tag_t{{1, 2}, 2}, value, 1, &written));
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE,
              tlv_write(out, sizeof(out), &writer_format, tlv_tag_t{{0}, 0}, value, 1, &written));
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_write(out, 3, &writer_format, tag, value, 2, &written));
    EXPECT_EQ(4u, written);
    for (size_t i = 0; i < sizeof(out); ++i) EXPECT_EQ(0xEE, out[i]);
}

TEST(Unit_BluetoothLtv, WriterRoundTripsThroughReader) {
    uint8_t      buffer[32];
    tlv_writer_t writer;
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, buffer, sizeof(buffer), &writer_format));
    const uint8_t flags[] = {0x06};
    const uint8_t name[] = {'H', 'i'};
    ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, tlv_tag_t{{0x01}, 1}, flags, 1));
    ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, tlv_tag_t{{0x09}, 1}, name, 2));
    ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, tlv_tag_t{{0x0A}, 1}, nullptr, 0));
    const uint8_t expected[] = {0x02, 0x01, 0x06, 0x03, 0x09, 'H', 'i', 0x01, 0x0A};
    ASSERT_EQ(sizeof(expected), tlv_writer_size(&writer));
    EXPECT_EQ(0, std::memcmp(expected, buffer, sizeof(expected)));

    tlv_view_t view;
    size_t     consumed = 0;
    ASSERT_EQ(TLV_OK, tlv_read(buffer + 3, 6, &reader_format, &view, &consumed));
    EXPECT_EQ(0x09, view.tag.data[0]);
    uint8_t copy[8];
    size_t  copied = 0;
    ASSERT_EQ(TLV_OK, tlv_copy_view(&view, &writer_format, copy, sizeof(copy), &copied));
    EXPECT_EQ(consumed, copied);
    EXPECT_EQ(0, std::memcmp(buffer + 3, copy, copied));
}

TEST(Unit_BluetoothLtv, GenericScannerWalkerAndTreeWalkWork) {
    tlv_view_t               view;
    size_t                   offset = 0, consumed = 0;
    const tlv_schema_entry_t entries[] = {{tlv_tag_t{{0x09}, 1}, 0, 8, 0}};
    const tlv_schema_t       schema = {entries, 1};
    ASSERT_EQ(TLV_OK, tlv_scan(advertising, sizeof(advertising), 0, &reader_format, &schema, &view,
                               &offset, &consumed));
    EXPECT_EQ(3u, offset);
    EXPECT_EQ(4u, consumed);

    size_t count = 0;
    ASSERT_EQ(TLV_OK,
              tlv_walk(advertising, sizeof(advertising), &reader_format, count_element, &count));
    EXPECT_EQ(3u, count);

    size_t error_offset = 99;
    EXPECT_EQ(TLV_OK, tlv_walk_tree(advertising, sizeof(advertising), &reader_format, nullptr, 8,
                                    100, nullptr, nullptr, &error_offset));
    const uint8_t bad[] = {0x02, 0x01, 0x06, 0x00};
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_walk_tree(bad, sizeof(bad), &reader_format, nullptr, 8,
                                                    100, nullptr, nullptr, &error_offset));
    EXPECT_EQ(3u, error_offset);
}

TEST(Unit_BluetoothLtv, InitHelpersCreateWholeElementFormats) {
    tlv_reader_format_t reader{};
    tlv_writer_format_t writer{};
    ASSERT_EQ(TLV_OK, tlv_reader_format_init_element(&reader, nullptr, reader_format.read_element));
    EXPECT_EQ(nullptr, reader.read_tag);
    EXPECT_EQ(nullptr, reader.read_length);
    EXPECT_EQ(nullptr, reader.read_value_bounds);
    ASSERT_EQ(TLV_OK, tlv_writer_format_init_header(&writer, nullptr, writer_format.write_header));
    EXPECT_EQ(nullptr, writer.write_tag);
    EXPECT_EQ(nullptr, writer.write_length);
    EXPECT_EQ(nullptr, writer.length_size);

    tlv_reader_format_t before = reader;
    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              tlv_reader_format_init_element(nullptr, nullptr, reader.read_element));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_reader_format_init_element(&reader, nullptr, nullptr));
    EXPECT_EQ(0, std::memcmp(&before, &reader, sizeof(reader)));
    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              tlv_writer_format_init_header(nullptr, nullptr, writer.write_header));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_writer_format_init_header(&writer, nullptr, nullptr));

    tlv_view_t view;
    size_t     consumed = 0;
    ASSERT_EQ(TLV_OK, tlv_read(advertising, sizeof(advertising), &reader, &view, &consumed));
    EXPECT_EQ(3u, consumed);
}

TEST(Unit_BluetoothLtv, GenericLayerRejectsEmptyHeader) {
    // A format that reports an empty header must not make the reader loop forever.
    tlv_reader_format_t reader{};
    ASSERT_EQ(TLV_OK, tlv_reader_format_init_element(&reader, nullptr, empty_header));
    tlv_view_t    view;
    size_t        consumed = 0;
    const uint8_t data[] = {1, 2, 3};
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_read(data, sizeof(data), &reader, &view, &consumed));
}
