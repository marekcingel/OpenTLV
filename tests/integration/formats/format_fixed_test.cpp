#include "tlv/formats/fixed.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#include <gtest/gtest.h>
#include <cstring>
#include <vector>

TEST(Integration_Tlv_Fixed, ExampleWireBytesTwoByteTagOneByteLength) {
    /* [tag: 2 bytes][length: 1 byte][value: N bytes], from the issue's example use case. */
    const tlv_fixed_format_t config = {2, 1, TLV_BYTE_ORDER_BIG_ENDIAN, TLV_ELEMENT_ORDER_TLV,
                                       TLV_LENGTH_SCOPE_VALUE};
    tlv_format_t             writer_format{};
    ASSERT_EQ(TLV_OK, tlv_fixed_format_init(&writer_format, &config));

    const uint8_t expected[] = {0x12, 0x34, 0x03, 0xAA, 0xBB, 0xCC};
    uint8_t       data[sizeof(expected)] = {};
    tlv_writer_t  writer;
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, data, sizeof(data), &writer_format));
    ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, (TLV_TAG(0x12, 0x34)), expected + 3, 3));
    EXPECT_EQ(sizeof(expected), tlv_writer_size(&writer));
    EXPECT_EQ(0, std::memcmp(expected, data, sizeof(data)));

    tlv_format_t reader_format{};
    ASSERT_EQ(TLV_OK, tlv_fixed_format_init(&reader_format, &config));
    tlv_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, writer.pos, &reader_format));
    tlv_element_t element{};
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
    EXPECT_EQ(2, element.tag.size);
    EXPECT_EQ(0x12, element.tag.data[0]);
    EXPECT_EQ(0x34, element.tag.data[1]);
    EXPECT_EQ(3u, element.value.size);
    EXPECT_EQ(0, std::memcmp(expected + 3, element.value.data, 3));
    EXPECT_TRUE(tlv_reader_at_end(&reader));
}

TEST(Integration_Tlv_Fixed, ExampleWireBytesTwoByteLittleEndianLength) {
    /* Matches tlv::fixed_format<2, 2, TLV_BYTE_ORDER_LITTLE_ENDIAN>, documented in
     * docs/formats/fixed/configurable.md: 12 34 03 00 AA BB CC. */
    const tlv_fixed_format_t config = {2, 2, TLV_BYTE_ORDER_LITTLE_ENDIAN, TLV_ELEMENT_ORDER_TLV,
                                       TLV_LENGTH_SCOPE_VALUE};
    tlv_format_t             writer_format{};
    tlv_format_t             reader_format{};
    ASSERT_EQ(TLV_OK, tlv_fixed_format_init(&writer_format, &config));
    ASSERT_EQ(TLV_OK, tlv_fixed_format_init(&reader_format, &config));

    const uint8_t expected[] = {0x12, 0x34, 0x03, 0x00, 0xAA, 0xBB, 0xCC};
    uint8_t       data[sizeof(expected)] = {};
    tlv_writer_t  writer;
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, data, sizeof(data), &writer_format));
    ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, (TLV_TAG(0x12, 0x34)), expected + 4, 3));
    EXPECT_EQ(0, std::memcmp(expected, data, sizeof(data)));

    tlv_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, writer.pos, &reader_format));
    tlv_element_t element{};
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
    EXPECT_EQ(3u, element.value.size);
    EXPECT_EQ(0, std::memcmp(expected + 4, element.value.data, 3));
}

TEST(Integration_Tlv_Fixed, EveryLengthByteRoundTripsOneByteTagOneByteLength) {
    const tlv_fixed_format_t config = {1, 1, TLV_BYTE_ORDER_BIG_ENDIAN, TLV_ELEMENT_ORDER_TLV,
                                       TLV_LENGTH_SCOPE_VALUE};
    tlv_format_t             writer_format{};
    tlv_format_t             reader_format{};
    ASSERT_EQ(TLV_OK, tlv_fixed_format_init(&writer_format, &config));
    ASSERT_EQ(TLV_OK, tlv_fixed_format_init(&reader_format, &config));

    uint8_t value[255];
    std::memset(value, 0xAB, sizeof(value));
    for (size_t byte = 0; byte <= 255; ++byte) {
        SCOPED_TRACE(byte);
        uint8_t      data[259] = {};
        tlv_writer_t writer;
        ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, data, sizeof(data), &writer_format));
        const uint8_t   tag_byte = static_cast<uint8_t>(byte);
        const tlv_tag_t tag = tlv_tag(&tag_byte, 1);
        ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, tag, value, byte));
        EXPECT_EQ(byte + 2, tlv_writer_size(&writer));
        EXPECT_EQ(byte, data[0]);
        EXPECT_EQ(byte, data[1]);

        tlv_reader_t reader;
        ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, writer.pos, &reader_format));
        tlv_element_t element{};
        ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
        EXPECT_EQ(1, element.tag.size);
        EXPECT_EQ(byte, element.tag.data[0]);
        EXPECT_EQ(byte, element.value.size);
        EXPECT_EQ(0, std::memcmp(value, element.value.data, byte));
        EXPECT_TRUE(tlv_reader_at_end(&reader));
    }
}

// One tlv_format_t (not two independently initialized ones, unlike the tests
// above) borrowed by a reader and a writer that stay simultaneously live and
// interleave their operations, proving the shared, immutable descriptor and
// context are safe for concurrent use. See
// docs/guides/memory.md#format-context-ownership-and-lifetime.
TEST(Integration_Tlv_Fixed, OneFormatSharedByReaderAndWriterConcurrentlyLive) {
    const tlv_fixed_format_t config = {2, 1, TLV_BYTE_ORDER_BIG_ENDIAN, TLV_ELEMENT_ORDER_TLV,
                                       TLV_LENGTH_SCOPE_VALUE};
    tlv_format_t             format{};
    ASSERT_EQ(TLV_OK, tlv_fixed_format_init(&format, &config));

    uint8_t      data[64] = {};
    tlv_writer_t writer;
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, data, sizeof(data), &format));
    tlv_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, 0, &format));

    const uint8_t first_value[] = {0xAA, 0xBB};
    ASSERT_EQ(TLV_OK,
              tlv_writer_write(&writer, (TLV_TAG(0x01, 0x02)), first_value, sizeof(first_value)));
    reader.size = writer.pos; /* The reader observes what the writer has produced so far. */
    tlv_element_t element{};
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
    EXPECT_EQ(2u, element.value.size);
    EXPECT_TRUE(tlv_reader_at_end(&reader));

    const uint8_t second_value[] = {0xCC};
    ASSERT_EQ(TLV_OK,
              tlv_writer_write(&writer, (TLV_TAG(0x03, 0x04)), second_value, sizeof(second_value)));
    reader.size = writer.pos;
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
    EXPECT_EQ(1u, element.value.size);
    EXPECT_TRUE(tlv_reader_at_end(&reader));
}

TEST(Integration_Tlv_Fixed, RejectsLengthThatOverflowsConfiguredWidth) {
    const tlv_fixed_format_t config = {1, 1, TLV_BYTE_ORDER_BIG_ENDIAN, TLV_ELEMENT_ORDER_TLV,
                                       TLV_LENGTH_SCOPE_VALUE};
    tlv_format_t             writer_format{};
    ASSERT_EQ(TLV_OK, tlv_fixed_format_init(&writer_format, &config));
    uint8_t      data[260] = {};
    tlv_writer_t writer;
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, data, sizeof(data), &writer_format));
    uint8_t value[256] = {};
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_writer_write(&writer, (TLV_TAG(1)), value, 256));
}

// [length: 1 byte][tag: 1 byte][value: N bytes], length = tag_size + value_size.
// Matches docs/formats/bluetooth/README.md's byte example exactly, since this
// configuration is the Bluetooth LTV preset.
TEST(Integration_Tlv_Fixed, ExampleWireBytesLtvFieldOrderTagAndValueScope) {
    const tlv_fixed_format_t config = {1, 1, TLV_BYTE_ORDER_BIG_ENDIAN, TLV_ELEMENT_ORDER_LTV,
                                       TLV_LENGTH_SCOPE_TAG_AND_VALUE};
    tlv_format_t             format{};
    ASSERT_EQ(TLV_OK, tlv_fixed_format_init(&format, &config));

    const uint8_t expected[] = {0x03, 0x09, 'H', 'i'};
    uint8_t       data[sizeof(expected)] = {};
    tlv_writer_t  writer;
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, data, sizeof(data), &format));
    ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, TLV_TAG(0x09), expected + 2, 2));
    EXPECT_EQ(0, std::memcmp(expected, data, sizeof(data)));

    tlv_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, writer.pos, &format));
    tlv_element_t element{};
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
    EXPECT_EQ(1, element.tag.size);
    EXPECT_EQ(0x09, element.tag.data[0]);
    EXPECT_EQ(2u, element.value.size);
    EXPECT_EQ(0, std::memcmp(expected + 2, element.value.data, 2));
    EXPECT_TRUE(tlv_reader_at_end(&reader));

    // A length byte of zero has no room for the tag it must also count.
    const uint8_t zero_length[] = {0x00};
    tlv_element_t rejected{};
    size_t        consumed = 0;
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
              tlv_read(zero_length, sizeof(zero_length), &format, &rejected, &consumed));
}

// [tag: 1 byte][length: 1 byte][value: N bytes], length = tag_size + value_size:
// the conventional field order with Bluetooth-style length semantics.
TEST(Integration_Tlv_Fixed, ExampleWireBytesTlvFieldOrderTagAndValueScope) {
    const tlv_fixed_format_t config = {1, 1, TLV_BYTE_ORDER_BIG_ENDIAN, TLV_ELEMENT_ORDER_TLV,
                                       TLV_LENGTH_SCOPE_TAG_AND_VALUE};
    tlv_format_t             format{};
    ASSERT_EQ(TLV_OK, tlv_fixed_format_init(&format, &config));

    const uint8_t expected[] = {0x09, 0x03, 'H', 'i'};
    uint8_t       data[sizeof(expected)] = {};
    tlv_writer_t  writer;
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, data, sizeof(data), &format));
    ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, TLV_TAG(0x09), expected + 2, 2));
    EXPECT_EQ(0, std::memcmp(expected, data, sizeof(data)));

    tlv_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, writer.pos, &format));
    tlv_element_t element{};
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
    EXPECT_EQ(2u, element.value.size);
    EXPECT_EQ(0, std::memcmp(expected + 2, element.value.data, 2));
    EXPECT_TRUE(tlv_reader_at_end(&reader));

    // The length field cannot encode less than the tag it must also count.
    const uint8_t too_short_length[] = {0x09, 0x00};
    tlv_element_t rejected{};
    size_t        consumed = 0;
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
              tlv_read(too_short_length, sizeof(too_short_length), &format, &rejected, &consumed));
}

// Every combination of element_order and length_scope round-trips the boundary
// lengths (empty and the widest value the length field can hold) and rejects
// truncated input with TLV_ERR_BUFFER_TOO_SHORT.
TEST(Integration_Tlv_Fixed, EveryFieldOrderAndLengthScopeCombinationRoundTrips) {
    const tlv_element_order_t element_orders[] = {TLV_ELEMENT_ORDER_TLV, TLV_ELEMENT_ORDER_LTV};
    const tlv_length_scope_t  length_scopes[] = {TLV_LENGTH_SCOPE_VALUE,
                                                 TLV_LENGTH_SCOPE_TAG_AND_VALUE};
    for (auto element_order : element_orders) {
        for (auto length_scope : length_scopes) {
            SCOPED_TRACE(::testing::Message()
                         << "element_order=" << element_order << " length_scope=" << length_scope);
            const tlv_fixed_format_t config = {1, 1, TLV_BYTE_ORDER_BIG_ENDIAN, element_order,
                                               length_scope};
            tlv_format_t             format{};
            ASSERT_EQ(TLV_OK, tlv_fixed_format_init(&format, &config));

            // The widest value the 1-byte length field can hold: 255, minus 1
            // for the tag when the length also counts it.
            const size_t max_value = length_scope == TLV_LENGTH_SCOPE_TAG_AND_VALUE ? 254 : 255;
            for (size_t value_size : {size_t(0), max_value}) {
                SCOPED_TRACE(value_size);
                std::vector<uint8_t> value(value_size, 0x5A);
                uint8_t              data[258] = {};
                tlv_writer_t         writer;
                ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, data, sizeof(data), &format));
                ASSERT_EQ(TLV_OK,
                          tlv_writer_write(&writer, TLV_TAG(0x7F), value.data(), value.size()));
                const size_t total = writer.pos;

                // size 0 is TLV_ERR_END_OF_BUFFER, not TLV_ERR_BUFFER_TOO_SHORT; only
                // partial input is a truncation.
                for (size_t size = 1; size < total; ++size) {
                    tlv_element_t truncated{};
                    size_t        consumed = 0;
                    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
                              tlv_read(data, size, &format, &truncated, &consumed));
                }

                tlv_reader_t reader;
                ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, total, &format));
                tlv_element_t element{};
                ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
                EXPECT_EQ(1, element.tag.size);
                EXPECT_EQ(0x7F, element.tag.data[0]);
                EXPECT_EQ(value_size, element.value.size);
                if (value_size)
                    EXPECT_EQ(0, std::memcmp(value.data(), element.value.data, value_size));
                EXPECT_TRUE(tlv_reader_at_end(&reader));
            }

            // One more than the widest encodable value must be rejected on write.
            const size_t         over_max = max_value + 1;
            std::vector<uint8_t> value(over_max, 0x5A);
            uint8_t              data[260] = {};
            tlv_writer_t         writer;
            ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, data, sizeof(data), &format));
            EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
                      tlv_writer_write(&writer, TLV_TAG(0x7F), value.data(), value.size()));
        }
    }
}
