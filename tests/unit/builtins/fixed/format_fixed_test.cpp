#include "tlv/builtins/fixed/fixed.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#include <gtest/gtest.h>
#include <cstring>

TEST(Unit_Tlv_Fixed, InitAcceptsValidConfigs) {
    const tlv_fixed_config_t configs[] = {
        {1, 1, TLV_BYTE_ORDER_BIG_ENDIAN},    {2, 1, TLV_BYTE_ORDER_BIG_ENDIAN},
        {1, 2, TLV_BYTE_ORDER_LITTLE_ENDIAN}, {2, 2, TLV_BYTE_ORDER_LITTLE_ENDIAN},
        {255, 8, TLV_BYTE_ORDER_BIG_ENDIAN},
    };
    for (const auto& config : configs) {
        SCOPED_TRACE(::testing::Message()
                     << "tag_size=" << config.tag_size << " length_size=" << config.length_size);
        tlv_reader_format_t reader{};
        ASSERT_EQ(TLV_OK, tlv_fixed_reader_format_init(&reader, &config));
        EXPECT_EQ(&config, reader.context);
        EXPECT_NE(nullptr, reader.read_tag);
        EXPECT_NE(nullptr, reader.read_length);
        EXPECT_EQ(nullptr, reader.read_value_bounds);
        EXPECT_EQ(nullptr, reader.read_element);

        tlv_writer_format_t writer{};
        ASSERT_EQ(TLV_OK, tlv_fixed_writer_format_init(&writer, &config));
        EXPECT_EQ(&config, writer.context);
        EXPECT_NE(nullptr, writer.write_tag);
        EXPECT_NE(nullptr, writer.write_length);
        EXPECT_NE(nullptr, writer.length_size);
        EXPECT_EQ(nullptr, writer.write_header);
    }
}

TEST(Unit_Tlv_Fixed, InitRejectsInvalidArgumentsWithoutModification) {
    const tlv_fixed_config_t valid = {1, 1, TLV_BYTE_ORDER_BIG_ENDIAN};
    const tlv_fixed_config_t invalid_configs[] = {
        {0, 1, TLV_BYTE_ORDER_BIG_ENDIAN},
        {1, 0, TLV_BYTE_ORDER_BIG_ENDIAN},
        {1, 9, TLV_BYTE_ORDER_BIG_ENDIAN},
    };

    tlv_reader_format_t reader{};
    unsigned char       reader_before[sizeof(reader)];
    ASSERT_EQ(TLV_OK, tlv_fixed_reader_format_init(&reader, &valid));
    std::memcpy(reader_before, &reader, sizeof(reader));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_fixed_reader_format_init(nullptr, &valid));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_fixed_reader_format_init(&reader, nullptr));
    EXPECT_EQ(0, std::memcmp(reader_before, &reader, sizeof(reader)));
    for (const auto& config : invalid_configs) {
        EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_fixed_reader_format_init(&reader, &config));
        EXPECT_EQ(0, std::memcmp(reader_before, &reader, sizeof(reader)));
    }

    tlv_writer_format_t writer{};
    unsigned char       writer_before[sizeof(writer)];
    ASSERT_EQ(TLV_OK, tlv_fixed_writer_format_init(&writer, &valid));
    std::memcpy(writer_before, &writer, sizeof(writer));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_fixed_writer_format_init(nullptr, &valid));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_fixed_writer_format_init(&writer, nullptr));
    EXPECT_EQ(0, std::memcmp(writer_before, &writer, sizeof(writer)));
    for (const auto& config : invalid_configs) {
        EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_fixed_writer_format_init(&writer, &config));
        EXPECT_EQ(0, std::memcmp(writer_before, &writer, sizeof(writer)));
    }
}

TEST(Unit_Tlv_Fixed, InitRejectsInvalidByteOrder) {
    const tlv_fixed_config_t unknown = {1, 2, TLV_BYTE_ORDER_UNKNOWN};
    const tlv_fixed_config_t bogus = {1, 2, static_cast<tlv_byte_order_t>(99)};
    tlv_reader_format_t      reader{};
    tlv_writer_format_t      writer{};
    EXPECT_EQ(TLV_ERR_INVALID_BYTE_ORDER, tlv_fixed_reader_format_init(&reader, &unknown));
    EXPECT_EQ(TLV_ERR_INVALID_BYTE_ORDER, tlv_fixed_reader_format_init(&reader, &bogus));
    EXPECT_EQ(TLV_ERR_INVALID_BYTE_ORDER, tlv_fixed_writer_format_init(&writer, &unknown));
    EXPECT_EQ(TLV_ERR_INVALID_BYTE_ORDER, tlv_fixed_writer_format_init(&writer, &bogus));
}

TEST(Unit_Tlv_Fixed, TruncationPreservesReaderAndOutput) {
    const tlv_fixed_config_t config = {2, 1, TLV_BYTE_ORDER_BIG_ENDIAN};
    tlv_reader_format_t      format{};
    ASSERT_EQ(TLV_OK, tlv_fixed_reader_format_init(&format, &config));
    const uint8_t data[] = {0x12, 0x34, 0x03, 0xAA, 0xBB, 0xCC};
    for (size_t size = 0; size < sizeof(data); ++size) {
        tlv_reader_t reader;
        ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, size, &format));
        tlv_view_t entry = {TLV_TAG(0xEE), {nullptr, 42}};
        EXPECT_EQ(size ? TLV_ERR_BUFFER_TOO_SHORT : TLV_ERR_END_OF_BUFFER,
                  tlv_reader_next(&reader, &entry));
        EXPECT_EQ(0u, reader.pos);
        EXPECT_EQ(0xEE, entry.tag.data[0]);
        EXPECT_EQ(nullptr, entry.value.data);
        EXPECT_EQ(42u, entry.value.length);
    }
}

TEST(Unit_Tlv_Fixed, InvalidWritesPreserveBufferAndPosition) {
    const tlv_fixed_config_t config = {1, 1, TLV_BYTE_ORDER_BIG_ENDIAN};
    tlv_writer_format_t      format{};
    ASSERT_EQ(TLV_OK, tlv_fixed_writer_format_init(&format, &config));
    uint8_t data[258];
    std::memset(data, 0xEE, sizeof(data));
    uint8_t      value[256] = {};
    tlv_writer_t writer;
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, data, sizeof(data), &format));
    const tlv_tag_t tag = TLV_TAG(1);
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_writer_write(&writer, tag, value, 256));
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE, tlv_writer_write(&writer, TLV_TAG(1, 2), value, 1));
    EXPECT_EQ(0u, writer.pos);
    for (auto byte : data) EXPECT_EQ(0xEE, byte);
}
