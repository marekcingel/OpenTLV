// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/config.h"
#include "tlv/formats/fixed.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#if OPENTLV_BLUETOOTH
#include "tlv/builtins/bluetooth/bluetooth_ltv.h"
#endif
#include <gtest/gtest.h>
#include <cstring>

TEST(Unit_Tlv_Fixed, InitAcceptsValidConfigs) {
    const tlv_fixed_format_t configs[] = {
        {{1}, {1, TLV_BYTE_ORDER_BIG_ENDIAN}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE},
        {{2}, {1, TLV_BYTE_ORDER_BIG_ENDIAN}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE},
        {{1}, {2, TLV_BYTE_ORDER_LITTLE_ENDIAN}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE},
        {{2}, {2, TLV_BYTE_ORDER_LITTLE_ENDIAN}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE},
        {{255}, {8, TLV_BYTE_ORDER_BIG_ENDIAN}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE},
    };
    for (const auto& config : configs) {
        SCOPED_TRACE(::testing::Message() << "tag_size=" << config.identifier.size
                                          << " length_size=" << config.length.size);
        tlv_format_t reader{};
        ASSERT_EQ(TLV_OK, tlv_fixed_format_init(&reader, &config));
        EXPECT_EQ(&config, reader.context);

        tlv_format_t writer{};
        ASSERT_EQ(TLV_OK, tlv_fixed_format_init(&writer, &config));
        EXPECT_EQ(&config, writer.context);
    }
}

TEST(Unit_Tlv_Fixed, BothOrdersUseTheSameBinaryPrimitives) {
    const tlv_fixed_format_t configs[] = {
        {{1}, {1, TLV_BYTE_ORDER_BIG_ENDIAN}, TLV_ELEMENT_ORDER_LTV, TLV_LENGTH_SCOPE_VALUE},
        {{1},
         {1, TLV_BYTE_ORDER_BIG_ENDIAN},
         TLV_ELEMENT_ORDER_LTV,
         TLV_LENGTH_SCOPE_TAG_AND_VALUE},
        {{2},
         {2, TLV_BYTE_ORDER_LITTLE_ENDIAN},
         TLV_ELEMENT_ORDER_LTV,
         TLV_LENGTH_SCOPE_TAG_AND_VALUE},
    };
    for (const auto& config : configs) {
        tlv_format_t format{};
        ASSERT_EQ(TLV_OK, tlv_fixed_format_init(&format, &config));
        EXPECT_EQ(&config, format.context);
        EXPECT_EQ(tlv_binary_decode, format.decode);
        EXPECT_EQ(tlv_binary_encode, format.encode);
    }
}

#if OPENTLV_BLUETOOTH
// A TLV_ELEMENT_ORDER_LTV/TLV_LENGTH_SCOPE_TAG_AND_VALUE configuration matching
// tag_size/length_size/length_order must behave exactly like
// tlv_format_bluetooth_ltv, since that global is this same configuration.
TEST(Unit_Tlv_Fixed, LtvTagAndValuePresetMatchesBluetoothLtv) {
    const tlv_fixed_format_t config = {
        {1}, {1, TLV_BYTE_ORDER_BIG_ENDIAN}, TLV_ELEMENT_ORDER_LTV, TLV_LENGTH_SCOPE_TAG_AND_VALUE};
    tlv_format_t format{};
    ASSERT_EQ(TLV_OK, tlv_fixed_format_init(&format, &config));

    const uint8_t advertising[] = {0x02, 0x01, 0x06, 0x03, 0x09, 'H', 'i'};
    tlv_reader_t  from_config, from_global;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&from_config, advertising, sizeof(advertising), &format));
    ASSERT_EQ(TLV_OK, tlv_reader_init(&from_global, advertising, sizeof(advertising),
                                      &tlv_format_bluetooth_ltv));
    for (int i = 0; i < 2; ++i) {
        tlv_element_t a{}, b{};
        ASSERT_EQ(TLV_OK, tlv_reader_next(&from_config, &a));
        ASSERT_EQ(TLV_OK, tlv_reader_next(&from_global, &b));
        EXPECT_EQ(a.tag.size, b.tag.size);
        EXPECT_EQ(0, std::memcmp(a.tag.data, b.tag.data, a.tag.size));
        EXPECT_EQ(a.value.size, b.value.size);
        EXPECT_EQ(0, std::memcmp(a.value.data, b.value.data, a.value.size));
    }
    EXPECT_TRUE(tlv_reader_at_end(&from_config));
    EXPECT_TRUE(tlv_reader_at_end(&from_global));
}
#endif

TEST(Unit_Tlv_Fixed, InitRejectsInvalidFieldOrderAndLengthScope) {
    const tlv_fixed_format_t valid = {
        {1}, {1, TLV_BYTE_ORDER_BIG_ENDIAN}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
    const tlv_fixed_format_t invalid_configs[] = {
        {{1},
         {1, TLV_BYTE_ORDER_BIG_ENDIAN},
         static_cast<tlv_element_order_t>(2),
         TLV_LENGTH_SCOPE_VALUE},
        {{1},
         {1, TLV_BYTE_ORDER_BIG_ENDIAN},
         TLV_ELEMENT_ORDER_TLV,
         static_cast<tlv_length_scope_t>(2)},
    };
    tlv_format_t format{};
    ASSERT_EQ(TLV_OK, tlv_fixed_format_init(&format, &valid));
    for (const auto& config : invalid_configs) {
        EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_fixed_format_init(&format, &config));
    }
}

TEST(Unit_Tlv_Fixed, InitRejectsInvalidArgumentsWithoutModification) {
    const tlv_fixed_format_t valid = {
        {1}, {1, TLV_BYTE_ORDER_BIG_ENDIAN}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
    const tlv_fixed_format_t invalid_configs[] = {
        {{0}, {1, TLV_BYTE_ORDER_BIG_ENDIAN}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE},
        {{1}, {0, TLV_BYTE_ORDER_BIG_ENDIAN}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE},
        {{1}, {9, TLV_BYTE_ORDER_BIG_ENDIAN}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE},
    };

    tlv_format_t  reader{};
    unsigned char reader_before[sizeof(reader)];
    ASSERT_EQ(TLV_OK, tlv_fixed_format_init(&reader, &valid));
    std::memcpy(reader_before, &reader, sizeof(reader));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_fixed_format_init(nullptr, &valid));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_fixed_format_init(&reader, nullptr));
    EXPECT_EQ(0, std::memcmp(reader_before, &reader, sizeof(reader)));
    for (const auto& config : invalid_configs) {
        EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_fixed_format_init(&reader, &config));
        EXPECT_EQ(0, std::memcmp(reader_before, &reader, sizeof(reader)));
    }

    tlv_format_t  writer{};
    unsigned char writer_before[sizeof(writer)];
    ASSERT_EQ(TLV_OK, tlv_fixed_format_init(&writer, &valid));
    std::memcpy(writer_before, &writer, sizeof(writer));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_fixed_format_init(nullptr, &valid));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_fixed_format_init(&writer, nullptr));
    EXPECT_EQ(0, std::memcmp(writer_before, &writer, sizeof(writer)));
    for (const auto& config : invalid_configs) {
        EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_fixed_format_init(&writer, &config));
        EXPECT_EQ(0, std::memcmp(writer_before, &writer, sizeof(writer)));
    }
}

TEST(Unit_Tlv_Fixed, InitRejectsInvalidByteOrder) {
    const tlv_fixed_format_t unknown = {
        {1}, {2, TLV_BYTE_ORDER_UNKNOWN}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
    tlv_format_t reader{};
    tlv_format_t writer{};
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_fixed_format_init(&reader, &unknown));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_fixed_format_init(&writer, &unknown));
}

TEST(Unit_Tlv_Fixed, TruncationPreservesReaderAndOutput) {
    const tlv_fixed_format_t config = {
        {2}, {1, TLV_BYTE_ORDER_BIG_ENDIAN}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
    tlv_format_t format{};
    ASSERT_EQ(TLV_OK, tlv_fixed_format_init(&format, &config));
    const uint8_t data[] = {0x12, 0x34, 0x03, 0xAA, 0xBB, 0xCC};
    for (size_t size = 0; size < sizeof(data); ++size) {
        tlv_reader_t reader;
        ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, size, &format));
        tlv_element_t element = {TLV_TAG(0xEE), {nullptr, 42}};
        EXPECT_EQ(size ? TLV_ERR_TRUNCATED : TLV_END, tlv_reader_next(&reader, &element));
        EXPECT_EQ(0u, reader.pos);
        EXPECT_EQ(0xEE, element.tag.data[0]);
        EXPECT_EQ(nullptr, element.value.data);
        EXPECT_EQ(42u, element.value.size);
    }
}

// tlv_format_t is a plain, trivially copyable value: copying it shallow-copies
// the context pointer without copying or extending the lifetime of what it
// points to. See docs/guides/memory.md#format-context-ownership-and-lifetime.
TEST(Unit_Tlv_Fixed, CopyingTheDescriptorSharesTheSameBorrowedContext) {
    const tlv_fixed_format_t config = {
        {2}, {1, TLV_BYTE_ORDER_BIG_ENDIAN}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
    tlv_format_t original{};
    ASSERT_EQ(TLV_OK, tlv_fixed_format_init(&original, &config));

    const tlv_format_t copy = original;
    EXPECT_EQ(&config, copy.context);
    EXPECT_EQ(original.context, copy.context);

    const uint8_t   value[] = {0xAA, 0xBB, 0xCC};
    const tlv_tag_t tag = TLV_TAG(0x12, 0x34);
    uint8_t         from_original[16] = {};
    uint8_t         from_copy[16] = {};
    size_t          written_original = 0, written_copy = 0;
    ASSERT_EQ(TLV_OK, tlv_write(from_original, sizeof(from_original), &original, tag, value,
                                sizeof(value), &written_original));
    ASSERT_EQ(TLV_OK, tlv_write(from_copy, sizeof(from_copy), &copy, tag, value, sizeof(value),
                                &written_copy));
    EXPECT_EQ(written_original, written_copy);
    EXPECT_EQ(0, std::memcmp(from_original, from_copy, written_original));

    tlv_element_t element_from_original{};
    tlv_element_t element_from_copy{};
    size_t        consumed_original = 0, consumed_copy = 0;
    ASSERT_EQ(TLV_OK, tlv_read(from_original, written_original, &original, &element_from_original,
                               &consumed_original));
    ASSERT_EQ(TLV_OK, tlv_read(from_copy, written_copy, &copy, &element_from_copy, &consumed_copy));
    EXPECT_EQ(consumed_original, consumed_copy);
    EXPECT_EQ(element_from_original.value.size, element_from_copy.value.size);
}

TEST(Unit_Tlv_Fixed, InvalidWritesPreserveBufferAndPosition) {
    const tlv_fixed_format_t config = {
        {1}, {1, TLV_BYTE_ORDER_BIG_ENDIAN}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
    tlv_format_t format{};
    ASSERT_EQ(TLV_OK, tlv_fixed_format_init(&format, &config));
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
