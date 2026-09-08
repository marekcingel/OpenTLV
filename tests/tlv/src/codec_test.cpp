#include "tlv/formats/fixed_1byte.h"
#include <gtest/gtest.h>
#include "tlv/codec/codec.h"
#include "tlv/endian.h"
#include "tlv/types.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"

namespace {
tlv_codec_result_t decode_u16(const void* context, const uint8_t* data,
                             size_t size, void* value, size_t capacity) {
    if (size != 2) return TLV_CODEC_ERR_INVALID_VALUE;
    if (capacity < sizeof(uint16_t)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    *static_cast<uint16_t*>(value) = *static_cast<const bool*>(context)
        ? tlv_read_u16_be(data) : tlv_read_u16_le(data);
    return TLV_CODEC_OK;
}
tlv_codec_result_t encode_u16(const void* context, const void* value,
                             size_t size, uint8_t* data, size_t capacity,
                             size_t* written) {
    if (size != sizeof(uint16_t)) return TLV_CODEC_ERR_INVALID_VALUE;
    if (data) {
        if (capacity < 2) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
        if (*static_cast<const bool*>(context))
            tlv_write_u16_be(data, *static_cast<const uint16_t*>(value));
        else tlv_write_u16_le(data, *static_cast<const uint16_t*>(value));
    }
    *written = 2;
    return TLV_CODEC_OK;
}
const bool big_endian = true;
const tlv_codec_t scalar = {&big_endian, decode_u16, encode_u16};

tlv_codec_result_t decode_view(const void*, const uint8_t* data, size_t size,
                              void* value, size_t capacity) {
    if (capacity < sizeof(tlv_buffer_t)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    *static_cast<tlv_buffer_t*>(value) = tlv_buffer_t{data, size};
    return TLV_CODEC_OK;
}
}

TEST(Codec, ScalarRoundTripAndSizeQuery) {
    uint16_t value = 0x1234, decoded = 0;
    uint8_t bytes[3] = {0, 0, 0xab};
    size_t written = 99;
    EXPECT_EQ(tlv_codec_encode(&scalar, &value, sizeof(value), nullptr, 0, &written), TLV_CODEC_OK);
    EXPECT_EQ(written, 2u);
    ASSERT_EQ(tlv_codec_encode(&scalar, &value, sizeof(value), bytes, 2, &written), TLV_CODEC_OK);
    EXPECT_EQ(written, 2u);
    EXPECT_EQ(bytes[0], 0x12);
    EXPECT_EQ(bytes[1], 0x34);
    EXPECT_EQ(bytes[2], 0xab);
    ASSERT_EQ(tlv_codec_decode(&scalar, bytes, 2, &decoded, sizeof(decoded)), TLV_CODEC_OK);
    EXPECT_EQ(decoded, value);
    const bool little_endian = false;
    const tlv_codec_t little = {&little_endian, decode_u16, encode_u16};
    ASSERT_EQ(tlv_codec_decode(&little, bytes, 2, &decoded, sizeof(decoded)), TLV_CODEC_OK);
    EXPECT_EQ(decoded, 0x3412);
}

TEST(Codec, BorrowedAndEmptyRepresentations) {
    const tlv_codec_t codec = {nullptr, decode_view, nullptr};
    uint8_t bytes[] = {1, 2, 3};
    tlv_buffer_t view = {};
    ASSERT_EQ(tlv_codec_decode(&codec, bytes, sizeof(bytes), &view, sizeof(view)), TLV_CODEC_OK);
    EXPECT_EQ(view.data, bytes);
    EXPECT_EQ(view.length, sizeof(bytes));
    bytes[0] = 9;
    EXPECT_EQ(view.data[0], 9);
    ASSERT_EQ(tlv_codec_decode(&codec, nullptr, 0, &view, sizeof(view)), TLV_CODEC_OK);
    EXPECT_EQ(view.data, nullptr);
    EXPECT_EQ(view.length, 0u);
}

TEST(Codec, ExplicitConversionBetweenFramingOperations) {
    uint16_t value = 0x1234, decoded = 0;
    uint8_t raw[2], framed[4];
    size_t raw_size = 0, framed_size = 0, consumed = 0;
    tlv_tag_t tag = {};
    tag.size = 1;
    tag.data[0] = 1;
    ASSERT_EQ(tlv_codec_encode(&scalar, &value, sizeof(value), raw, sizeof(raw), &raw_size), TLV_CODEC_OK);
    ASSERT_EQ(tlv_write(framed, sizeof(framed), &tlv_format_fixed_1byte,
                        tag, raw, raw_size, &framed_size), TLV_OK);
    tlv_view_t view = {};
    ASSERT_EQ(tlv_read(framed, framed_size, &tlv_format_fixed_1byte, &view, &consumed), TLV_OK);
    EXPECT_EQ(consumed, framed_size);
    EXPECT_EQ(view.value.data, framed + 2);
    ASSERT_EQ(tlv_codec_decode(&scalar, view.value.data, view.value.length,
                               &decoded, sizeof(decoded)), TLV_CODEC_OK);
    EXPECT_EQ(decoded, value);
    // Framing also accepts values that this codec rejects.
    framed[1] = 1;
    ASSERT_EQ(tlv_read(framed, 3, &tlv_format_fixed_1byte, &view, &consumed), TLV_OK);
    EXPECT_EQ(tlv_codec_decode(&scalar, view.value.data, view.value.length,
                               &decoded, sizeof(decoded)), TLV_CODEC_ERR_INVALID_VALUE);
}

TEST(Codec, CallbackErrorsAndStorageBounds) {
    uint8_t bytes[] = {0x12, 0x34};
    uint16_t value = 7;
    size_t written = 99;
    EXPECT_EQ(tlv_codec_decode(&scalar, bytes, 1, &value, sizeof(value)), TLV_CODEC_ERR_INVALID_VALUE);
    EXPECT_EQ(tlv_codec_decode(&scalar, bytes, 2, &value, 1), TLV_CODEC_ERR_BUFFER_TOO_SHORT);
    EXPECT_EQ(value, 7);
    EXPECT_EQ(tlv_codec_encode(&scalar, &value, sizeof(value), bytes, 1, &written), TLV_CODEC_ERR_BUFFER_TOO_SHORT);
    EXPECT_EQ(written, 0u);
    EXPECT_EQ(bytes[0], 0x12);
    EXPECT_EQ(tlv_codec_encode(&scalar, &value, 0, nullptr, 0, &written), TLV_CODEC_ERR_INVALID_VALUE);
    EXPECT_EQ(written, 0u);
}

TEST(Codec, InvalidArgumentsAndUnsupportedDirections) {
    uint8_t byte = 0;
    uint16_t value = 0;
    size_t written = 99;
    const tlv_codec_t empty = {};
    EXPECT_EQ(tlv_codec_decode(nullptr, &byte, 1, &value, sizeof(value)), TLV_CODEC_ERR_NULL_ARG);
    EXPECT_EQ(tlv_codec_decode(&scalar, nullptr, 1, &value, sizeof(value)), TLV_CODEC_ERR_NULL_ARG);
    EXPECT_EQ(tlv_codec_decode(&scalar, &byte, 1, nullptr, 0), TLV_CODEC_ERR_NULL_ARG);
    EXPECT_EQ(tlv_codec_decode(&empty, &byte, 1, &value, sizeof(value)), TLV_CODEC_ERR_UNSUPPORTED);
    EXPECT_EQ(tlv_codec_encode(nullptr, &value, sizeof(value), &byte, 1, &written), TLV_CODEC_ERR_NULL_ARG);
    EXPECT_EQ(written, 0u);
    EXPECT_EQ(tlv_codec_encode(&scalar, nullptr, 0, &byte, 1, &written), TLV_CODEC_ERR_NULL_ARG);
    EXPECT_EQ(tlv_codec_encode(&scalar, &value, sizeof(value), nullptr, 1, &written), TLV_CODEC_ERR_NULL_ARG);
    EXPECT_EQ(tlv_codec_encode(&scalar, &value, sizeof(value), &byte, 1, nullptr), TLV_CODEC_ERR_NULL_ARG);
    EXPECT_EQ(tlv_codec_encode(&empty, &value, sizeof(value), nullptr, 0, &written), TLV_CODEC_ERR_UNSUPPORTED);
    EXPECT_EQ(written, 0u);
    EXPECT_STREQ(tlv_codec_strerror(TLV_CODEC_ERR_INVALID_VALUE), "Invalid codec value");
    EXPECT_STREQ(tlv_codec_strerror(static_cast<tlv_codec_result_t>(99)), "Unknown codec error");
}
