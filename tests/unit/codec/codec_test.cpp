// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include <gtest/gtest.h>
#include "tlv/codec/codec.h"
#include "tlv/endian.h"
#include "tlv/element.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"

namespace {
tlv_result_t decode_u16(const void* context, const uint8_t* data, size_t size, void* value,
                        size_t capacity, tlv_codec_diagnostic_t* diagnostic) {
    tlv_codec_diagnostic_init(diagnostic, TLV_CODEC_OP_DECODE);
    if (size != sizeof(uint16_t))
        return tlv_codec_diagnostic_result(diagnostic, TLV_ERR_INVALID_VALUE);
    if (capacity < sizeof(uint16_t))
        return tlv_codec_diagnostic_result(diagnostic, TLV_ERR_BUFFER_TOO_SHORT);
    *static_cast<uint16_t*>(value) =
        *static_cast<const bool*>(context) ? tlv_read_u16_be(data) : tlv_read_u16_le(data);
    return tlv_codec_diagnostic_result(diagnostic, TLV_OK);
}
tlv_result_t encode_u16(const void* context, const void* value, size_t size, uint8_t* data,
                        size_t capacity, size_t* written, tlv_codec_diagnostic_t* diagnostic) {
    tlv_codec_diagnostic_init(diagnostic, TLV_CODEC_OP_ENCODE);
    if (size != sizeof(uint16_t))
        return tlv_codec_diagnostic_result(diagnostic, TLV_ERR_INVALID_VALUE);
    if (data) {
        if (capacity < sizeof(uint16_t))
            return tlv_codec_diagnostic_result(diagnostic, TLV_ERR_BUFFER_TOO_SHORT);
        if (*static_cast<const bool*>(context))
            tlv_write_u16_be(data, *static_cast<const uint16_t*>(value));
        else
            tlv_write_u16_le(data, *static_cast<const uint16_t*>(value));
    }
    *written = sizeof(uint16_t);
    return tlv_codec_diagnostic_result(diagnostic, TLV_OK);
}
const bool        big_endian = true;
const tlv_codec_t scalar = {&big_endian, decode_u16, encode_u16};

struct byte_view {
    const uint8_t* data;
    size_t         length;
};

tlv_result_t decode_view(const void*, const uint8_t* data, size_t size, void* value,
                         size_t capacity, tlv_codec_diagnostic_t* diagnostic) {
    tlv_codec_diagnostic_init(diagnostic, TLV_CODEC_OP_DECODE);
    if (capacity < sizeof(byte_view))
        return tlv_codec_diagnostic_result(diagnostic, TLV_ERR_BUFFER_TOO_SHORT);
    *static_cast<byte_view*>(value) = byte_view{data, size};
    return tlv_codec_diagnostic_result(diagnostic, TLV_OK);
}
} // namespace

TEST(Unit_Tlv_Codec, ScalarRoundTripAndSizeQuery) {
    uint16_t value = 0x1234, decoded = 0;
    uint8_t  bytes[3] = {0, 0, 0xab};
    size_t   written = 99;
    EXPECT_EQ(tlv_codec_encode(&scalar, &value, sizeof(value), nullptr, 0, &written, NULL), TLV_OK);
    EXPECT_EQ(written, 2u);
    ASSERT_EQ(tlv_codec_encode(&scalar, &value, sizeof(value), bytes, 2, &written, NULL), TLV_OK);
    EXPECT_EQ(written, 2u);
    EXPECT_EQ(bytes[0], 0x12);
    EXPECT_EQ(bytes[1], 0x34);
    EXPECT_EQ(bytes[2], 0xab);
    ASSERT_EQ(tlv_codec_decode(&scalar, bytes, 2, &decoded, sizeof(decoded), NULL), TLV_OK);
    EXPECT_EQ(decoded, value);
    const bool        little_endian = false;
    const tlv_codec_t little = {&little_endian, decode_u16, encode_u16};
    ASSERT_EQ(tlv_codec_decode(&little, bytes, 2, &decoded, sizeof(decoded), NULL), TLV_OK);
    EXPECT_EQ(decoded, 0x3412);
}

TEST(Unit_Tlv_Codec, BorrowedAndEmptyRepresentations) {
    const tlv_codec_t codec = {nullptr, decode_view, nullptr};
    uint8_t           bytes[] = {1, 2, 3};
    byte_view         view = {};
    ASSERT_EQ(tlv_codec_decode(&codec, bytes, sizeof(bytes), &view, sizeof(view), NULL), TLV_OK);
    EXPECT_EQ(view.data, bytes);
    EXPECT_EQ(view.length, sizeof(bytes));
    bytes[0] = 9;
    EXPECT_EQ(view.data[0], 9);
    ASSERT_EQ(tlv_codec_decode(&codec, nullptr, 0, &view, sizeof(view), NULL), TLV_OK);
    EXPECT_EQ(view.data, nullptr);
    EXPECT_EQ(view.length, 0u);
}

TEST(Unit_Tlv_Codec, CallbackErrorsAndStorageBounds) {
    uint8_t  bytes[] = {0x12, 0x34};
    uint16_t value = 7;
    size_t   written = 99;
    EXPECT_EQ(tlv_codec_decode(&scalar, bytes, 1, &value, sizeof(value), NULL),
              TLV_ERR_INVALID_VALUE);
    EXPECT_EQ(tlv_codec_decode(&scalar, bytes, 2, &value, 1, NULL), TLV_ERR_BUFFER_TOO_SHORT);
    EXPECT_EQ(value, 7);
    EXPECT_EQ(tlv_codec_encode(&scalar, &value, sizeof(value), bytes, 1, &written, NULL),
              TLV_ERR_BUFFER_TOO_SHORT);
    EXPECT_EQ(written, 0u);
    EXPECT_EQ(bytes[0], 0x12);
    EXPECT_EQ(tlv_codec_encode(&scalar, &value, 0, nullptr, 0, &written, NULL),
              TLV_ERR_INVALID_VALUE);
    EXPECT_EQ(written, 0u);
}

TEST(Unit_Tlv_Codec, InvalidArgumentsAndUnsupportedDirections) {
    uint8_t           byte = 0;
    uint16_t          value = 0;
    size_t            written = 99;
    const tlv_codec_t empty = {};
    EXPECT_EQ(tlv_codec_decode(nullptr, &byte, 1, &value, sizeof(value), NULL), TLV_ERR_NULL_ARG);
    EXPECT_EQ(tlv_codec_decode(&scalar, nullptr, 1, &value, sizeof(value), NULL), TLV_ERR_NULL_ARG);
    EXPECT_EQ(tlv_codec_decode(&scalar, &byte, 1, nullptr, 0, NULL), TLV_ERR_NULL_ARG);
    EXPECT_EQ(tlv_codec_decode(&empty, &byte, 1, &value, sizeof(value), NULL), TLV_ERR_UNSUPPORTED);
    EXPECT_EQ(tlv_codec_encode(nullptr, &value, sizeof(value), &byte, 1, &written, NULL),
              TLV_ERR_NULL_ARG);
    EXPECT_EQ(written, 0u);
    EXPECT_EQ(tlv_codec_encode(&scalar, nullptr, 0, &byte, 1, &written, NULL), TLV_ERR_NULL_ARG);
    EXPECT_EQ(tlv_codec_encode(&scalar, &value, sizeof(value), nullptr, 1, &written, NULL),
              TLV_ERR_NULL_ARG);
    EXPECT_EQ(tlv_codec_encode(&scalar, &value, sizeof(value), &byte, 1, nullptr, NULL),
              TLV_ERR_NULL_ARG);
    EXPECT_EQ(tlv_codec_encode(&empty, &value, sizeof(value), nullptr, 0, &written, NULL),
              TLV_ERR_UNSUPPORTED);
    EXPECT_EQ(written, 0u);
    EXPECT_STREQ(tlv_strerror(TLV_ERR_INVALID_VALUE), "invalid data or application representation");
    EXPECT_STREQ(tlv_strerror(static_cast<tlv_result_t>(99)), "unknown error");
}

TEST(Unit_Tlv_Codec, SharedResultsAndCallbackEvidenceAreLossless) {
    for (int code = TLV_OK; code <= TLV_ERR_CALLBACK; ++code) {
        const auto  reported = static_cast<tlv_result_t>(code);
        tlv_codec_t codec = {
            &reported,
            [](const void* context, const uint8_t*, size_t, void*, size_t,
               tlv_codec_diagnostic_t*) { return *static_cast<const tlv_result_t*>(context); },
            [](const void* context, const void*, size_t, uint8_t*, size_t, size_t* written,
               tlv_codec_diagnostic_t*) {
                *written = 0;
                return *static_cast<const tlv_result_t*>(context);
            }};
        unsigned char          value = 0;
        tlv_codec_diagnostic_t diagnostic{};
        const auto decode = reported == TLV_ERR_END_OF_BUFFER ? TLV_ERR_CALLBACK : reported;
        EXPECT_EQ(decode, tlv_codec_decode(&codec, nullptr, 0, &value, 1, &diagnostic));
        EXPECT_EQ(decode, diagnostic.diagnostic.code);
        EXPECT_EQ(reported, diagnostic.codec.reported);
        EXPECT_EQ(decode, tlv_codec_decode(&codec, nullptr, 0, &value, 1, nullptr));
        size_t     written = 99;
        const auto encode = reported == TLV_ERR_END_OF_BUFFER || reported == TLV_NEED_MORE_DATA
                                ? TLV_ERR_CALLBACK
                                : reported;
        EXPECT_EQ(encode, tlv_codec_encode(&codec, &value, 1, nullptr, 0, &written, &diagnostic));
        EXPECT_EQ(encode, diagnostic.diagnostic.code);
        EXPECT_EQ(reported, diagnostic.codec.reported);
        EXPECT_EQ(TLV_CODEC_OP_MEASURE, diagnostic.codec.operation);
        EXPECT_EQ(0u, written);
    }
    tlv_codec_t   codec = {nullptr,
                           [](const void*, const uint8_t*, size_t, void*, size_t,
                              tlv_codec_diagnostic_t*) { return static_cast<tlv_result_t>(999); },
                           [](const void*, const void*, size_t, uint8_t*, size_t capacity,
                              size_t* written, tlv_codec_diagnostic_t*) {
                             *written = capacity + 1;
                             return TLV_OK;
                           }};
    unsigned char value = 0;
    tlv_codec_diagnostic_t diagnostic{};
    EXPECT_EQ(TLV_ERR_CALLBACK, tlv_codec_decode(&codec, nullptr, 0, &value, 1, &diagnostic));
    EXPECT_EQ(999, diagnostic.codec.reported);
    EXPECT_EQ(TLV_CODEC_VIOLATION_RESULT, diagnostic.codec.violation);
    size_t written = 99;
    EXPECT_EQ(TLV_ERR_CALLBACK,
              tlv_codec_encode(&codec, &value, 1, &value, 1, &written, &diagnostic));
    EXPECT_EQ(TLV_OK, diagnostic.codec.reported);
    EXPECT_EQ(TLV_CODEC_VIOLATION_SIZE, diagnostic.codec.violation);
    EXPECT_EQ(0u, written);
}
