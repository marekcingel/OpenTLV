// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/codec/values.h"
#include "tlv/endian.h"
#include <string.h>

static tlv_codec_result_t decode_uint8(const void* context, const uint8_t* data, size_t size,
                                       void* value, size_t capacity) {
    uint8_t result;
    (void)context;
    if (size != 1) return TLV_CODEC_ERR_INVALID_VALUE;
    if (capacity < sizeof(result)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    result = data[0];
    memcpy(value, &result, sizeof(result));
    return TLV_CODEC_OK;
}

static tlv_codec_result_t encode_uint8(const void* context, const void* value, size_t size,
                                       uint8_t* data, size_t capacity, size_t* written) {
    uint8_t input;
    (void)context;
    if (size != sizeof(input)) return TLV_CODEC_ERR_INVALID_VALUE;
    if (data) {
        if (capacity < 1) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
        memcpy(&input, value, sizeof(input));
        data[0] = input;
    }
    *written = 1;
    return TLV_CODEC_OK;
}

const tlv_codec_t tlv_codec_uint8 = {NULL, decode_uint8, encode_uint8};

static const tlv_byte_order_t big_endian = TLV_BYTE_ORDER_BIG_ENDIAN;
static const tlv_byte_order_t little_endian = TLV_BYTE_ORDER_LITTLE_ENDIAN;

static tlv_codec_result_t decode_uint16(const void* context, const uint8_t* data, size_t size,
                                        void* value, size_t capacity) {
    uint16_t result;
    (void)context;
    if (size != 2) return TLV_CODEC_ERR_INVALID_VALUE;
    if (capacity < sizeof(result)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    result = *(const tlv_byte_order_t*)context == TLV_BYTE_ORDER_BIG_ENDIAN ? tlv_read_u16_be(data)
                                                                            : tlv_read_u16_le(data);
    memcpy(value, &result, sizeof(result));
    return TLV_CODEC_OK;
}

static tlv_codec_result_t encode_uint16(const void* context, const void* value, size_t size,
                                        uint8_t* data, size_t capacity, size_t* written) {
    uint16_t input;
    (void)context;
    if (size != sizeof(input)) return TLV_CODEC_ERR_INVALID_VALUE;
    if (data) {
        if (capacity < 2) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
        memcpy(&input, value, sizeof(input));
        if (*(const tlv_byte_order_t*)context == TLV_BYTE_ORDER_BIG_ENDIAN)
            tlv_write_u16_be(data, input);
        else
            tlv_write_u16_le(data, input);
    }
    *written = 2;
    return TLV_CODEC_OK;
}

const tlv_codec_t tlv_codec_uint16_be = {&big_endian, decode_uint16, encode_uint16};

static tlv_codec_result_t decode_uint32(const void* context, const uint8_t* data, size_t size,
                                        void* value, size_t capacity) {
    uint32_t result;
    (void)context;
    if (size != 4) return TLV_CODEC_ERR_INVALID_VALUE;
    if (capacity < sizeof(result)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    result = *(const tlv_byte_order_t*)context == TLV_BYTE_ORDER_BIG_ENDIAN ? tlv_read_u32_be(data)
                                                                            : tlv_read_u32_le(data);
    memcpy(value, &result, sizeof(result));
    return TLV_CODEC_OK;
}

static tlv_codec_result_t encode_uint32(const void* context, const void* value, size_t size,
                                        uint8_t* data, size_t capacity, size_t* written) {
    uint32_t input;
    (void)context;
    if (size != sizeof(input)) return TLV_CODEC_ERR_INVALID_VALUE;
    if (data) {
        if (capacity < 4) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
        memcpy(&input, value, sizeof(input));
        if (*(const tlv_byte_order_t*)context == TLV_BYTE_ORDER_BIG_ENDIAN)
            tlv_write_u32_be(data, input);
        else
            tlv_write_u32_le(data, input);
    }
    *written = 4;
    return TLV_CODEC_OK;
}

const tlv_codec_t tlv_codec_uint32_be = {&big_endian, decode_uint32, encode_uint32};

static tlv_codec_result_t decode_bytes(const void* context, const uint8_t* data, size_t size,
                                       void* value, size_t capacity) {
    tlv_value_t result;
    (void)context;
    if (capacity < sizeof(result)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    result.data = data;
    result.size = size;
    memcpy(value, &result, sizeof(result));
    return TLV_CODEC_OK;
}

static tlv_codec_result_t encode_bytes(const void* context, const void* value, size_t size,
                                       uint8_t* data, size_t capacity, size_t* written) {
    tlv_value_t input;
    size_t length;
    (void)context;
    if (size != sizeof(input)) return TLV_CODEC_ERR_INVALID_VALUE;
    memcpy(&input, value, sizeof(input));
    if (!input.data && input.size) return TLV_CODEC_ERR_NULL_ARG;
    if (tlv_size_to_native(input.size, &length) != TLV_OK) return TLV_CODEC_ERR_INVALID_VALUE;
    if (data) {
        if (capacity < length) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
        if (length) memcpy(data, input.data, length);
    }
    *written = length;
    return TLV_CODEC_OK;
}

const tlv_codec_t tlv_codec_bytes = {NULL, decode_bytes, encode_bytes};

const tlv_codec_t tlv_codec_uint16_le = {&little_endian, decode_uint16, encode_uint16};
const tlv_codec_t tlv_codec_uint32_le = {&little_endian, decode_uint32, encode_uint32};

/* Minimal signed two's-complement big-endian values. */
static int integer_decode_value(const uint8_t* data, size_t size, int64_t* out) {
    uint64_t bits;
    size_t i;
    if (size < 1 || size > sizeof(int64_t)) return 0;
    bits = (data[0] & 0x80) ? ~(uint64_t)0 : 0;
    for (i = 0; i < size; ++i) bits = (bits << 8) | data[i];
    *out = bits <= INT64_MAX ? (int64_t)bits : -1 - (int64_t)(~bits);
    return 1;
}

static size_t integer_minimal_size(const uint8_t full[sizeof(int64_t)]) {
    size_t start = 0;
    while (start + 1 < sizeof(int64_t) && ((full[start] == 0x00 && (full[start + 1] & 0x80) == 0) ||
                                           (full[start] == 0xFF && (full[start + 1] & 0x80) != 0)))
        ++start;
    return sizeof(int64_t) - start;
}

static void integer_encode_value(int64_t value, uint8_t full[sizeof(int64_t)]) {
    uint64_t bits = (uint64_t)value;
    size_t i;
    for (i = 0; i < sizeof(int64_t); ++i)
        full[i] = (uint8_t)(bits >> (8 * (sizeof(int64_t) - 1 - i)));
}

static tlv_codec_result_t decode_integer(const void* context, const uint8_t* data, size_t size,
                                         void* value, size_t capacity) {
    int64_t result;
    (void)context;
    if (size == 0 || size > sizeof(int64_t)) return TLV_CODEC_ERR_INVALID_VALUE;
    if (size > 1 &&
        ((data[0] == 0 && (data[1] & 0x80) == 0) || (data[0] == 0xFF && (data[1] & 0x80) != 0)))
        return TLV_CODEC_ERR_INVALID_VALUE;
    if (!integer_decode_value(data, size, &result)) return TLV_CODEC_ERR_INVALID_VALUE;
    if (capacity < sizeof(result)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    memcpy(value, &result, sizeof(result));
    return TLV_CODEC_OK;
}

static tlv_codec_result_t encode_integer(const void* context, const void* value, size_t size,
                                         uint8_t* data, size_t capacity, size_t* written) {
    int64_t input;
    uint8_t full[sizeof(int64_t)];
    size_t minimal_size, offset;
    (void)context;
    if (size != sizeof(input)) return TLV_CODEC_ERR_INVALID_VALUE;
    memcpy(&input, value, sizeof(input));
    integer_encode_value(input, full);
    minimal_size = integer_minimal_size(full);
    offset = sizeof(full) - minimal_size;
    if (data) {
        if (capacity < minimal_size) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
        memcpy(data, full + offset, minimal_size);
    }
    *written = minimal_size;
    return TLV_CODEC_OK;
}

const tlv_codec_t tlv_codec_int64_minimal_be = {NULL, decode_integer, encode_integer};
