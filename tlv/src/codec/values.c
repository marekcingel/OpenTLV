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

static tlv_codec_result_t decode_uint16_be(const void* context, const uint8_t* data, size_t size,
                                           void* value, size_t capacity) {
    uint16_t result;
    (void)context;
    if (size != 2) return TLV_CODEC_ERR_INVALID_VALUE;
    if (capacity < sizeof(result)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    result = tlv_read_u16_be(data);
    memcpy(value, &result, sizeof(result));
    return TLV_CODEC_OK;
}

static tlv_codec_result_t encode_uint16_be(const void* context, const void* value, size_t size,
                                           uint8_t* data, size_t capacity, size_t* written) {
    uint16_t input;
    (void)context;
    if (size != sizeof(input)) return TLV_CODEC_ERR_INVALID_VALUE;
    if (data) {
        if (capacity < 2) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
        memcpy(&input, value, sizeof(input));
        tlv_write_u16_be(data, input);
    }
    *written = 2;
    return TLV_CODEC_OK;
}

const tlv_codec_t tlv_codec_uint16_be = {NULL, decode_uint16_be, encode_uint16_be};

static tlv_codec_result_t decode_uint32_be(const void* context, const uint8_t* data, size_t size,
                                           void* value, size_t capacity) {
    uint32_t result;
    (void)context;
    if (size != 4) return TLV_CODEC_ERR_INVALID_VALUE;
    if (capacity < sizeof(result)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    result = tlv_read_u32_be(data);
    memcpy(value, &result, sizeof(result));
    return TLV_CODEC_OK;
}

static tlv_codec_result_t encode_uint32_be(const void* context, const void* value, size_t size,
                                           uint8_t* data, size_t capacity, size_t* written) {
    uint32_t input;
    (void)context;
    if (size != sizeof(input)) return TLV_CODEC_ERR_INVALID_VALUE;
    if (data) {
        if (capacity < 4) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
        memcpy(&input, value, sizeof(input));
        tlv_write_u32_be(data, input);
    }
    *written = 4;
    return TLV_CODEC_OK;
}

const tlv_codec_t tlv_codec_uint32_be = {NULL, decode_uint32_be, encode_uint32_be};

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
