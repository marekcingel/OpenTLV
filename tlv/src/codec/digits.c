// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/codec/digits.h"

static unsigned nibble(const uint8_t* data, size_t index) {
    return (index % 2 ? data[index / 2] : data[index / 2] >> 4) & 15;
}

tlv_codec_result_t tlv_digits_decode(const void* context, const uint8_t* data, size_t size,
                                     void* value, size_t capacity) {
    const tlv_digits_codec_config_t* config = (const tlv_digits_codec_config_t*)context;
    size_t i, count = 0;
    int padding = 0;
    char* digits = (char*)value;
    if (!config || !value || (!data && size)) return TLV_CODEC_ERR_NULL_ARG;
    if ((config->width && size != config->width) || size > (SIZE_MAX - 1) / 2)
        return TLV_CODEC_ERR_INVALID_VALUE;
    for (i = 0; i < size * 2; ++i) {
        unsigned digit = nibble(data, i);
        if (digit == 15)
            padding = 1;
        else {
            if (digit > 9 || padding) return TLV_CODEC_ERR_INVALID_VALUE;
            ++count;
        }
    }
    if (capacity <= count) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    for (i = 0; i < count; ++i) digits[i] = (char)('0' + nibble(data, i));
    digits[count] = '\0';
    return TLV_CODEC_OK;
}

tlv_codec_result_t tlv_digits_encode(const void* context, const void* value, size_t size,
                                     uint8_t* data, size_t capacity, size_t* written) {
    const tlv_digits_codec_config_t* config = (const tlv_digits_codec_config_t*)context;
    const char* digits = (const char*)value;
    size_t i, bytes = size / 2 + size % 2;
    if (!written) return TLV_CODEC_ERR_NULL_ARG;
    *written = 0;
    if (!config || !value || (!data && capacity)) return TLV_CODEC_ERR_NULL_ARG;
    if (config->width) {
        if (bytes > config->width) return TLV_CODEC_ERR_INVALID_VALUE;
        bytes = config->width;
    }
    if (bytes > (SIZE_MAX - 1) / 2) return TLV_CODEC_ERR_INVALID_VALUE;
    for (i = 0; i < size; ++i)
        if (digits[i] < '0' || digits[i] > '9') return TLV_CODEC_ERR_INVALID_VALUE;
    if (data) {
        if (capacity < bytes) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
        for (i = 0; i < bytes; ++i) {
            unsigned high = i * 2 < size ? (unsigned)(digits[i * 2] - '0') : 15;
            unsigned low = i * 2 + 1 < size ? (unsigned)(digits[i * 2 + 1] - '0') : 15;
            data[i] = (uint8_t)((high << 4) | low);
        }
    }
    *written = bytes;
    return TLV_CODEC_OK;
}
