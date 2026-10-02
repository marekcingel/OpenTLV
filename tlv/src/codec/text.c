// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/codec/text.h"
#include <string.h>

static int valid_config(const tlv_text_codec_config_t* config) {
    return (config->alphabet == TLV_TEXT_ASCII_PRINTABLE ||
            config->alphabet == TLV_TEXT_ASCII_ALNUM) &&
           (config->zero_padding == 0 || config->zero_padding == 1);
}

static int valid_text(const tlv_text_codec_config_t* config, const uint8_t* data, size_t size) {
    size_t i;
    for (i = 0; i < size; ++i) {
        unsigned c = data[i];
        if (config->alphabet == TLV_TEXT_ASCII_PRINTABLE) {
            if (c < 0x20 || c > 0x7E) return 0;
        } else if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')))
            return 0;
    }
    return 1;
}

tlv_codec_result_t tlv_text_decode(const void* context, const uint8_t* data, size_t size,
                                   void* value, size_t capacity) {
    const tlv_text_codec_config_t* config = (const tlv_text_codec_config_t*)context;
    tlv_value_t text;
    if (!config || !value || (!data && size)) return TLV_CODEC_ERR_NULL_ARG;
    if (!valid_config(config) || (config->width && size != config->width))
        return TLV_CODEC_ERR_INVALID_VALUE;
    if (config->zero_padding)
        while (size && data[size - 1] == 0) --size;
    if (!valid_text(config, data, size)) return TLV_CODEC_ERR_INVALID_VALUE;
    if (capacity < sizeof(text)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    text.data = data;
    text.size = size;
    memcpy(value, &text, sizeof(text));
    return TLV_CODEC_OK;
}

tlv_codec_result_t tlv_text_encode(const void* context, const void* value, size_t size,
                                   uint8_t* data, size_t capacity, size_t* written) {
    const tlv_text_codec_config_t* config = (const tlv_text_codec_config_t*)context;
    tlv_value_t text;
    size_t bytes, length;
    if (!written) return TLV_CODEC_ERR_NULL_ARG;
    *written = 0;
    if (!config || !value || (!data && capacity)) return TLV_CODEC_ERR_NULL_ARG;
    if (!valid_config(config) || size != sizeof(text)) return TLV_CODEC_ERR_INVALID_VALUE;
    memcpy(&text, value, sizeof(text));
    if (!text.data && text.size) return TLV_CODEC_ERR_NULL_ARG;
    if (tlv_size_to_native(text.size, &length) != TLV_OK) return TLV_CODEC_ERR_INVALID_VALUE;
    bytes = length;
    if (config->zero_padding && bytes < config->width) bytes = config->width;
    if ((config->width && bytes != config->width) || !valid_text(config, text.data, length))
        return TLV_CODEC_ERR_INVALID_VALUE;
    if (data) {
        if (capacity < bytes) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
        if (length) memcpy(data, text.data, length);
        if (bytes > length) memset(data + length, 0, bytes - length);
    }
    *written = bytes;
    return TLV_CODEC_OK;
}
