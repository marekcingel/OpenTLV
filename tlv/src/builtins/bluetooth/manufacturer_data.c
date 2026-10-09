// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/builtins/bluetooth/manufacturer_data.h"
#include "tlv/endian.h"
#include <string.h>

static tlv_result_t decode(const void* context, const uint8_t* data, size_t size, void* value,
                           size_t capacity, tlv_codec_diagnostic_t* diagnostic) {
    tlv_codec_diagnostic_init(diagnostic, TLV_CODEC_OP_DECODE);
    tlv_bluetooth_manufacturer_data_t result = {0};
    (void)context;
    if (size < 2) return tlv_codec_diagnostic_result(diagnostic, TLV_ERR_INVALID_VALUE);
    if (capacity < sizeof(result))
        return tlv_codec_diagnostic_result(diagnostic, TLV_ERR_BUFFER_TOO_SHORT);
    result.company_id = tlv_read_u16_le(data);
    result.payload.data = data + 2;
    result.payload.size = size - 2;
    result.raw.data = data;
    result.raw.size = size;
    memcpy(value, &result, sizeof(result));
    return tlv_codec_diagnostic_result(diagnostic, TLV_OK);
}

static tlv_result_t encode(const void* context, const void* value, size_t size, uint8_t* data,
                           size_t capacity, size_t* written, tlv_codec_diagnostic_t* diagnostic) {
    tlv_codec_diagnostic_init(diagnostic, data ? TLV_CODEC_OP_ENCODE : TLV_CODEC_OP_MEASURE);
    tlv_bluetooth_manufacturer_data_t input;
    size_t length;
    (void)context;
    if (size != sizeof(input))
        return tlv_codec_diagnostic_result(diagnostic, TLV_ERR_INVALID_VALUE);
    memcpy(&input, value, sizeof(input));
    if (!input.payload.data && input.payload.size)
        return tlv_codec_diagnostic_result(diagnostic, TLV_ERR_NULL_ARG);
    if (tlv_size_to_native(input.payload.size, &length) != TLV_OK || length > SIZE_MAX - 2)
        return tlv_codec_diagnostic_result(diagnostic, TLV_ERR_INVALID_VALUE);
    if (data) {
        if (capacity < 2 + length)
            return tlv_codec_diagnostic_result(diagnostic, TLV_ERR_BUFFER_TOO_SHORT);
        tlv_write_u16_le(data, input.company_id);
        if (length) memcpy(data + 2, input.payload.data, length);
    }
    *written = 2 + length;
    return tlv_codec_diagnostic_result(diagnostic, TLV_OK);
}

const tlv_codec_t tlv_bluetooth_codec_manufacturer_data = {NULL, decode, encode};
