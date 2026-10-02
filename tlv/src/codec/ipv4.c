// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/codec/ipv4.h"
#include "tlv/codec/values.h"
#include <string.h>

static tlv_codec_result_t decode_ipv4(const void* context, const uint8_t* data, size_t size,
                                      void* value, size_t capacity) {
    tlv_ipv4_t result;
    (void)context;
    if (size != 4) return TLV_CODEC_ERR_INVALID_VALUE;
    if (capacity < sizeof(result)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    memcpy(result.bytes, data, 4);
    memcpy(value, &result, sizeof(result));
    return TLV_CODEC_OK;
}

static tlv_codec_result_t encode_ipv4(const void* context, const void* value, size_t size,
                                      uint8_t* data, size_t capacity, size_t* written) {
    tlv_ipv4_t input;
    (void)context;
    if (size != sizeof(input)) return TLV_CODEC_ERR_INVALID_VALUE;
    if (data) {
        if (capacity < 4) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
        memcpy(&input, value, sizeof(input));
        memcpy(data, input.bytes, 4);
    }
    *written = 4;
    return TLV_CODEC_OK;
}

const tlv_codec_t tlv_codec_ipv4 = {NULL, decode_ipv4, encode_ipv4};

static tlv_codec_result_t validate_list(tlv_value_t value, size_t* length) {
    if (!value.data && value.size) return TLV_CODEC_ERR_NULL_ARG;
    if (tlv_size_to_native(value.size, length) != TLV_OK || *length % 4)
        return TLV_CODEC_ERR_INVALID_VALUE;
    return TLV_CODEC_OK;
}

static tlv_codec_result_t decode_ipv4_list(const void* context, const uint8_t* data, size_t size,
                                           void* value, size_t capacity) {
    tlv_ipv4_list_t result;
    (void)context;
    if (size % 4) return TLV_CODEC_ERR_INVALID_VALUE;
    if (capacity < sizeof(result)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    result.raw.data = data;
    result.raw.size = size;
    memcpy(value, &result, sizeof(result));
    return TLV_CODEC_OK;
}

static tlv_codec_result_t encode_ipv4_list(const void* context, const void* value, size_t size,
                                           uint8_t* data, size_t capacity, size_t* written) {
    tlv_ipv4_list_t input;
    size_t length;
    tlv_codec_result_t rc;
    (void)context;
    if (size != sizeof(input)) return TLV_CODEC_ERR_INVALID_VALUE;
    memcpy(&input, value, sizeof(input));
    rc = validate_list(input.raw, &length);
    if (rc != TLV_CODEC_OK) return rc;
    return tlv_codec_encode(&tlv_codec_bytes, &input.raw, sizeof(input.raw), data, capacity,
                            written);
}

tlv_codec_result_t tlv_ipv4_list_at(const tlv_ipv4_list_t* list, size_t index, tlv_ipv4_t* value) {
    size_t length;
    tlv_codec_result_t rc;
    if (!list || !value) return TLV_CODEC_ERR_NULL_ARG;
    rc = validate_list(list->raw, &length);
    if (rc != TLV_CODEC_OK) return rc;
    if (index >= length / 4) return TLV_CODEC_ERR_INVALID_VALUE;
    memcpy(value->bytes, list->raw.data + index * 4, 4);
    return TLV_CODEC_OK;
}

const tlv_codec_t tlv_codec_ipv4_list = {NULL, decode_ipv4_list, encode_ipv4_list};
