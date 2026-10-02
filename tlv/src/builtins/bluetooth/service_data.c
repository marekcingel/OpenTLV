// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/builtins/bluetooth/service_data.h"
#include <string.h>

/* Validate all lengths before writing the UUID or touching payload storage. */
static tlv_codec_result_t payload_size(tlv_value_t payload, size_t width, size_t* length) {
    if (!payload.data && payload.size) return TLV_CODEC_ERR_NULL_ARG;
    if (tlv_size_to_native(payload.size, length) != TLV_OK || *length > SIZE_MAX - width)
        return TLV_CODEC_ERR_INVALID_VALUE;
    return TLV_CODEC_OK;
}

static tlv_codec_result_t decode16(const void* context, const uint8_t* data, size_t size,
                                   void* value, size_t capacity) {
    tlv_bluetooth_service_data16_t result = {0};
    tlv_codec_result_t rc;
    (void)context;
    if (size < 2) return TLV_CODEC_ERR_INVALID_VALUE;
    if (capacity < sizeof(result)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    rc = tlv_codec_decode(&tlv_bluetooth_codec_uuid16, data, 2, &result.uuid, sizeof(result.uuid));
    if (rc != TLV_CODEC_OK) return rc;
    result.payload.data = data + 2;
    result.payload.size = size - 2;
    result.raw.data = data;
    result.raw.size = size;
    memcpy(value, &result, sizeof(result));
    return TLV_CODEC_OK;
}

static tlv_codec_result_t encode16(const void* context, const void* value, size_t size,
                                   uint8_t* data, size_t capacity, size_t* written) {
    tlv_bluetooth_service_data16_t input;
    size_t length, uuid_written;
    tlv_codec_result_t rc;
    (void)context;
    if (size != sizeof(input)) return TLV_CODEC_ERR_INVALID_VALUE;
    memcpy(&input, value, sizeof(input));
    rc = payload_size(input.payload, 2, &length);
    if (rc != TLV_CODEC_OK) return rc;
    if (data) {
        if (capacity < 2 + length) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
        rc = tlv_codec_encode(&tlv_bluetooth_codec_uuid16, &input.uuid, sizeof(input.uuid), data, 2,
                              &uuid_written);
        if (rc != TLV_CODEC_OK) return rc;
        if (length) memcpy(data + 2, input.payload.data, length);
    }
    *written = 2 + length;
    return TLV_CODEC_OK;
}

const tlv_codec_t tlv_bluetooth_codec_service_data16 = {NULL, decode16, encode16};

static tlv_codec_result_t decode32(const void* context, const uint8_t* data, size_t size,
                                   void* value, size_t capacity) {
    tlv_bluetooth_service_data32_t result = {0};
    tlv_codec_result_t rc;
    (void)context;
    if (size < 4) return TLV_CODEC_ERR_INVALID_VALUE;
    if (capacity < sizeof(result)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    rc = tlv_codec_decode(&tlv_bluetooth_codec_uuid32, data, 4, &result.uuid, sizeof(result.uuid));
    if (rc != TLV_CODEC_OK) return rc;
    result.payload.data = data + 4;
    result.payload.size = size - 4;
    result.raw.data = data;
    result.raw.size = size;
    memcpy(value, &result, sizeof(result));
    return TLV_CODEC_OK;
}

static tlv_codec_result_t encode32(const void* context, const void* value, size_t size,
                                   uint8_t* data, size_t capacity, size_t* written) {
    tlv_bluetooth_service_data32_t input;
    size_t length, uuid_written;
    tlv_codec_result_t rc;
    (void)context;
    if (size != sizeof(input)) return TLV_CODEC_ERR_INVALID_VALUE;
    memcpy(&input, value, sizeof(input));
    rc = payload_size(input.payload, 4, &length);
    if (rc != TLV_CODEC_OK) return rc;
    if (data) {
        if (capacity < 4 + length) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
        rc = tlv_codec_encode(&tlv_bluetooth_codec_uuid32, &input.uuid, sizeof(input.uuid), data, 4,
                              &uuid_written);
        if (rc != TLV_CODEC_OK) return rc;
        if (length) memcpy(data + 4, input.payload.data, length);
    }
    *written = 4 + length;
    return TLV_CODEC_OK;
}

const tlv_codec_t tlv_bluetooth_codec_service_data32 = {NULL, decode32, encode32};

static tlv_codec_result_t decode128(const void* context, const uint8_t* data, size_t size,
                                    void* value, size_t capacity) {
    tlv_bluetooth_service_data128_t result = {0};
    tlv_codec_result_t rc;
    (void)context;
    if (size < 16) return TLV_CODEC_ERR_INVALID_VALUE;
    if (capacity < sizeof(result)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    rc =
        tlv_codec_decode(&tlv_bluetooth_codec_uuid128, data, 16, &result.uuid, sizeof(result.uuid));
    if (rc != TLV_CODEC_OK) return rc;
    result.payload.data = data + 16;
    result.payload.size = size - 16;
    result.raw.data = data;
    result.raw.size = size;
    memcpy(value, &result, sizeof(result));
    return TLV_CODEC_OK;
}

static tlv_codec_result_t encode128(const void* context, const void* value, size_t size,
                                    uint8_t* data, size_t capacity, size_t* written) {
    tlv_bluetooth_service_data128_t input;
    size_t length, uuid_written;
    tlv_codec_result_t rc;
    (void)context;
    if (size != sizeof(input)) return TLV_CODEC_ERR_INVALID_VALUE;
    memcpy(&input, value, sizeof(input));
    rc = payload_size(input.payload, 16, &length);
    if (rc != TLV_CODEC_OK) return rc;
    if (data) {
        if (capacity < 16 + length) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
        rc = tlv_codec_encode(&tlv_bluetooth_codec_uuid128, &input.uuid, sizeof(input.uuid), data,
                              16, &uuid_written);
        if (rc != TLV_CODEC_OK) return rc;
        if (length) memcpy(data + 16, input.payload.data, length);
    }
    *written = 16 + length;
    return TLV_CODEC_OK;
}

const tlv_codec_t tlv_bluetooth_codec_service_data128 = {NULL, decode128, encode128};
