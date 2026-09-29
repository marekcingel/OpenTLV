#include "tlv/builtins/bluetooth/uuid.h"
#include "tlv/endian.h"
#include "tlv/codec/values.h"
#include <string.h>

static const size_t width16 = 2;
static const size_t width32 = 4;
static const size_t width128 = 16;

static size_t object_size(size_t width) {
    return width == 2   ? sizeof(uint16_t)
           : width == 4 ? sizeof(uint32_t)
                        : sizeof(tlv_bluetooth_uuid128_t);
}

static tlv_codec_result_t decode_uuid(const void* context, const uint8_t* data, size_t size,
                                      void* value, size_t capacity) {
    const size_t width = *(const size_t*)context;
    if (size != width) return TLV_CODEC_ERR_INVALID_VALUE;
    if (capacity < object_size(width)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    if (width == 2 || width == 4) {
        return tlv_codec_decode(width == 2 ? &tlv_codec_uint16_le : &tlv_codec_uint32_le, data,
                                size, value, capacity);
    } else {
        tlv_bluetooth_uuid128_t result;
        size_t i;
        for (i = 0; i < 16; ++i) result.bytes[i] = data[15 - i];
        memcpy(value, &result, sizeof(result));
    }
    return TLV_CODEC_OK;
}

static tlv_codec_result_t encode_uuid(const void* context, const void* value, size_t size,
                                      uint8_t* data, size_t capacity, size_t* written) {
    const size_t width = *(const size_t*)context;
    if (size != object_size(width)) return TLV_CODEC_ERR_INVALID_VALUE;
    if (width == 2 || width == 4)
        return tlv_codec_encode(width == 2 ? &tlv_codec_uint16_le : &tlv_codec_uint32_le, value,
                                size, data, capacity, written);
    if (data) {
        if (capacity < width) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
        {
            tlv_bluetooth_uuid128_t input;
            size_t i;
            memcpy(&input, value, sizeof(input));
            for (i = 0; i < 16; ++i) data[i] = input.bytes[15 - i];
        }
    }
    *written = width;
    return TLV_CODEC_OK;
}

static tlv_codec_result_t validate_list(const tlv_bluetooth_uuid_list_t* list, size_t* size) {
    if (list->uuid_size != 2 && list->uuid_size != 4 && list->uuid_size != 16)
        return TLV_CODEC_ERR_INVALID_VALUE;
    if (!list->raw.data && list->raw.size) return TLV_CODEC_ERR_NULL_ARG;
    if (tlv_size_to_native(list->raw.size, size) != TLV_OK || *size % list->uuid_size)
        return TLV_CODEC_ERR_INVALID_VALUE;
    return TLV_CODEC_OK;
}

static tlv_codec_result_t decode_list(const void* context, const uint8_t* data, size_t size,
                                      void* value, size_t capacity) {
    const size_t width = *(const size_t*)context;
    tlv_bluetooth_uuid_list_t result;
    if (size % width) return TLV_CODEC_ERR_INVALID_VALUE;
    if (capacity < sizeof(result)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    result.raw.data = data;
    result.raw.size = size;
    result.uuid_size = width;
    memcpy(value, &result, sizeof(result));
    return TLV_CODEC_OK;
}

static tlv_codec_result_t encode_list(const void* context, const void* value, size_t size,
                                      uint8_t* data, size_t capacity, size_t* written) {
    tlv_bluetooth_uuid_list_t input;
    size_t length;
    tlv_codec_result_t rc;
    if (size != sizeof(input)) return TLV_CODEC_ERR_INVALID_VALUE;
    memcpy(&input, value, sizeof(input));
    if (input.uuid_size != *(const size_t*)context) return TLV_CODEC_ERR_INVALID_VALUE;
    rc = validate_list(&input, &length);
    if (rc != TLV_CODEC_OK) return rc;
    if (data) {
        if (capacity < length) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
        if (length) memcpy(data, input.raw.data, length);
    }
    *written = length;
    return TLV_CODEC_OK;
}

tlv_codec_result_t tlv_bluetooth_uuid_list_at(const tlv_bluetooth_uuid_list_t* list, size_t index,
                                              void* value, size_t capacity) {
    size_t size;
    tlv_codec_result_t rc;
    const tlv_codec_t* codec;
    if (!list || !value) return TLV_CODEC_ERR_NULL_ARG;
    rc = validate_list(list, &size);
    if (rc != TLV_CODEC_OK) return rc;
    if (index >= size / list->uuid_size) return TLV_CODEC_ERR_INVALID_VALUE;
    codec = list->uuid_size == 2   ? &tlv_bluetooth_codec_uuid16
            : list->uuid_size == 4 ? &tlv_bluetooth_codec_uuid32
                                   : &tlv_bluetooth_codec_uuid128;
    return tlv_codec_decode(codec, list->raw.data + index * list->uuid_size, list->uuid_size, value,
                            capacity);
}

const tlv_codec_t tlv_bluetooth_codec_uuid16 = {&width16, decode_uuid, encode_uuid};
const tlv_codec_t tlv_bluetooth_codec_uuid32 = {&width32, decode_uuid, encode_uuid};
const tlv_codec_t tlv_bluetooth_codec_uuid128 = {&width128, decode_uuid, encode_uuid};
const tlv_codec_t tlv_bluetooth_codec_uuid16_list = {&width16, decode_list, encode_list};
const tlv_codec_t tlv_bluetooth_codec_uuid32_list = {&width32, decode_list, encode_list};
const tlv_codec_t tlv_bluetooth_codec_uuid128_list = {&width128, decode_list, encode_list};
