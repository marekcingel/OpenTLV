#include "tlv/builtins/bluetooth/manufacturer_data.h"
#include "tlv/endian.h"
#include <string.h>

static tlv_codec_result_t decode(const void* context, const uint8_t* data, size_t size, void* value,
                                 size_t capacity) {
    tlv_bluetooth_manufacturer_data_t result = {0};
    (void)context;
    if (size < 2) return TLV_CODEC_ERR_INVALID_VALUE;
    if (capacity < sizeof(result)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    result.company_id = tlv_read_u16_le(data);
    result.payload.data = data + 2;
    result.payload.size = size - 2;
    result.raw.data = data;
    result.raw.size = size;
    memcpy(value, &result, sizeof(result));
    return TLV_CODEC_OK;
}

static tlv_codec_result_t encode(const void* context, const void* value, size_t size, uint8_t* data,
                                 size_t capacity, size_t* written) {
    tlv_bluetooth_manufacturer_data_t input;
    size_t length;
    (void)context;
    if (size != sizeof(input)) return TLV_CODEC_ERR_INVALID_VALUE;
    memcpy(&input, value, sizeof(input));
    if (!input.payload.data && input.payload.size) return TLV_CODEC_ERR_NULL_ARG;
    if (tlv_size_to_native(input.payload.size, &length) != TLV_OK || length > SIZE_MAX - 2)
        return TLV_CODEC_ERR_INVALID_VALUE;
    if (data) {
        if (capacity < 2 + length) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
        tlv_write_u16_le(data, input.company_id);
        if (length) memcpy(data + 2, input.payload.data, length);
    }
    *written = 2 + length;
    return TLV_CODEC_OK;
}

const tlv_codec_t tlv_bluetooth_codec_manufacturer_data = {NULL, decode, encode};
