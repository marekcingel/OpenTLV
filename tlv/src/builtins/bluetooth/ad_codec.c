#include "tlv/builtins/bluetooth/ad_codec.h"
#include "../../utf8_internal.h"
#include <string.h>
#include "tlv/codec/values.h"

static tlv_codec_result_t validate_flags(const uint8_t* data, size_t size) {
    if (size && data[size - 1] == 0) return TLV_CODEC_ERR_INVALID_VALUE;
    return TLV_CODEC_OK;
}

/* Local names are complete UTF-8 byte sequences, even for the shortened AD
 * type: a shortened name must end at a character boundary. */
static tlv_codec_result_t validate_name(const uint8_t* data, size_t size) {
    return tlv_utf8_validate(data, size) == TLV_OK ? TLV_CODEC_OK : TLV_CODEC_ERR_INVALID_VALUE;
}

typedef tlv_codec_result_t (*ad_validator_t)(const uint8_t*, size_t);

static tlv_codec_result_t decode_span(const uint8_t* data, size_t size, void* value,
                                      size_t capacity, ad_validator_t validate) {
    tlv_codec_result_t rc = validate(data, size);
    if (rc != TLV_CODEC_OK) return rc;
    return tlv_codec_decode(&tlv_codec_bytes, data, size, value, capacity);
}

static tlv_codec_result_t encode_span(const void* value, size_t size, uint8_t* data,
                                      size_t capacity, size_t* written, ad_validator_t validate) {
    tlv_value_t input;
    size_t length;
    tlv_codec_result_t rc;
    if (size != sizeof(input)) return TLV_CODEC_ERR_INVALID_VALUE;
    memcpy(&input, value, sizeof(input));
    if (!input.data && input.size) return TLV_CODEC_ERR_NULL_ARG;
    if (tlv_size_to_native(input.size, &length) != TLV_OK) return TLV_CODEC_ERR_INVALID_VALUE;
    rc = validate(input.data, length);
    if (rc != TLV_CODEC_OK) return rc;
    return tlv_codec_encode(&tlv_codec_bytes, value, size, data, capacity, written);
}

static tlv_codec_result_t decode_flags(const void* context, const uint8_t* data, size_t size,
                                       void* value, size_t capacity) {
    (void)context;
    return decode_span(data, size, value, capacity, validate_flags);
}

static tlv_codec_result_t encode_flags(const void* context, const void* value, size_t size,
                                       uint8_t* data, size_t capacity, size_t* written) {
    (void)context;
    return encode_span(value, size, data, capacity, written, validate_flags);
}

bool tlv_bluetooth_ad_flags_test(const tlv_value_t* flags, uint8_t mask) {
    return flags && flags->size && flags->data && (flags->data[0] & mask) != 0;
}

static tlv_codec_result_t decode_name(const void* context, const uint8_t* data, size_t size,
                                      void* value, size_t capacity) {
    (void)context;
    return decode_span(data, size, value, capacity, validate_name);
}

static tlv_codec_result_t encode_name(const void* context, const void* value, size_t size,
                                      uint8_t* data, size_t capacity, size_t* written) {
    (void)context;
    return encode_span(value, size, data, capacity, written, validate_name);
}

static tlv_codec_result_t decode_tx_power(const void* context, const uint8_t* data, size_t size,
                                          void* value, size_t capacity) {
    int8_t result;
    (void)context;
    if (size != 1 || data[0] == 0x80) return TLV_CODEC_ERR_INVALID_VALUE;
    if (capacity < sizeof(result)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    /* Subtract in int before narrowing: no out-of-range unsigned-to-signed cast. */
    result = (int8_t)(data[0] < 0x80 ? (int)data[0] : (int)data[0] - 256);
    memcpy(value, &result, sizeof(result));
    return TLV_CODEC_OK;
}

static tlv_codec_result_t encode_tx_power(const void* context, const void* value, size_t size,
                                          uint8_t* data, size_t capacity, size_t* written) {
    int8_t input;
    (void)context;
    if (size != sizeof(input)) return TLV_CODEC_ERR_INVALID_VALUE;
    memcpy(&input, value, sizeof(input));
    if (input == INT8_MIN) return TLV_CODEC_ERR_INVALID_VALUE;
    if (data) {
        if (capacity < 1) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
        data[0] = (uint8_t)input;
    }
    *written = 1;
    return TLV_CODEC_OK;
}

const tlv_codec_t tlv_bluetooth_ad_codec_flags = {NULL, decode_flags, encode_flags};
const tlv_codec_t tlv_bluetooth_ad_codec_local_name = {NULL, decode_name, encode_name};
const tlv_codec_t tlv_bluetooth_ad_codec_tx_power = {NULL, decode_tx_power, encode_tx_power};
