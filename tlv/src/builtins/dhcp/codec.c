#include "tlv/builtins/dhcp/codec.h"

static tlv_codec_result_t decode_message_type(const void* context, const uint8_t* data, size_t size,
                                              void* value, size_t capacity) {
    (void)context;
    return tlv_codec_decode(&tlv_codec_uint8, data, size, value, capacity);
}

static tlv_codec_result_t encode_message_type(const void* context, const void* value, size_t size,
                                              uint8_t* data, size_t capacity, size_t* written) {
    (void)context;
    return tlv_codec_encode(&tlv_codec_uint8, value, size, data, capacity, written);
}

const tlv_codec_t tlv_dhcpv4_codec_message_type = {NULL, decode_message_type, encode_message_type};
