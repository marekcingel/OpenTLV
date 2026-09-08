#include "tlv/codec/codec.h"

tlv_codec_result_t tlv_codec_decode(const tlv_codec_t* codec,
                                    const uint8_t* data, size_t size,
                                    void* value, size_t capacity) {
    if (!codec || !value || (!data && size)) return TLV_CODEC_ERR_NULL_ARG;
    if (!codec->decode) return TLV_CODEC_ERR_UNSUPPORTED;
    return codec->decode(codec->context, data, size, value, capacity);
}

tlv_codec_result_t tlv_codec_encode(const tlv_codec_t* codec,
                                    const void* value, size_t size,
                                    uint8_t* data, size_t capacity,
                                    size_t* written) {
    size_t count = 0;
    tlv_codec_result_t result;
    if (!written) return TLV_CODEC_ERR_NULL_ARG;
    *written = 0;
    if (!codec || !value || (!data && capacity)) return TLV_CODEC_ERR_NULL_ARG;
    if (!codec->encode) return TLV_CODEC_ERR_UNSUPPORTED;
    result = codec->encode(codec->context, value, size, data, capacity, &count);
    if (result != TLV_CODEC_OK) return result;
    if (data && count > capacity) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    *written = count;
    return TLV_CODEC_OK;
}

const char* tlv_codec_strerror(tlv_codec_result_t result) {
    switch (result) {
        case TLV_CODEC_OK: return "Success";
        case TLV_CODEC_ERR_NULL_ARG: return "Null codec argument";
        case TLV_CODEC_ERR_BUFFER_TOO_SHORT: return "Codec destination too short";
        case TLV_CODEC_ERR_INVALID_VALUE: return "Invalid codec value";
        case TLV_CODEC_ERR_UNSUPPORTED: return "Unsupported codec operation";
        case TLV_CODEC_ERR_INVALID_STRUCTURE: return "Invalid TLV structure";
        default: return "Unknown codec error";
    }
}
