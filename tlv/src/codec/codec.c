// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/codec/codec.h"
#include "result_internal.h"

tlv_result_t tlv_codec_decode(const tlv_codec_t* codec, const uint8_t* data, size_t size,
                              void* value, size_t capacity, tlv_codec_diagnostic_t* diagnostic) {
    tlv_result_t result;
    tlv_codec_diagnostic_init(diagnostic, TLV_CODEC_OP_DECODE);
    if (!codec || !value || (!data && size))
        return tlv_codec_diagnostic_result(diagnostic, TLV_ERR_NULL_ARG);
    if (!codec->decode) return tlv_codec_diagnostic_result(diagnostic, TLV_ERR_UNSUPPORTED);
    result = codec->decode(codec->context, data, size, value, capacity, diagnostic);
    return tlv_codec_callback_result(diagnostic, result, TLV_CODEC_OP_DECODE);
}

tlv_result_t tlv_codec_encode(const tlv_codec_t* codec, const void* value, size_t size,
                              uint8_t* data, size_t capacity, size_t* written,
                              tlv_codec_diagnostic_t* diagnostic) {
    size_t count = 0;
    tlv_result_t result;
    tlv_codec_operation_t operation = data ? TLV_CODEC_OP_ENCODE : TLV_CODEC_OP_MEASURE;
    tlv_codec_diagnostic_init(diagnostic, operation);
    if (!written) return tlv_codec_diagnostic_result(diagnostic, TLV_ERR_NULL_ARG);
    *written = 0;
    if (!codec || !value || (!data && capacity))
        return tlv_codec_diagnostic_result(diagnostic, TLV_ERR_NULL_ARG);
    if (!codec->encode) return tlv_codec_diagnostic_result(diagnostic, TLV_ERR_UNSUPPORTED);
    result = codec->encode(codec->context, value, size, data, capacity, &count, diagnostic);
    result = tlv_codec_callback_result(diagnostic, result, operation);
    if (result != TLV_OK) return result;
    if (data && count > capacity) {
        if (diagnostic) diagnostic->codec.violation = TLV_CODEC_VIOLATION_SIZE;
        return tlv_codec_diagnostic_result(diagnostic, TLV_ERR_CALLBACK);
    }
    *written = count;
    return TLV_OK;
}
