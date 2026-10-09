// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#ifndef OPENTLV_CODEC_RESULT_INTERNAL_H
#define OPENTLV_CODEC_RESULT_INTERNAL_H
#include "tlv/codec/diagnostic.h"
#include "../callback_internal.h"

/* Decode may preserve delegated resumable input. END never produces a Value. */
static inline tlv_result_t tlv_codec_result(tlv_result_t result, tlv_codec_operation_t operation) {
    if (result == TLV_NEED_MORE_DATA && operation == TLV_CODEC_OP_DECODE) return result;
    return tlv_callback_result(result, 0);
}
static inline tlv_result_t tlv_codec_callback_result(tlv_codec_diagnostic_t* d,
                                                     tlv_result_t reported,
                                                     tlv_codec_operation_t operation) {
    tlv_result_t result = tlv_codec_result(reported, operation);
    if (d) {
        if (d->codec.violation == TLV_CODEC_VIOLATION_NONE) d->codec.reported = reported;
        d->codec.operation = operation;
        if (result != reported) d->codec.violation = TLV_CODEC_VIOLATION_RESULT;
    }
    return tlv_codec_diagnostic_result(d, result);
}
#endif
