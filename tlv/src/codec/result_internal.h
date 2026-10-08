// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#ifndef OPENTLV_CODEC_RESULT_INTERNAL_H
#define OPENTLV_CODEC_RESULT_INTERNAL_H
#include "tlv/codec/codec.h"

/* Exhaustive over the separate Codec domain until its shared-result migration. */
static inline int tlv_codec_result_valid(tlv_codec_result_t result) {
    switch (result) {
        case TLV_CODEC_OK:
        case TLV_CODEC_ERR_NULL_ARG:
        case TLV_CODEC_ERR_BUFFER_TOO_SHORT:
        case TLV_CODEC_ERR_INVALID_VALUE:
        case TLV_CODEC_ERR_UNSUPPORTED:
        case TLV_CODEC_ERR_INVALID_STRUCTURE: return 1;
    }
    /* No default: new enumerators must be considered explicitly. */
    return 0;
}
#endif
