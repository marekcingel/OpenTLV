// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_CALLBACK_INTERNAL_H
#define OPENTLV_CALLBACK_INTERNAL_H

#include "tlv/error.h"

/* Callback control statuses are opt-in. Ordinary provider failures retain
 * their identity; an unknown discriminator is a provider contract defect. */
static inline tlv_result_t tlv_callback_result(tlv_result_t result, int allow_end) {
    switch (result) {
        case TLV_END: return allow_end ? result : TLV_ERR_CALLBACK;
        case TLV_OK:
        case TLV_ERR_BUFFER_TOO_SHORT:
        case TLV_ERR_INVALID_LENGTH:
        case TLV_ERR_NULL_ARG:
        case TLV_ERR_OUT_OF_MEMORY:
        case TLV_ERR_INVALID_TAG:
        case TLV_ERR_VISITOR:
        case TLV_ERR_LIMIT:
        case TLV_ERR_SCHEMA:
        case TLV_ERR_INVALID_ARG:
        case TLV_ERR_INVALID_TAG_SIZE:
        case TLV_ERR_SYNTAX:
        case TLV_ERR_TRUNCATED:
        case TLV_ERR_OVERFLOW:
        case TLV_ERR_INVALID_VALUE:
        case TLV_ERR_UNSUPPORTED:
        case TLV_ERR_INVALID_SCHEMA:
        case TLV_ERR_NATIVE_SIZE:
        case TLV_ERR_INVALID_STATE:
        case TLV_ERR_CALLBACK: return result;
        case TLV_NEED_MORE_DATA: return TLV_ERR_CALLBACK;
    }
    /* No default: -Wswitch must diagnose newly added result enumerators. */
    return TLV_ERR_CALLBACK;
}

#endif
