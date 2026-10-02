// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "utf8_internal.h"

void tlv_utf8_stream_init(tlv_utf8_stream_t* state) {
    state->pending_len = 0;
    state->pending_need = 0;
}

/* Validates one completed code point's leading byte range/overlong/surrogate
 * rules from its collected bytes (state->pending[0..pending_need-1]). */
static tlv_result_t utf8_stream_finish_codepoint(const tlv_utf8_stream_t* state) {
    uint8_t b0 = state->pending[0];
    uint32_t cp, min_cp;
    size_t k;
    if ((b0 & 0xE0) == 0xC0) {
        cp = (uint32_t)(b0 & 0x1F);
        min_cp = 0x80;
    } else if ((b0 & 0xF0) == 0xE0) {
        cp = (uint32_t)(b0 & 0x0F);
        min_cp = 0x800;
    } else {
        cp = (uint32_t)(b0 & 0x07);
        min_cp = 0x10000;
    }
    for (k = 1; k < state->pending_need; ++k) cp = (cp << 6) | (uint32_t)(state->pending[k] & 0x3F);
    if (cp < min_cp || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF))
        return TLV_ERR_INVALID_VALUE;
    return TLV_OK;
}

tlv_result_t tlv_utf8_stream_update(tlv_utf8_stream_t* state, const uint8_t* value, size_t length) {
    size_t i = 0;
    while (i < length) {
        if (state->pending_need == 0) {
            uint8_t b0 = value[i];
            size_t extra;
            if (b0 < 0x80) {
                ++i;
                continue;
            }
            if ((b0 & 0xE0) == 0xC0)
                extra = 1;
            else if ((b0 & 0xF0) == 0xE0)
                extra = 2;
            else if ((b0 & 0xF8) == 0xF0)
                extra = 3;
            else
                return TLV_ERR_INVALID_VALUE;
            state->pending[0] = b0;
            state->pending_len = 1;
            state->pending_need = 1 + extra;
            ++i;
        } else {
            while (state->pending_len < state->pending_need && i < length) {
                uint8_t b = value[i];
                if ((b & 0xC0) != 0x80) return TLV_ERR_INVALID_VALUE;
                state->pending[state->pending_len++] = b;
                ++i;
            }
            if (state->pending_len == state->pending_need) {
                tlv_result_t rc = utf8_stream_finish_codepoint(state);
                if (rc != TLV_OK) return rc;
                state->pending_len = 0;
                state->pending_need = 0;
            }
        }
    }
    return TLV_OK;
}

tlv_result_t tlv_utf8_stream_finish(const tlv_utf8_stream_t* state) {
    return state->pending_need == 0 ? TLV_OK : TLV_ERR_INVALID_VALUE;
}

/* Rejects overlong encodings, surrogate code points, out-of-range code
 * points, and truncated or malformed continuation bytes. */
tlv_result_t tlv_utf8_validate(const uint8_t* value, size_t length) {
    tlv_utf8_stream_t state;
    tlv_result_t rc;
    tlv_utf8_stream_init(&state);
    rc = tlv_utf8_stream_update(&state, value, length);
    if (rc != TLV_OK) return rc;
    return tlv_utf8_stream_finish(&state);
}
