// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_UTF8_INTERNAL_H
#define OPENTLV_UTF8_INTERNAL_H

#include "tlv/error.h"
#include <stddef.h>
#include <stdint.h>

/* Shared, protocol-independent UTF-8 validation. No allocation or recursion.
 * Input may be NULL only with zero length. Rejects malformed/overlong UTF-8,
 * surrogates and code points above U+10FFFF, accepting embedded U+0000.
 * Returns TLV_OK or TLV_ERR_INVALID_VALUE. */
tlv_result_t tlv_utf8_validate(const uint8_t* value, size_t length);

/* Streaming validation for byte spans whose boundaries may split a code
 * point (for example CER segments). Initialize before the first update and
 * finish after the final update. After any error, discard the state.
 * finish() rejects incomplete final code points. Fixed O(1) storage. */
typedef struct tlv_utf8_stream {
    uint8_t pending[4];
    size_t pending_len;  /* bytes collected for the in-flight code point */
    size_t pending_need; /* total expected bytes, 0 when between code points */
} tlv_utf8_stream_t;

void tlv_utf8_stream_init(tlv_utf8_stream_t* state);
tlv_result_t tlv_utf8_stream_update(tlv_utf8_stream_t* state, const uint8_t* value, size_t length);
tlv_result_t tlv_utf8_stream_finish(const tlv_utf8_stream_t* state);

#endif /* OPENTLV_UTF8_INTERNAL_H */
