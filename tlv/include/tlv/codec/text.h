// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_CODEC_TEXT_H
#define OPENTLV_CODEC_TEXT_H

#include "tlv/codec/codec.h"
#include "tlv/value.h"

/** @file
 * @ingroup codecs
 * @brief Explicit ASCII text conversion with optional trailing zero padding.
 */
#ifdef __cplusplus
extern "C" {
#endif

/** @brief Allowed logical text characters; protocol labels do not select these automatically. */
typedef enum tlv_text_alphabet {
    /** Printable ASCII, including space (0x20..0x7E). */
    TLV_TEXT_ASCII_PRINTABLE,
    /** ASCII A..Z, a..z and 0..9 only; excludes spaces. */
    TLV_TEXT_ASCII_ALNUM
} tlv_text_alphabet_t;

/** @brief Immutable borrowed text-codec configuration, independent of tags.
 * Width zero selects variable-width text. Nonzero width selects a fixed-width
 * representation. With padding enabled, decode strips trailing zero bytes and
 * encode pads to that width; otherwise text must occupy the entire width.
 * Embedded zeros are rejected. Field-length limits belong to Schema.
 * Configuration must outlive its codec.
 */
typedef struct tlv_text_codec_config {
    /** Explicit character repertoire. */
    tlv_text_alphabet_t alphabet;
    /** Fixed wire width, or zero for variable-width text. */
    size_t width;
    /** Zero disables padding; one enables trailing zero padding. */
    int zero_padding;
} tlv_text_codec_config_t;

/** @brief Validates text and returns a borrowed #tlv_value_t of unpadded characters.
 * @param[in] context Required immutable #tlv_text_codec_config_t.
 * @param[in] data Value bytes, NULL only with zero size; must outlive the returned view.
 * @param[in] size Wire byte count.
 * @param[out] value Required tlv_value_t destination, disjoint from input/configuration.
 * @param[in] capacity Destination size, at least sizeof(tlv_value_t).
 * @return #TLV_OK, #TLV_ERR_NULL_ARG, #TLV_ERR_INVALID_VALUE
 *         for invalid length/text, #TLV_ERR_INVALID_ARG for invalid configuration, or
 * #TLV_ERR_BUFFER_TOO_SHORT.
 * @note No allocation or NUL terminator is added. Destination is unchanged on failure.
 * @param[out] diagnostic Optional initialized failure output; NULL skips evidence collection.
 */
TLV_API tlv_result_t tlv_text_decode(const void* context, const uint8_t* data, size_t size,
                                     void* value, size_t capacity,
                                     tlv_codec_diagnostic_t* diagnostic);

/** @brief Encodes a tlv_value_t character span, optionally adding trailing zero bytes.
 * @param[in] context Required immutable #tlv_text_codec_config_t.
 * @param[in] value Required tlv_value_t; its data may be NULL only for an empty span.
 * @param[in] size Exactly sizeof(tlv_value_t).
 * @param[out] data Destination, or NULL with zero capacity for a validated size query.
 * @param[in] capacity Destination byte capacity.
 * @param[out] written Required encoded byte count, zero on failure.
 * @return #TLV_OK, #TLV_ERR_NULL_ARG, #TLV_ERR_INVALID_VALUE
 *         for invalid length/text, #TLV_ERR_INVALID_ARG for invalid configuration, or
 * #TLV_ERR_BUFFER_TOO_SHORT.
 * @note No allocation occurs; output is unchanged on failure. All input storage,
 *       output, configuration and written must be disjoint.
 * @param[out] diagnostic Optional initialized failure output; NULL skips evidence collection.
 */
TLV_API tlv_result_t tlv_text_encode(const void* context, const void* value, size_t size,
                                     uint8_t* data, size_t capacity, size_t* written,
                                     tlv_codec_diagnostic_t* diagnostic);

/** @brief Creates a descriptor borrowing a text configuration.
 * @param[in] config Borrowed configuration, validated when invoked.
 * @return Descriptor; NULL configuration fails on invocation.
 */
static inline tlv_codec_t tlv_text_codec(const tlv_text_codec_config_t* config) {
    tlv_codec_t result = {config, tlv_text_decode, tlv_text_encode};
    return result;
}

#ifdef __cplusplus
}
#endif
#endif
