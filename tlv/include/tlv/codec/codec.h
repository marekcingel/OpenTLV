// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_CODEC_H
#define OPENTLV_CODEC_H

#include "tlv/result.h"
#include "tlv/codec/diagnostic.h"
#include "tlv/export.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup codecs
 * @brief Value codec descriptors for converting raw TLV values to and from C representations.
 */

/** @addtogroup codecs
 * @{
 */

/**
 * @brief Borrowed codec descriptor with an optional immutable context.
 *
 * A descriptor neither allocates nor takes ownership of anything. Each codec
 * documents its C representation and required alignment; callers supply
 * correctly typed and aligned objects. Capacities and sizes are in bytes.
 * Callbacks must respect bounds and must not require heap allocation.
 *
 * Value conversion is independent of the enclosing element's tag. The caller
 * or a domain dictionary selects the codec before invoking it; a value codec
 * must not resolve that tag through a Definition registry or domain dictionary.
 * Structure codecs may interpret nested elements by composing Reader/Writer,
 * schema and value codecs; they still do not select themselves by an enclosing
 * tag.
 *
 * - **Decode** consumes the entire raw value and may return a representation
 *   that borrows the input bytes; that input must then outlive the
 *   representation.
 * - **Encode** with `data == NULL` and `capacity == 0` validates the value and
 *   reports its exact encoded size without writing. A normal success reports
 *   the bytes written.
 * - A callback may be `NULL` for an unsupported direction. Errors propagate
 *   unchanged.
 * - On error, destination contents are unspecified, and the tlv_codec_encode()
 *   wrapper reports `written == 0`.
 * - Input and output must not overlap unless the codec explicitly supports it.
 *
 * Failures use the shared tlv_result_t domain unchanged. Decode admits delegated
 * #TLV_NEED_MORE_DATA; encode and measure reject it. #TLV_END and
 * unknown results are callback violations. A successful encode count larger than
 * the supplied buffer is #TLV_ERR_CALLBACK. Optional diagnostics retain reported
 * results and any delegated cause; borrowed evidence must outlive the call.
 *
 * @see tlv_codec_decode, tlv_codec_encode
 */
typedef struct tlv_codec {
    /** Immutable context passed to both callbacks; may be `NULL`. */
    const void* context;
    /**
     * Decodes a raw value into a C representation; `NULL` if unsupported.
     *
     * `capacity` is the size of `value` in bytes.
     */
    tlv_result_t (*decode)(const void* context, const uint8_t* data, size_t size, void* value,
                           size_t capacity, tlv_codec_diagnostic_t* diagnostic);
    /**
     * Encodes a C representation into raw value bytes; `NULL` if unsupported.
     *
     * `size` is the size of `value` in bytes. `capacity` is the size of `data`.
     */
    tlv_result_t (*encode)(const void* context, const void* value, size_t size, uint8_t* data,
                           size_t capacity, size_t* written, tlv_codec_diagnostic_t* diagnostic);
} tlv_codec_t;

/**
 * @brief Decodes a raw value with a codec.
 *
 * `value` is required even for empty representations. The decoded
 * representation may borrow `data`, in which case `data` must outlive it.
 *
 * @param[in]  codec    Codec descriptor.
 * @param[in]  data     Raw value bytes. May be `NULL` only when `size` is zero.
 * @param[in]  size     Raw value size in bytes.
 * @param[out] value    Destination object, correctly typed and aligned.
 * @param[in]  capacity Size of `value` in bytes.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for missing required pointers.
 * @return #TLV_ERR_UNSUPPORTED if the codec has no decoder.
 * @return #TLV_ERR_BUFFER_TOO_SHORT or #TLV_ERR_INVALID_VALUE as
 *         reported by the codec.
 *
 * @warning On error the contents of `value` are unspecified.
 * @param[out] diagnostic Optional initialized failure output; NULL skips evidence collection.
 */
TLV_API tlv_result_t tlv_codec_decode(const tlv_codec_t* codec, const uint8_t* data, size_t size,
                                      void* value, size_t capacity,
                                      tlv_codec_diagnostic_t* diagnostic);

/**
 * @brief Encodes a C representation into raw value bytes with a codec.
 *
 * With `data == NULL` and `capacity == 0` the value is validated and the
 * exact encoded size is reported in `*written` without writing.
 *
 * @param[in]  codec    Codec descriptor.
 * @param[in]  value    Object to encode, correctly typed and aligned.
 * @param[in]  size     Size of `value` in bytes.
 * @param[out] data     Destination bytes. May be `NULL` only for a size query.
 * @param[in]  capacity Destination capacity in bytes.
 * @param[out] written  Receives the bytes written, or the required size for a
 *                      query. Required; must not alias input or destination.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for missing required pointers.
 * @return #TLV_ERR_UNSUPPORTED if the codec has no encoder.
 * @return #TLV_ERR_BUFFER_TOO_SHORT or #TLV_ERR_INVALID_VALUE as
 *         reported by the codec.
 *
 * @warning On error the destination contents are unspecified and `*written` is zero.
 * @param[out] diagnostic Optional initialized failure output; NULL skips evidence collection.
 */
TLV_API tlv_result_t tlv_codec_encode(const tlv_codec_t* codec, const void* value, size_t size,
                                      uint8_t* data, size_t capacity, size_t* written,
                                      tlv_codec_diagnostic_t* diagnostic);

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* OPENTLV_CODEC_H */
