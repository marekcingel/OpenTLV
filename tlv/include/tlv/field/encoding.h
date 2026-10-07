// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_FIELD_ENCODING_H
#define OPENTLV_FIELD_ENCODING_H

#include "tlv/tag.h"
#include "tlv/size.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup field_encoding
 * @brief Callback contracts for encoding and decoding individual wire fields.
 *
 * Callbacks describe one identifier or length field, without element placement,
 * framing or protocol policy. Context is borrowed and immutable; callbacks do
 * not allocate. Value interpretation belongs to the separate Codec API.
 *
 * Validation order is shared with the standalone Field Encoding primitives:
 * required NULL arguments (#TLV_ERR_NULL_ARG), encoding configuration
 * (#TLV_ERR_INVALID_ARG or #TLV_ERR_INVALID_BYTE_ORDER), field-specific
 * constraints, then available input/output capacity. Decoders inspect wire
 * constraints as the necessary prefix becomes available. Context follows the
 * enclosing Format's borrowing preconditions; stateless callbacks may ignore it.
 * Argument/configuration errors leave all outputs unchanged. Incomplete input
 * reports the available field prefix in consumed while preserving the decoded
 * identifier/count. Writing and sizing validate the same real configuration.
 * Failed writes preserve written and destination bytes. These contracts do not
 * imply overlap support; that remains specific to each field encoding.
 */

/** @addtogroup field_encoding
 * @{
 */

/**
 * @brief Decode identifier bytes and their consumed extent.
 *
 * @param[in]  context  Borrowed immutable encoding configuration.
 * @param[in]  data     Identifier bytes; NULL only with zero size.
 * @param[in]  size     Available bytes.
 * @param[out] tag      Borrowed identifier on success.
 * @param[out] consumed Encoded width on success; available prefix on incomplete input.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for a missing required pointer.
 * @return #TLV_ERR_INVALID_ARG or #TLV_ERR_INVALID_BYTE_ORDER for invalid configuration.
 * @return An identifier or buffer error reported by the decoder.
 */
typedef tlv_result_t (*tlv_read_tag_fn)(const void* context, const uint8_t* data, size_t size,
                                        tlv_tag_t* tag, size_t* consumed);

/**
 * @brief Decode a wire count without narrowing to native size.
 *
 * @param[in]  context  Borrowed immutable encoding configuration.
 * @param[in]  data     Count bytes; NULL only with zero size.
 * @param[in]  size     Available bytes.
 * @param[out] length   Logical wire count on success, before composition applies count scope.
 * @param[out] consumed Encoded width on success; available prefix on incomplete input.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for a missing required pointer.
 * @return #TLV_ERR_INVALID_ARG or #TLV_ERR_INVALID_BYTE_ORDER for invalid configuration.
 * @return A length or buffer error reported by the decoder.
 */
typedef tlv_result_t (*tlv_read_length_fn)(const void* context, const uint8_t* data, size_t size,
                                           tlv_size_t* length, size_t* consumed);

/**
 * @brief Encode an identifier, or query its width with NULL output.
 *
 * @param[in]  context  Borrowed immutable encoding configuration.
 * @param[out] data     Destination; NULL with zero capacity for sizing.
 * @param[in]  capacity Available native capacity; zero for sizing.
 * @param[in]  tag      Identifier to validate and encode.
 * @param[out] written  Exact encoded width on success, identical for sizing and writing.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for a missing required pointer.
 * @return #TLV_ERR_INVALID_ARG or #TLV_ERR_INVALID_BYTE_ORDER for invalid configuration.
 * @return An identifier or buffer error reported by the encoder.
 *
 * @note Validation follows the shared Field Encoding order; failed writes preserve outputs.
 */
typedef tlv_result_t (*tlv_write_tag_fn)(const void* context, uint8_t* data, size_t capacity,
                                         const tlv_tag_t* tag, size_t* written);

/**
 * @brief Encode a logical count into a length field.
 *
 * @param[in]  context  Borrowed immutable encoding configuration.
 * @param[out] data     Destination; NULL with zero capacity for sizing.
 * @param[in]  capacity Available native capacity.
 * @param[in]  length   Wire count after composition applies count scope.
 * @param[out] written  Exact encoded width on success.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for a missing required pointer.
 * @return #TLV_ERR_INVALID_ARG or #TLV_ERR_INVALID_BYTE_ORDER for invalid configuration.
 * @return A length or buffer error reported by the encoder.
 *
 * @note Validation follows the shared Field Encoding order; failed writes preserve outputs.
 */
typedef tlv_result_t (*tlv_write_length_fn)(const void* context, uint8_t* data, size_t capacity,
                                            tlv_size_t length, size_t* written);

/**
 * @brief Validate a logical count and query its encoded field width.
 *
 * @param[in]  context Borrowed immutable encoding configuration.
 * @param[in]  length  Wire count after composition applies count scope.
 * @param[out] size    Exact native width of the encoded field on success.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for a missing required pointer.
 * @return #TLV_ERR_INVALID_ARG or #TLV_ERR_INVALID_BYTE_ORDER for invalid configuration.
 * @return A length error reported by the encoder.
 *
 * @note No buffer is accessed. Validate required pointers, configuration and
 * count representability in that order; leave size unchanged on failure.
 */
typedef tlv_result_t (*tlv_length_size_fn)(const void* context, tlv_size_t length, size_t* size);

/** @} */

#ifdef __cplusplus
}
#endif
#endif
