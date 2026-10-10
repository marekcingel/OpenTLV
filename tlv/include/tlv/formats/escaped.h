// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_FORMATS_ESCAPED_H
#define OPENTLV_FORMATS_ESCAPED_H

#include "tlv/formats/compose.h"
#include "tlv/field/escaped.h"

/** @file
 * @ingroup formats
 * @brief Fixed identifiers with short or escape-prefixed unsigned lengths.
 *
 * Configurations are immutable and borrowed. All processing is allocation-free
 * and independent of protocol semantics.
 */

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup formats
 * @{
 */

/** @brief Fixed identifiers composed with escape-prefixed lengths.
 *
 * Optional tag-only identifiers require TLV/VALUE framing and empty Values.
 * They imply neither skipping nor termination. Configuration, table and tag
 * bytes are borrowed and must outlive the descriptor. All Values are opaque.
 */
typedef struct tlv_escaped_format {
    tlv_fixed_identifier_t identifier; /**< Nonzero fixed identifier width. */
    tlv_escaped_length_t length;       /**< Count encoding and accepted range. */
    tlv_element_order_t element_order; /**< TLV or LTV ordering. */
    tlv_length_scope_t length_scope;   /**< Value or identifier-and-value count. */
    const tlv_tag_t* tag_only;         /**< Borrowed table; NULL only if count is zero. */
    size_t count;                      /**< Table size; tags have identifier.size bytes. */
} tlv_escaped_format_t;

/** @brief Decode escape-length framing.
 * @copydetails tlv_decode_fn
 * @note context points to a valid immutable #tlv_escaped_format_t.
 */
TLV_API tlv_result_t tlv_escaped_decode(const void* context, const uint8_t* data, size_t size,
                                        tlv_decoded_t* result, tlv_format_error_t* error);
/** @brief Measure escape-length framing.
 * @copydetails tlv_measure_fn
 * @note context points to a valid immutable #tlv_escaped_format_t.
 */
TLV_API tlv_result_t tlv_escaped_measure(const void* context, const tlv_element_t* element,
                                         tlv_encoding_t* encoding, tlv_format_error_t* error);
/** @brief Encode escape-length framing.
 * @copydetails tlv_encode_fn
 * @note context points to a valid immutable #tlv_escaped_format_t.
 */
TLV_API tlv_result_t tlv_escaped_encode(const void* context, const tlv_element_t* element,
                                        uint8_t* data, size_t capacity, size_t* written,
                                        tlv_format_error_t* error);

/** @brief Initialize a bidirectional escape-length format.
 * @param[out] format Descriptor, unchanged on failure.
 * @param[in] config Immutable configuration borrowed for the descriptor lifetime.
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for missing pointers.
 * @return #TLV_ERR_INVALID_ARG for invalid widths, ranges, framing or tag table.
 * @return #TLV_ERR_INVALID_ARG for an unknown byte order.
 */
TLV_API tlv_result_t tlv_escaped_format_init(tlv_format_t* format,
                                             const tlv_escaped_format_t* config);

/** @} */
#ifdef __cplusplus
}
#endif
#endif
