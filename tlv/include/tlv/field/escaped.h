// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_FIELD_ESCAPED_H
#define OPENTLV_FIELD_ESCAPED_H

#include "tlv/size.h"
#include "tlv/endian.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup field_encoding
 * @brief Inline or escape-prefixed unsigned count encoding.
 *
 * Configurations are immutable and borrowed. All processing is allocation-free
 * and independent of element placement and protocol semantics.
 */

/** @addtogroup field_encoding
 * @{
 */

/** @brief One-byte inline count or an escape followed by a fixed-width count.
 *
 * Prefixes below escape encode their own value. Prefixes above escape are
 * invalid. The escape is followed by extended_size full bytes in byte_order.
 * Extended counts must be at least min_extended and at most max_length.
 * All counts, including inline ones, must not exceed max_length. Writing uses
 * inline form whenever possible. Reading accepts configured nonminimal forms.
 * No prefix has protocol meaning.
 */
typedef struct tlv_escaped_length {
    uint8_t escape;              /**< Nonzero escape marker and exclusive inline limit. */
    size_t extended_size;        /**< Extended count width, one through eight bytes. */
    tlv_byte_order_t byte_order; /**< Explicit big or little endian. */
    tlv_size_t min_extended;     /**< Inclusive minimum extended count, at most escape. */
    tlv_size_t max_length;       /**< Inclusive maximum count; at least escape and representable. */
} tlv_escaped_length_t;

/** @brief Decode an inline or escape-prefixed count.
 * @param[in] config Immutable validated encoding configuration.
 * @param[in] data Source bytes; NULL allowed only with zero size.
 * @param[in] size Available bytes.
 * @param[out] length Decoded count; unchanged on failure.
 * @param[out] consumed Field width on success; available prefix width on wire errors.
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for a missing required pointer.
 * @return #TLV_ERR_INVALID_ARG for invalid configuration.
 * @return #TLV_ERR_INVALID_BYTE_ORDER for unsupported byte order.
 * @return #TLV_ERR_BUFFER_TOO_SHORT for incomplete fields.
 * @return #TLV_ERR_INVALID_LENGTH for a reserved prefix or out-of-range count.
 * @note Argument/configuration errors preserve both outputs.
 */
TLV_API tlv_result_t tlv_escaped_length_read(const tlv_escaped_length_t* config,
                                             const uint8_t* data, size_t size, tlv_size_t* length,
                                             size_t* consumed);

/** @brief Encode a count, or measure its field width with NULL output.
 * @param[in] config Immutable encoding configuration.
 * @param[in] length Logical unsigned count.
 * @param[out] data Destination; NULL with zero capacity queries width.
 * @param[in] capacity Available bytes; zero when data is NULL.
 * @param[out] written Encoded width; unchanged on failure.
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for a missing pointer or NULL data with nonzero capacity.
 * @return #TLV_ERR_INVALID_ARG for invalid configuration.
 * @return #TLV_ERR_INVALID_BYTE_ORDER for unsupported byte order.
 * @return #TLV_ERR_INVALID_LENGTH for a count above max_length.
 * @return #TLV_ERR_BUFFER_TOO_SHORT for insufficient capacity.
 * @note Validates before writing; no allocation occurs.
 */
TLV_API tlv_result_t tlv_escaped_length_write(const tlv_escaped_length_t* config, tlv_size_t length,
                                              uint8_t* data, size_t capacity, size_t* written);

/** @} */

#ifdef __cplusplus
}
#endif
#endif
