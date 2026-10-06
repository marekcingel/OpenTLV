// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_FIELD_FIXED_H
#define OPENTLV_FIELD_FIXED_H

#include "tlv/tag.h"
#include "tlv/size.h"
#include "tlv/endian.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup field_encoding
 * @brief Fixed-width raw identifiers and unsigned count encodings.
 *
 * Configurations are immutable and borrowed for each call. Operations do not
 * allocate or retain configuration pointers. Identifiers preserve raw byte
 * identity; byte order applies only to counts. Element placement, count scope,
 * framing and protocol policy belong to the caller's Format composition.
 */

/** @addtogroup field_encoding
 * @{
 */

/**
 * @brief Encoding of an identifier as a fixed number of unchanged wire bytes.
 */
typedef struct tlv_fixed_identifier {
    size_t size; /**< Identifier width in bytes; nonzero, with no numeric tag interpretation. */
} tlv_fixed_identifier_t;

/**
 * @brief Encoding of an unsigned count as a fixed-width wire integer.
 */
typedef struct tlv_fixed_length {
    size_t size;                 /**< Count width in bytes, one through eight. */
    tlv_byte_order_t byte_order; /**< Explicit big or little endian, independent of the host. */
} tlv_fixed_length_t;

/**
 * @brief Borrow exactly the configured number of identifier bytes.
 *
 * @param[in] config Immutable identifier configuration, not NULL.
 * @param[in] data Source bytes; NULL is allowed only when size is zero.
 * @param[in] size Available source bytes.
 * @param[out] tag Identifier borrowing data; input must remain alive and unchanged while used.
 * @param[out] consumed Configured identifier width on success.
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for a missing required pointer or NULL data with nonzero size.
 * @return #TLV_ERR_INVALID_ARG for a zero configured width.
 * @return #TLV_ERR_BUFFER_TOO_SHORT for incomplete input.
 * @note Validation follows the order above. Both outputs are unchanged on failure.
 * No allocation or copy occurs; bytes after the identifier are not inspected.
 */
TLV_API tlv_result_t tlv_fixed_identifier_read(const tlv_fixed_identifier_t* config,
                                               const uint8_t* data, size_t size, tlv_tag_t* tag,
                                               size_t* consumed);

/**
 * @brief Copy a fixed-width raw identifier, or measure it with NULL output.
 *
 * @param[in] config Immutable identifier configuration, not NULL.
 * @param[in] tag Raw identifier, not NULL; its data may be NULL only when its size is zero.
 * @param[out] data Destination; NULL with zero capacity queries the width.
 * @param[in] capacity Destination capacity in bytes.
 * @param[out] written Configured identifier width on success.
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for missing pointers, nonempty NULL tag bytes or NULL data with nonzero
 * capacity.
 * @return #TLV_ERR_INVALID_ARG for a zero configured width.
 * @return #TLV_ERR_INVALID_TAG_SIZE if tag size differs from the configured width.
 * @return #TLV_ERR_BUFFER_TOO_SHORT for insufficient destination capacity.
 * @note Validation follows the order above. The destination and *written are
 * unchanged on failure. Sizing validates the identifier and does not copy it.
 * Source identifier bytes and destination must not overlap. No allocation occurs.
 */
TLV_API tlv_result_t tlv_fixed_identifier_write(const tlv_fixed_identifier_t* config,
                                                const tlv_tag_t* tag, uint8_t* data,
                                                size_t capacity, size_t* written);

/**
 * @brief Decode a fixed-width unsigned count without narrowing to native size.
 *
 * @param[in] config Immutable count configuration, not NULL.
 * @param[in] data Source bytes; NULL is allowed only when size is zero.
 * @param[in] size Available source bytes.
 * @param[out] length Decoded count on success; unchanged on failure.
 * @param[out] consumed Configured width on success; available prefix width on incomplete input.
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for a missing required pointer or NULL data with nonzero size.
 * @return #TLV_ERR_INVALID_ARG for a configured width outside one through eight bytes.
 * @return #TLV_ERR_INVALID_BYTE_ORDER for unsupported byte order.
 * @return #TLV_ERR_BUFFER_TOO_SHORT for incomplete input.
 * @note Validation follows the order above. Argument/configuration errors leave
 * both outputs unchanged. Incomplete input sets *consumed to size. No allocation
 * or access beyond the configured width occurs.
 */
TLV_API tlv_result_t tlv_fixed_length_read(const tlv_fixed_length_t* config, const uint8_t* data,
                                           size_t size, tlv_size_t* length, size_t* consumed);

/**
 * @brief Encode a fixed-width unsigned count, or measure it with NULL output.
 *
 * @param[in] config Immutable count configuration, not NULL.
 * @param[in] length Logical unsigned count, without native-size narrowing.
 * @param[out] data Destination; NULL with zero capacity queries the width.
 * @param[in] capacity Destination capacity in bytes.
 * @param[out] written Configured field width on success.
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for missing pointers or NULL data with nonzero capacity.
 * @return #TLV_ERR_INVALID_ARG for a configured width outside one through eight bytes.
 * @return #TLV_ERR_INVALID_BYTE_ORDER for unsupported byte order.
 * @return #TLV_ERR_INVALID_LENGTH if length does not fit the configured width.
 * @return #TLV_ERR_BUFFER_TOO_SHORT for insufficient destination capacity.
 * @note Validation follows the order above. The destination and *written are
 * unchanged on failure. Sizing validates the count. No allocation occurs.
 */
TLV_API tlv_result_t tlv_fixed_length_write(const tlv_fixed_length_t* config, tlv_size_t length,
                                            uint8_t* data, size_t capacity, size_t* written);

/** @} */

#ifdef __cplusplus
}
#endif
#endif
