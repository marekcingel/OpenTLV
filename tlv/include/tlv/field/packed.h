// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_FIELD_PACKED_H
#define OPENTLV_FIELD_PACKED_H

#include "tlv/endian.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup field_encoding
 * @brief Unsigned packed bit-field extraction and insertion.
 */

/** @addtogroup field_encoding
 * @{
 */

/**
 * @brief One unsigned bit field within a fixed-size wire integer.
 *
 * This is a storage/bit primitive, independent of element composition.
 * Offsets count from the least significant bit after applying byte_order,
 * independently of host endianness. No protocol semantics or storage ownership
 * are implied. Multiple fields may share the same backing bytes.
 */
typedef struct tlv_packed_field {
    size_t storage_size;         /**< Backing integer width in bytes, 1..8. */
    unsigned int bit_offset;     /**< Least significant field bit, 0..63. */
    unsigned int bit_width;      /**< Field width, 1..64; must fit in storage. */
    tlv_byte_order_t byte_order; /**< Explicit big or little endian. */
} tlv_packed_field_t;

/**
 * @brief Extract an unsigned field from its complete backing wire integer.
 *
 * @param[in] field Immutable field configuration, borrowed for this call.
 * @param[in] data Beginning of the backing integer; no alignment required.
 * @param[in] size Available source bytes.
 * @param[out] value Extracted unsigned value on success.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for any required NULL pointer.
 * @return #TLV_ERR_INVALID_ARG for invalid storage size, offset, width or byte order.
 * @return #TLV_ERR_TRUNCATED if the complete storage is unavailable.
 *
 * @note Validation follows the order above. Failure leaves *value unchanged.
 * No allocation or access beyond storage_size bytes occurs.
 */
TLV_API tlv_result_t tlv_packed_field_read(const tlv_packed_field_t* field, const uint8_t* data,
                                           size_t size, uint64_t* value);

/**
 * @brief Insert an unsigned field, preserving every bit outside the field.
 *
 * @param[in] field Immutable field configuration, borrowed for this call.
 * @param[in,out] data Initialized backing bytes; no alignment required.
 * @param[in] capacity Available destination bytes.
 * @param[in] value Unsigned value to insert without truncation.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for any required NULL pointer.
 * @return #TLV_ERR_INVALID_ARG for invalid storage size, offset, width or byte order.
 * @return #TLV_ERR_BUFFER_TOO_SHORT if the complete storage is unavailable.
 * @return #TLV_ERR_OVERFLOW if value does not fit bit_width.
 *
 * @note Validation follows the order above. Failure leaves data unchanged.
 * Initialize backing bytes (for example to zero) before first insertion.
 * No allocation or access beyond storage_size bytes occurs.
 */
TLV_API tlv_result_t tlv_packed_field_write(const tlv_packed_field_t* field, uint8_t* data,
                                            size_t capacity, uint64_t value);

/** @} */

#ifdef __cplusplus
}
#endif
#endif
