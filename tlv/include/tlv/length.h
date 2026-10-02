// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_LENGTH_H
#define OPENTLV_LENGTH_H

#include <stddef.h>
#include <stdint.h>

/**
 * @file
 * @ingroup core
 * @brief Borrowed raw wire length field.
 */

/** @addtogroup core
 * @{
 */

/**
 * @brief Original encoded length bytes, without numeric interpretation.
 *
 * Borrows `size` bytes in wire order. The source must remain valid and
 * unchanged while this descriptor or any copy is used. No allocation or byte
 * copying occurs. `size` is a native memory extent, not a decoded quantity.
 * The selected format interprets these bytes; a marker for a terminated
 * value is preserved as-is. `{ NULL, 0 }` denotes an absent length field.
 *
 * @see tlv_size_t, tlv_element_t
 */
typedef struct {
    /** Borrowed wire bytes; may be `NULL` only when `size` is zero. */
    const uint8_t* data;
    /** Native byte count of the encoded length field. */
    size_t size;
} tlv_length_t;

/** @} */

#endif /* OPENTLV_LENGTH_H */
