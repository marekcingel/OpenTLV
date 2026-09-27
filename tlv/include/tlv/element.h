#ifndef OPENTLV_ELEMENT_H
#define OPENTLV_ELEMENT_H

#include "tlv/tag.h"
#include "tlv/length.h"
#include "tlv/value.h"

/**
 * @file
 * @ingroup core
 * @brief Canonical, format-independent borrowed TLV element.
 */

/** @addtogroup core
 * @{
 */

/**
 * @brief Raw tag and length fields plus the resolved borrowed value.
 *
 * All three fields borrow source storage, which must remain valid and
 * unchanged while any copy of the element is used. Copying this structure
 * copies descriptors only; no allocation, byte copying, ownership transfer
 * or hidden lifetime management occurs.
 *
 * `tag` preserves byte identity; `length` preserves the exact length-field
 * encoding. Their `size_t` sizes are native memory extents. `value.size` is
 * the decoded logical value byte count (#tlv_size_t, always 64 bits), excluding
 * framing. The format interprets the raw length and resolves this count,
 * including for terminated values or lengths that count other fields.
 * No host-endian tag interpretation or concrete wire layout is implied.
 *
 * Reader-produced values fit the input buffer. Manually assembled values
 * require validation before narrowing their size to `size_t`. Serialization
 * uses tag and value and regenerates the length in the destination format;
 * it does not use the raw length bytes as the value size.
 *
 * @note This plain type does not validate its fields or own their storage.
 */
typedef struct {
    /** Raw identifier bytes borrowed from the source. */
    tlv_tag_t tag;
    /** Raw length-field bytes borrowed from the source. */
    tlv_length_t length;
    /** Borrowed value bytes and their decoded logical size. */
    tlv_value_t value;
} tlv_element_t;

/** @} */

#endif /* OPENTLV_ELEMENT_H */
