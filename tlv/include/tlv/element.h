#ifndef OPENTLV_ELEMENT_H
#define OPENTLV_ELEMENT_H

#include "tlv/tag.h"
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
 * @brief Canonical identifier and resolved borrowed value.
 *
 * Both fields borrow source storage, which must remain valid and
 * unchanged while any copy of the element is used. Copying this structure
 * copies descriptors only; no allocation, byte copying, ownership transfer
 * or hidden lifetime management occurs.
 *
 * `tag` preserves identifier byte identity; `{ NULL, 0 }` means no identifier.
 * `value.size` is the logical value byte count, independent of native pointer
 * width, excluding framing. Value bytes are contiguous. Neither a wire Length
 * field nor a particular header layout is implied.
 *
 * Reader-produced values fit the input buffer. Manually assembled values
 * require validation before narrowing to `size_t`. Wire/source information
 * belongs to #tlv_source_t, not to this semantic value. Changing either field
 * invalidates preservation against its original source unless semantic
 * equality is explicitly verified. Source buffers must remain immutable.
 *
 * @note This plain type does not validate its fields or own their storage.
 */
typedef struct {
    /** Raw identifier bytes borrowed from the source. */
    tlv_tag_t tag;
    /** Borrowed value bytes and their decoded logical size. */
    tlv_value_t value;
} tlv_element_t;

/** @} */

#endif /* OPENTLV_ELEMENT_H */
