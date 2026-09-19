#ifndef OPENTLV_VIEW_H
#define OPENTLV_VIEW_H

#include "tlv/error.h"
#include "tlv/tag.h"
#include "tlv/value.h"

/**
 * @file view.h
 * @brief Decoded TLV element view: an inline tag plus a borrowed value.
 */

/**
 * @brief A decoded TLV element: an inline tag and a borrowed value.
 *
 * The tag is stored inline. The value borrows the original input storage, so
 * copying a view copies the tag but neither copies the value bytes nor
 * extends their lifetime; the input must outlive every copy of the view.
 *
 * @note This plain type does not validate its fields or impose a wire format.
 */
typedef struct {
    /** Element tag, stored inline. */
    tlv_tag_t tag;
    /** Element value; borrows the original input storage. */
    tlv_value_t value;
} tlv_view_t;

#endif /* OPENTLV_VIEW_H */
