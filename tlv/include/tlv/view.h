#ifndef OPENTLV_VIEW_H
#define OPENTLV_VIEW_H

#include "tlv/error.h"
#include "tlv/tag.h"
#include "tlv/value.h"

/**
 * @file
 * @ingroup core
 * @brief Decoded TLV element view: a borrowed tag plus a borrowed value.
 */

/** @addtogroup core
 * @{
 */

/**
 * @brief A decoded TLV element: a borrowed tag and a borrowed value.
 *
 * Both the tag and the value normally reference the original input storage.
 * Copying a view copies only the tag and value descriptors, never their
 * bytes, and does not extend their lifetime: the storage they reference must
 * outlive every copy of the view.
 *
 * @note This plain type does not validate its fields or impose a wire format.
 */
typedef struct {
    /** Element tag; borrows the original input storage. */
    tlv_tag_t tag;
    /** Element value; borrows the original input storage. */
    tlv_value_t value;
} tlv_view_t;

/** @} */

#endif /* OPENTLV_VIEW_H */
