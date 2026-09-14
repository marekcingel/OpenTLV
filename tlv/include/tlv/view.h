#ifndef OPENTLV_VIEW_H
#define OPENTLV_VIEW_H

#include "tlv/error.h"
#include "tlv/tag.h"
#include "tlv/value.h"

/* The tag is stored inline; value borrows the original input storage.
 * Copying a view copies the tag but does not copy or extend the value lifetime.
 * This plain type does not validate its fields or impose a wire format.
 */
typedef struct {
    tlv_tag_t tag;
    tlv_value_t value;
} tlv_view_t;

#endif /* OPENTLV_VIEW_H */
