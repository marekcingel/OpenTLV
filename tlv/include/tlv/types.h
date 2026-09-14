#ifndef OPENTLV_TYPES_H
#define OPENTLV_TYPES_H

#include "tlv/error.h"
#include "tlv/tag.h"
#include <stddef.h>
#include <stdint.h>

/* Non-owning, read-only byte range. The caller keeps the storage alive.
 * data may be NULL only when length is zero. No allocation is performed.
 */
typedef struct {
    const uint8_t *data;
    size_t length;
} tlv_buffer_t;

/* The tag is stored inline; value borrows the original input storage.
 * Copying a view copies the tag but does not copy or extend the value lifetime.
 * These plain types do not validate their fields or impose a wire format.
 */
typedef struct {
    tlv_tag_t tag;
    tlv_buffer_t value;
} tlv_view_t;

#endif /* OPENTLV_TYPES_H */
