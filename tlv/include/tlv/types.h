#ifndef OPENTLV_TYPES_H
#define OPENTLV_TYPES_H

#include "tlv/error.h"
#include <stddef.h>
#include <stdint.h>

/* Override consistently in the library and all consumers: this affects ABI. */
#ifndef TLV_TAG_MAX_SIZE
#define TLV_TAG_MAX_SIZE 8
#endif

#if TLV_TAG_MAX_SIZE < 1 || TLV_TAG_MAX_SIZE > 255
#error "TLV_TAG_MAX_SIZE must be between 1 and 255"
#endif

/* Non-owning, read-only byte range. The caller keeps the storage alive.
 * data may be NULL only when length is zero. No allocation is performed.
 */
typedef struct {
    const uint8_t *data;
    size_t length;
} tlv_buffer_t;

/* Raw bytes in wire order, independent of host endianness or TLV profile.
 * size is the number of valid bytes, from zero to TLV_TAG_MAX_SIZE.
 * A zero size represents an empty tag; profile-specific validity is separate.
 */
typedef struct {
    uint8_t data[TLV_TAG_MAX_SIZE];
    uint8_t size;
} tlv_tag_t;

/* The tag is stored inline; value borrows the original input storage.
 * Copying a view copies the tag but does not copy or extend the value lifetime.
 * These plain types do not validate their fields or impose a wire format.
 */
typedef struct {
    tlv_tag_t tag;
    tlv_buffer_t value;
} tlv_view_t;

#endif /* OPENTLV_TYPES_H */
