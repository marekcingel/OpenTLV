#ifndef OPENTLV_SCHEMA_H
#define OPENTLV_SCHEMA_H

#include "tlv/types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    tlv_tag_t tag;
    size_t min_length;
    size_t max_length;
    uint32_t flags; /* Reserved for future extensions; currently ignored. */
} tlv_schema_entry_t;

/* Borrows a table, which may be static const. No registration or allocation.
 * entries may be NULL only when count is zero. Keep the table alive and
 * unchanged while using the schema or pointers returned by lookup.
 */
typedef struct {
    const tlv_schema_entry_t* entries;
    size_t count;
} tlv_schema_t;

/* Linear lookup by tag size and active bytes (including empty tags).
 * Returns the first matching entry, or NULL for unknown tags, NULL arguments,
 * a missing nonempty table, or a tag size exceeding TLV_TAG_MAX_SIZE.
 * Entries with invalid tag sizes are skipped. No sorting is required.
 */
const tlv_schema_entry_t* tlv_schema_find(const tlv_schema_t* schema,
                                          const tlv_tag_t* tag);

/* Validates only value length, independently of parsing or tag lookup.
 * Bounds are inclusive; equal bounds specify an exact length. SIZE_MAX can
 * be used as an unrestricted upper bound. Returns TLV_ERR_INVALID_LENGTH
 * for an out-of-range length or reversed bounds, TLV_ERR_NULL_ARG for NULL,
 * and TLV_OK otherwise. Flags do not affect validation.
 */
tlv_result_t tlv_schema_validate_length(const tlv_schema_entry_t* entry,
                                         size_t length);

#ifdef __cplusplus
}
#endif

#endif /* OPENTLV_SCHEMA_H */
