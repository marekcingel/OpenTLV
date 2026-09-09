#ifndef OPENTLV_SCHEMA_H
#define OPENTLV_SCHEMA_H

#include "tlv/types.h"
#include "tlv/formats/format.h"

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

typedef enum tlv_schema_kind {
    TLV_SCHEMA_ANY = 0,
    TLV_SCHEMA_PRIMITIVE,
    TLV_SCHEMA_CONSTRUCTED
} tlv_schema_kind_t;

struct tlv_structure_schema;
typedef struct tlv_structure_rule {
    tlv_schema_entry_t entry;
    size_t min_occurs; /* 1 makes a field required; 0 makes it optional. */
    size_t max_occurs; /* 1 prohibits duplicates; SIZE_MAX is unrestricted. */
    tlv_schema_kind_t kind;
    const struct tlv_structure_schema* children;
} tlv_structure_rule_t;

/* Rules apply within one parent only. Tags must be unique in each table.
 * children requires CONSTRUCTED and validates its complete value, including
 * required children in empty containers. NULL children leaves membership
 * unrestricted, while wire structure is still checked recursively.
 * Unknown tags are rejected unless allow_unknown is nonzero. */
typedef struct tlv_structure_schema {
    const tlv_structure_rule_t* rules;
    size_t count;
    int allow_unknown;
} tlv_structure_schema_t;

/* Validate framing, nesting, lengths, occurrence counts and child membership.
 * Never decodes values. All tables are borrowed and immutable during use.
 * Limits and offsets follow tlv_walk_tree; missing required fields report
 * the end of their parent value. Invalid rule tables return TLV_ERR_SCHEMA.
 * Uses bounded stack storage without allocation or recursion. Counts are
 * checked by rescanning each scope per rule: O(rules * rules + elements * rules) per scope.
 * Input and schema errors leave no partial application objects. */
/* is_constructed uses format->context; NULL treats values as opaque. */
tlv_result_t tlv_schema_validate(const uint8_t* data, size_t size,
                                 const tlv_reader_format_t* format,
                                 tlv_is_constructed_fn is_constructed,
                                 const tlv_structure_schema_t* schema,
                                 size_t max_depth, size_t max_elements,
                                 size_t* error_offset);

#ifdef __cplusplus
}
#endif

#endif /* OPENTLV_SCHEMA_H */
