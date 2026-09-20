#ifndef OPENTLV_SCHEMA_H
#define OPENTLV_SCHEMA_H

#include "tlv/view.h"
#include "tlv/formats/format.h"
#include "tlv/export.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup schemas
 * @brief Length schemas and structural schemas for validating TLV data.
 */

/** @addtogroup schemas
 * @{
 */

/**
 * @brief Length rule for one tag in a #tlv_schema_t.
 *
 * Length bounds are inclusive; equal bounds specify an exact length.
 */
typedef struct {
    /** Tag this entry describes. */
    tlv_tag_t tag;
    /** Minimum permitted value length in bytes, inclusive. */
    size_t min_length;
    /** Maximum permitted value length in bytes, inclusive; `SIZE_MAX` is unrestricted. */
    size_t max_length;
    /** Reserved for future extensions; currently ignored. */
    uint32_t flags;
} tlv_schema_entry_t;

/**
 * @brief Borrowed table of per-tag length rules.
 *
 * The table may be `static const`. There is no registration and no
 * allocation. `entries` may be `NULL` only when `count` is zero.
 *
 * @warning Keep the table alive and unchanged while using the schema or
 *          pointers returned by tlv_schema_find().
 */
typedef struct {
    /** Borrowed entries; may be `NULL` only when `count` is zero. */
    const tlv_schema_entry_t* entries;
    /** Number of entries. */
    size_t count;
} tlv_schema_t;

/**
 * @brief Looks up a tag's entry by linear search.
 *
 * Matches by tag size and active bytes, including empty tags. Entries with
 * invalid tag sizes are skipped. No sorting is required.
 *
 * @param[in] schema Schema to search.
 * @param[in] tag    Tag to find.
 *
 * @return The first matching entry, borrowed from the schema's table.
 * @return `NULL` for an unknown tag, `NULL` arguments, a missing nonempty
 *         table, or a tag size exceeding #TLV_TAG_CAPACITY.
 */
TLV_API const tlv_schema_entry_t* tlv_schema_find(const tlv_schema_t* schema, const tlv_tag_t* tag);

/**
 * @brief Validates a value length against an entry's bounds.
 *
 * Checks only the length, independently of parsing or tag lookup. Bounds are
 * inclusive; equal bounds specify an exact length, and `SIZE_MAX` can be used
 * as an unrestricted upper bound. The entry's flags do not affect validation.
 *
 * @param[in] entry  Entry providing the bounds.
 * @param[in] length Value length to check.
 *
 * @return #TLV_OK if the length is within the bounds.
 * @return #TLV_ERR_INVALID_LENGTH for an out-of-range length or reversed bounds.
 * @return #TLV_ERR_NULL_ARG if `entry` is `NULL`.
 */
TLV_API tlv_result_t tlv_schema_validate_length(const tlv_schema_entry_t* entry, size_t length);

/** @brief Expected form of a value described by a #tlv_structure_rule_t. */
typedef enum tlv_schema_kind {
    /** The element may be primitive or constructed. */
    TLV_SCHEMA_ANY = 0,
    /** The element must be primitive. */
    TLV_SCHEMA_PRIMITIVE,
    /** The element must be constructed. */
    TLV_SCHEMA_CONSTRUCTED
} tlv_schema_kind_t;

struct tlv_structure_schema;

/**
 * @brief Structural rule for one tag within a single parent.
 *
 * @see tlv_structure_schema_t
 */
typedef struct tlv_structure_rule {
    /** Tag and permitted value-length bounds for this rule. */
    tlv_schema_entry_t entry;
    /** Minimum occurrences within the parent: 1 makes a field required; 0 makes it optional. */
    size_t min_occurs;
    /** Maximum occurrences within the parent: 1 prohibits duplicates; `SIZE_MAX` is unrestricted.
     */
    size_t max_occurs;
    /** Required form of the value. */
    tlv_schema_kind_t kind;
    /**
     * Schema for the value's children. Requires #TLV_SCHEMA_CONSTRUCTED and
     * validates the complete value, including required children in empty
     * containers. `NULL` leaves membership unrestricted, while wire structure
     * is still checked recursively.
     */
    const struct tlv_structure_schema* children;
} tlv_structure_rule_t;

/**
 * @brief Borrowed set of structural rules for one parent scope.
 *
 * Rules apply within one parent only, and tags must be unique in each table.
 * Unknown tags are rejected unless `allow_unknown` is nonzero.
 *
 * @warning Rule tables are borrowed and must stay valid and unchanged while in use.
 */
typedef struct tlv_structure_schema {
    /** Borrowed rules; tags must be unique. */
    const tlv_structure_rule_t* rules;
    /** Number of rules. */
    size_t count;
    /** Nonzero accepts tags that match no rule. */
    int allow_unknown;
} tlv_structure_schema_t;

/**
 * @brief Validates framing, nesting, lengths, occurrence counts and child membership.
 *
 * Never decodes values. All tables are borrowed and immutable during use.
 * Limits and offsets follow tlv_walk_tree(). Uses bounded stack storage
 * without allocation or recursion. Counts are checked by rescanning each
 * scope per rule: O(rules * rules + elements * rules) per scope. Input and
 * schema errors leave no partial application objects.
 *
 * `is_constructed` receives `format->context`; `NULL` treats values as opaque.
 *
 * @param[in]  data          Encoded input.
 * @param[in]  size          Input size in bytes.
 * @param[in]  format        Reader format.
 * @param[in]  is_constructed Nesting predicate, or `NULL`.
 * @param[in]  schema        Structural schema to validate against.
 * @param[in]  max_depth     Maximum nesting depth, as for tlv_walk_tree().
 * @param[in]  max_elements  Maximum total elements, as for tlv_walk_tree().
 * @param[out] error_offset  Optional. Receives the offset of the failure; see below.
 *
 * @return #TLV_OK if the data conforms to the schema.
 * @return #TLV_ERR_SCHEMA_MISSING if a required field is absent (an
 *         occurrence count below its rule's `min_occurs`). The offset is the
 *         end of the parent's value: a scope boundary, not an element, which
 *         can coincide with the start of an unrelated sibling in the
 *         enclosing scope.
 * @return #TLV_ERR_SCHEMA for every other violation (forbidden or unknown
 *         tag, an occurrence count above `max_occurs`, kind mismatch, an
 *         invalid rule table), with the offset anchored to the offending element.
 * @return #TLV_ERR_INVALID_LENGTH for a length failure, also element-anchored.
 * @return Any other error of tlv_walk_tree().
 */
TLV_API tlv_result_t tlv_schema_validate(const uint8_t* data, size_t size,
                                         const tlv_reader_format_t* format,
                                         tlv_is_constructed_fn is_constructed,
                                         const tlv_structure_schema_t* schema, size_t max_depth,
                                         size_t max_elements, size_t* error_offset);

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* OPENTLV_SCHEMA_H */
