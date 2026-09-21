#ifndef OPENTLV_SCHEMA_H
#define OPENTLV_SCHEMA_H

#include "tlv/error.h"
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
    /** Tag this entry describes; borrows its bytes, which must outlive the schema. */
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
 * Matches by tag size and bytes with tlv_tag_equal(), so a tag matches
 * regardless of the memory backing it. Entries with an invalid tag are
 * skipped. No sorting is required.
 *
 * @param[in] schema Schema to search.
 * @param[in] tag    Tag to find.
 *
 * @return The first matching entry, borrowed from the schema's table.
 * @return `NULL` for an unknown tag, `NULL` arguments, or a missing nonempty
 *         table.
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

/** @brief Maximum number of tags in a #tlv_schema_issue_t path. */
enum { TLV_SCHEMA_PATH_MAX = 16 };

/** @brief Kind of violation found by tlv_schema_validate_all(). */
typedef enum tlv_schema_issue_kind {
    /** A required tag is absent: its occurrence count is below `min_occurs`. */
    TLV_SCHEMA_ISSUE_MISSING = 1,
    /** A tag occurs more often than `max_occurs` allows. */
    TLV_SCHEMA_ISSUE_DUPLICATE,
    /** A tag is prohibited or unknown in its parent and unknown tags are rejected. */
    TLV_SCHEMA_ISSUE_UNEXPECTED,
    /** A primitive value where a constructed one is required, or the reverse. */
    TLV_SCHEMA_ISSUE_KIND,
    /** A value length is outside the bounds of the tag's rule. */
    TLV_SCHEMA_ISSUE_LENGTH
} tlv_schema_issue_kind_t;

/** @brief Unknown-tag policy applied by tlv_schema_validate_all(). */
typedef enum tlv_schema_unknown_policy {
    /** Each scope follows its own #tlv_structure_schema_t::allow_unknown. */
    TLV_SCHEMA_UNKNOWN_BY_SCHEMA = 0,
    /** Tags without a rule are accepted in every scope. */
    TLV_SCHEMA_UNKNOWN_ALLOW,
    /** Tags without a rule are reported in every scope. */
    TLV_SCHEMA_UNKNOWN_REJECT
} tlv_schema_unknown_policy_t;

/**
 * @brief One violation found by tlv_schema_validate_all().
 *
 * `path` lists the tags from the outermost scope to the affected tag, for
 * example `70`, `77`, `9F36` for the text `70/77/9F36`. For
 * #TLV_SCHEMA_ISSUE_MISSING the last entry is the tag that is absent.
 */
typedef struct tlv_schema_issue {
    /** What is wrong. */
    tlv_schema_issue_kind_t kind;
    /**
     * Tags from the outermost scope to the affected tag; `path_length` entries
     * are valid. They borrow the input buffer, or the schema for a missing tag,
     * so both must outlive the issue.
     */
    tlv_tag_t path[TLV_SCHEMA_PATH_MAX];
    /** Number of valid entries in `path`, at least one. */
    size_t path_length;
    /**
     * Nonzero if `offset` is set. Zero for a tag missing from the top-level
     * scope, which has no enclosing element.
     */
    int has_offset;
    /**
     * Offset of the affected element's tag in the input. For
     * #TLV_SCHEMA_ISSUE_MISSING it is the offset of the enclosing element,
     * because the absent tag has no position of its own.
     */
    size_t offset;
} tlv_schema_issue_t;

/**
 * @brief Caller-provided storage for the violations of tlv_schema_validate_all().
 *
 * @see tlv_schema_validate_all
 */
typedef struct tlv_schema_report {
    /** Destination for the first `capacity` violations; may be `NULL` only if `capacity` is zero.
     */
    tlv_schema_issue_t* issues;
    /** Number of entries `issues` can hold. */
    size_t capacity;
    /** Receives the total number of violations found, which can exceed `capacity`. */
    size_t count;
} tlv_schema_report_t;

/**
 * @brief Validates a TLV structure and reports every schema violation.
 *
 * Applies the same rules as tlv_schema_validate() (required and optional
 * tags, occurrence limits, parent-child membership, primitive or constructed
 * form, and per-tag length bounds), but continues after a violation and
 * records each one with the path to the affected tag and its byte offset.
 * The tag and length rules come from the same #tlv_structure_rule_t entries,
 * so nothing is defined twice. Never decodes values. No allocation and no
 * recursion.
 *
 * Wire-level errors (a truncated or malformed element, or an exceeded limit)
 * make the input unparseable and abort the call before any violation is
 * recorded. The contents of a scope that violates its rules are still
 * checked: an element rejected as unexpected or of the wrong form is not
 * descended into, but its siblings are checked.
 *
 * Violations are recorded in scope order; the order of violations within one
 * scope is not part of the contract.
 *
 * @param[in]     data          Encoded input.
 * @param[in]     size          Input size in bytes.
 * @param[in]     format        Reader format.
 * @param[in]     is_constructed Nesting predicate, or `NULL` to treat values as opaque.
 * @param[in]     schema        Structural schema to validate against.
 * @param[in]     max_depth     Maximum nesting depth, as for tlv_walk_tree().
 * @param[in]     max_elements  Maximum total elements, as for tlv_walk_tree().
 * @param[in]     unknown       Policy for tags without a rule.
 * @param[in,out] report        Receives the violations; `count` is set on #TLV_OK
 *                              and #TLV_ERR_SCHEMA and is zero on other errors.
 * @param[out]    error_offset  Optional. Receives the failing offset for errors
 *                              other than #TLV_ERR_SCHEMA; see tlv_walk_tree().
 *
 * @return #TLV_OK if the data conforms; `report->count` is zero.
 * @return #TLV_ERR_SCHEMA if at least one violation was found; `report->count`
 *         is their total number, of which the first `report->capacity` are stored.
 * @return #TLV_ERR_NULL_ARG for missing required arguments.
 * @return #TLV_ERR_INVALID_ARG for an invalid rule table or `unknown` value.
 * @return #TLV_ERR_LIMIT if the schema nests deeper than #TLV_SCHEMA_PATH_MAX
 *         tags, or as for tlv_walk_tree().
 * @return Any other error of tlv_walk_tree().
 *
 * @see tlv_schema_issue_path_string
 */
TLV_API tlv_result_t tlv_schema_validate_all(const uint8_t* data, size_t size,
                                             const tlv_reader_format_t* format,
                                             tlv_is_constructed_fn is_constructed,
                                             const tlv_structure_schema_t* schema, size_t max_depth,
                                             size_t max_elements,
                                             tlv_schema_unknown_policy_t unknown,
                                             tlv_schema_report_t* report, size_t* error_offset);

/**
 * @brief Returns a short name for a violation kind.
 *
 * @param[in] kind Violation kind.
 *
 * @return A static, NUL-terminated string such as `"missing"`, never `NULL`;
 *         an unrecognized value yields `"unknown"`.
 */
TLV_API const char* tlv_schema_issue_kind_string(tlv_schema_issue_kind_t kind);

/**
 * @brief Formats the path of a violation as uppercase hexadecimal tags joined by `/`.
 *
 * For example `70/77/9F36`. The text is NUL-terminated when it fits.
 *
 * @param[in]  issue    Violation to format.
 * @param[out] out      Destination; may be `NULL` only if `capacity` is zero.
 * @param[in]  capacity Size of `out` in bytes, including the terminator.
 * @param[out] length   Receives the text length without the terminator, also
 *                      when `out` is too small. May be `NULL`.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG if `issue` or a required `out` is `NULL`.
 * @return #TLV_ERR_INVALID_ARG if the path length or a tag size is invalid.
 * @return #TLV_ERR_BUFFER_TOO_SHORT if `capacity` is below `*length + 1`.
 */
TLV_API tlv_result_t tlv_schema_issue_path_string(const tlv_schema_issue_t* issue, char* out,
                                                  size_t capacity, size_t* length);

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* OPENTLV_SCHEMA_H */
