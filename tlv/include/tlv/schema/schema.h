// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_SCHEMA_H
#define OPENTLV_SCHEMA_H

#include "tlv/error.h"
#include "tlv/config.h"
#include "tlv/element.h"
#include "tlv/format.h"
#include "tlv/diagnostic.h"
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

/** @brief Nesting capacity of the Schema validators' local traversal storage. */
enum { TLV_SCHEMA_MAX_DEPTH = 64 };

/**
 * @brief Length rule for one tag in a #tlv_schema_t.
 *
 * Length bounds are inclusive; equal bounds specify an exact length.
 * A nonzero `length_multiple` additionally requires divisibility by that width.
 * #TLV_SCHEMA_LENGTH_ENDPOINTS permits only min_length or max_length.
 */
typedef struct {
    /** Tag this entry describes; borrows its bytes, which must outlive the schema. */
    tlv_tag_t tag;
    /** Minimum permitted value length in bytes, inclusive. */
    size_t min_length;
    /** Maximum permitted value length in bytes, inclusive; `SIZE_MAX` is unrestricted. */
    size_t max_length;
    /** Length policy bits; unknown bits are ignored. See #TLV_SCHEMA_LENGTH_ENDPOINTS. */
    uint32_t flags;
    /** Borrowed name of the field this entry describes, for example `"df_name"`, or `NULL` if
     * unnamed. Used only for diagnostics; never affects validation. */
    const char* name;
    /** Required value-length multiple in bytes; 0 disables this constraint.
     * Zero length is divisible by every nonzero width, subject to the bounds. */
    size_t length_multiple;
} tlv_schema_entry_t;

/** @brief Permit only the two bounds, rather than every length between them.
 * Equal bounds still specify an exact length; length_multiple also applies. */
enum { TLV_SCHEMA_LENGTH_ENDPOINTS = 1 };

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
 * as an unrestricted upper bound. A nonzero `length_multiple` requires
 * `length % length_multiple == 0`. #TLV_SCHEMA_LENGTH_ENDPOINTS additionally
 * requires length to equal one of the two bounds. Unknown flag bits are ignored.
 *
 * @param[in] entry  Entry providing the bounds.
 * @param[in] length Value length to check.
 *
 * @return #TLV_OK if the length satisfies both the bounds and the multiple.
 * @return #TLV_ERR_SCHEMA for an out-of-range length, a non-multiple,
 *         or an excluded intermediate length under a valid rule.
 * @return #TLV_ERR_INVALID_SCHEMA for reversed bounds.
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
    /** Required authoritative field Schema. Borrows immutable storage (including
     * tag bytes and name) that must outlive every use of this structural rule.
     * Multiple rules and dictionaries may share this same field Schema. */
    const tlv_schema_entry_t* entry;
    /**
     * Minimum occurrences within the parent: 1 makes a field required; 0
     * makes it optional or, together with a default value maintained outside
     * this schema-only engine, defaulted. Must be 0 when `group` is nonzero.
     */
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
    /**
     * Group this rule belongs to, or 0 if it stands alone (the default).
     * A nonzero value must match the `id` of an entry in the enclosing
     * #tlv_structure_schema_t::groups, and makes this rule one alternative of
     * that #tlv_structure_group_t, modeling an ASN.1-style CHOICE among the
     * group's member tags. `min_occurs` must be 0 for a grouped rule;
     * `max_occurs` still bounds how many times this specific alternative may
     * repeat, independently of the group's own bounds.
     */
    uint32_t group;
} tlv_structure_rule_t;

/**
 * @brief Ordering required among a scope's matched elements.
 *
 * @see tlv_structure_schema_t::order
 */
typedef enum tlv_schema_order {
    /** No relative order is required among matched elements, as for ASN.1 SET
     * and SET OF (the default, and the engine's original behavior). */
    TLV_SCHEMA_ORDER_ANY = 0,
    /**
     * Elements that match a rule must appear in the same relative order as
     * their rules are listed in the table, as for ASN.1 SEQUENCE and
     * SEQUENCE OF. Repeated matches of one rule may appear consecutively.
     * Elements that match no rule (accepted only when `allow_unknown` is
     * nonzero) are not constrained by this ordering.
     */
    TLV_SCHEMA_ORDER_SEQUENCE
} tlv_schema_order_t;

/**
 * @brief A CHOICE-like group of mutually related alternative rules.
 *
 * Occurrence bounds apply to the sum of matches across every rule that
 * shares this group's `id` through #tlv_structure_rule_t::group, instead of
 * to each rule individually: `min_occurs` 1 and `max_occurs` 1 require
 * exactly one occurrence of exactly one of the group's alternatives,
 * modeling an ASN.1 CHOICE component; `min_occurs` 0 models an optional one.
 *
 * @see tlv_structure_rule_t::group, tlv_structure_schema_t::groups
 */
typedef struct tlv_structure_group {
    /** Nonzero identifier, referenced by #tlv_structure_rule_t::group; unique within one
     * #tlv_structure_schema_t::groups table. */
    uint32_t id;
    /** Minimum total occurrences across all member rules, inclusive. */
    size_t min_occurs;
    /** Maximum total occurrences across all member rules, inclusive; `SIZE_MAX` is unrestricted.
     */
    size_t max_occurs;
    /** Borrowed name of the group, for example `"choice_field"`, for diagnostics; `NULL` if
     * unnamed. Never affects validation. */
    const char* name;
} tlv_structure_group_t;

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
    /** Borrowed table of alternative groups referenced by `rules[*].group`; may be `NULL` only
     * when `group_count` is zero. */
    const tlv_structure_group_t* groups;
    /** Number of entries in `groups`. */
    size_t group_count;
    /** Ordering required among this scope's matched elements. */
    tlv_schema_order_t order;
} tlv_structure_schema_t;

/** @brief Schema failure detail, independent of the common result. */
typedef enum tlv_schema_issue_kind {
    /** No Schema-specific detail (success or a delegated error). */
    TLV_SCHEMA_ISSUE_NONE = 0,
    /** A required tag is absent: its occurrence count is below `min_occurs`. */
    TLV_SCHEMA_ISSUE_MISSING = 1,
    /** A tag occurs more often than `max_occurs` allows. */
    TLV_SCHEMA_ISSUE_DUPLICATE,
    /** A tag is prohibited or unknown in its parent and unknown tags are rejected. */
    TLV_SCHEMA_ISSUE_UNEXPECTED,
    /** A primitive value where a constructed one is required, or the reverse. */
    TLV_SCHEMA_ISSUE_KIND,
    /** A value length violates the bounds or required multiple of the tag's rule. */
    TLV_SCHEMA_ISSUE_LENGTH,
    /** An element appears before an earlier-listed rule's element in a scope whose
     * #tlv_structure_schema_t::order is #TLV_SCHEMA_ORDER_SEQUENCE. */
    TLV_SCHEMA_ISSUE_ORDER,
    /** Contextual compiled Query boolean assertion failed. */
    TLV_SCHEMA_ISSUE_ASSERTION,
    /** Input Value violates a valid semantic constraint. */
    TLV_SCHEMA_ISSUE_VALUE,
    /** Invalid schema definition; byte location is unknown. */
    TLV_SCHEMA_ISSUE_DEFINITION
} tlv_schema_issue_kind_t;

/** @brief Unknown-tag policy applied by tlv_schema_validate_all_diag(). */
typedef enum tlv_schema_unknown_policy {
    /** Each scope follows its own #tlv_structure_schema_t::allow_unknown. */
    TLV_SCHEMA_UNKNOWN_BY_SCHEMA = 0,
    /** Tags without a rule are accepted in every scope. */
    TLV_SCHEMA_UNKNOWN_ALLOW,
    /** Tags without a rule are reported in every scope. */
    TLV_SCHEMA_UNKNOWN_REJECT
} tlv_schema_unknown_policy_t;

/**
 * @brief Returns a short name for a violation kind.
 *
 * @param[in] kind Violation kind.
 *
 * @return A static, NUL-terminated string such as `"missing"` or `"order"`, never `NULL`;
 *         an unrecognized value yields `"unknown"`.
 */
TLV_API const char* tlv_schema_issue_kind_string(tlv_schema_issue_kind_t kind);

/** @brief Meaning of a Schema diagnostic byte position. */
typedef enum tlv_schema_anchor {
    /** No byte position is known. */
    TLV_SCHEMA_ANCHOR_UNKNOWN = 0,
    /** Position of evidence in an existing element. */
    TLV_SCHEMA_ANCHOR_ELEMENT,
    /** End of the enclosing scope; no element exists at this position. */
    TLV_SCHEMA_ANCHOR_SCOPE_END,
    /** Position at which absent ordered content would be inserted. */
    TLV_SCHEMA_ANCHOR_INSERTION
} tlv_schema_anchor_t;

/**
 * @brief Structured Schema failure detail shared by validation and definition checks.
 *
 * Pairs a #tlv_diagnostic_t (code, severity and an optional byte position) with the schema-specific
 * detail needed to explain the violation: which rule or #tlv_structure_group_t it breaks, the tag
 * involved, the enclosing path, the schema field or group name if it has one, and the
 * expected-versus-actual detail for whichever of `kind`'s cases applies. A
 * field not applicable to `kind` is left unset, indicated by its paired
 * `has_*` flag being zero. Every field is a fixed-size value or a borrowed
 * pointer, so filling one never allocates.
 *
 * #TLV_SCHEMA_ISSUE_MISSING and #TLV_SCHEMA_ISSUE_DUPLICATE can be reported
 * against a #tlv_structure_group_t instead of a single #tlv_structure_rule_t,
 * signaled by `is_group`: `tag` is then the group's first member rule's tag
 * (missing) or the actual offending member's tag (duplicate), `field` is the
 * group's `name`, and the occurrence fields are the group's own bounds and
 * summed occurrences rather than one rule's.
 *
 * `diagnostic.path` is left `NULL`; `path` below holds the same information
 * as a plain value so that copying a `tlv_schema_diagnostic_t` out of a
 * report array never leaves a dangling self-reference. A caller that wants
 * `path` reachable through `diagnostic.path` sets it explicitly with
 * tlv_diagnostic_set_path() after the copy has a stable address.
 *
 * @see tlv_schema_diagnostic_init
 */
typedef struct tlv_schema_diagnostic {
    /** Common result, severity and optional byte offset; interpret with anchor. */
    tlv_diagnostic_t diagnostic;
    /** Which rule was violated; see #tlv_schema_issue_kind_t. */
    tlv_schema_issue_kind_t kind;
    /** Affected tag; for #TLV_SCHEMA_ISSUE_MISSING, the tag that is absent. Borrows the input
     * buffer, immutable format identifier storage, or the schema for a missing tag. */
    tlv_tag_t tag;
    /** Tags of the scopes enclosing `tag`, outermost first; does not include `tag` itself. */
    tlv_diagnostic_path_t path;
    /** Borrowed schema name for `tag` (the violated rule's `entry->name`, or the violated group's
     * `name` when `is_group` is nonzero), or `NULL` if it has none or no rule matched
     * (#TLV_SCHEMA_ISSUE_UNEXPECTED). */
    const char* field;
    /** Nonzero if this #TLV_SCHEMA_ISSUE_MISSING or #TLV_SCHEMA_ISSUE_DUPLICATE is reported
     * against a #tlv_structure_group_t rather than a single #tlv_structure_rule_t. */
    int is_group;
    /** Nonzero if `min_occurs`, `max_occurs` and `occurs` are set (#TLV_SCHEMA_ISSUE_MISSING,
     * #TLV_SCHEMA_ISSUE_DUPLICATE). */
    int has_occurs;
    /** Minimum permitted occurrences of `tag` in its parent, or of the group's members combined
     * when `is_group` is nonzero. */
    size_t min_occurs;
    /** Maximum permitted occurrences of `tag` in its parent, or of the group's members combined
     * when `is_group` is nonzero. */
    size_t max_occurs;
    /** Occurrences found so far at the point of the violation, of `tag` or, when `is_group` is
     * nonzero, of the group's members combined. */
    size_t occurs;
    /** Nonzero if `min_length`, `max_length`, `actual_length`, `length_multiple` and `length_flags`
     * are set
     * (#TLV_SCHEMA_ISSUE_LENGTH). */
    int has_length;
    /** Minimum permitted value length in bytes, inclusive. */
    size_t min_length;
    /** Maximum permitted value length in bytes, inclusive. */
    size_t max_length;
    /** Actual value length in bytes. */
    size_t actual_length;
    /** Nonzero if `expected_form` and `actual_constructed` are set (#TLV_SCHEMA_ISSUE_KIND). */
    int has_form;
    /** Form the rule requires. */
    tlv_schema_kind_t expected_form;
    /** Nonzero if the actual value was constructed, zero if primitive. */
    int actual_constructed;
    /** Required value-length multiple for a length violation; 0 means unrestricted. */
    size_t length_multiple;
    /** Schema length-policy flags, including #TLV_SCHEMA_LENGTH_ENDPOINTS, when has_length. */
    uint32_t length_flags;
    /** Meaning of diagnostic.offset, or UNKNOWN when has_offset is false. */
    tlv_schema_anchor_t anchor;
} tlv_schema_diagnostic_t;

/**
 * @brief Resets a schema diagnostic to all-unset.
 *
 * @param[out] diagnostic Diagnostic to initialize; must not be `NULL`.
 */
TLV_API void tlv_schema_diagnostic_init(tlv_schema_diagnostic_t* diagnostic);

/**
 * @brief Checks every reachable structural schema table independently of input.
 * Recursive references are supported; the active ancestor chain is checked once.
 * @param schema Borrowed schema graph.
 * @param diagnostic Optional failure detail; definition errors have unknown byte location.
 * @return #TLV_OK, #TLV_ERR_NULL_ARG, #TLV_ERR_INVALID_SCHEMA, or
 * #TLV_ERR_UNSUPPORTED_TYPE when the definition exceeds bounded checking capacity.
 */
TLV_API tlv_result_t tlv_schema_check(const tlv_structure_schema_t* schema,
                                      tlv_schema_diagnostic_t* diagnostic);

#if OPENTLV_READER
/**
 * @brief Validates framing, nesting, lengths, occurrence counts, ordering,
 * alternative groups and child membership.
 *
 * Never decodes values. All tables are borrowed and immutable during use.
 * Limits and offsets follow Tree Reader. Uses TLV_SCHEMA_MAX_DEPTH structural frames
 * and bounded schema-context storage
 * without allocation or recursion. Counts are checked by rescanning each
 * scope per rule and per group: O((rules + groups) * (rules + elements)) per
 * scope. Input and schema errors leave no partial application objects.
 *
 * A scope whose #tlv_structure_schema_t::order is #TLV_SCHEMA_ORDER_SEQUENCE
 * additionally requires matched elements to appear in the same relative
 * order as their rules are listed. A scope with a nonempty
 * #tlv_structure_schema_t::groups additionally requires, for each group, the
 * total occurrences of its member tags to be within the group's own
 * `min_occurs`/`max_occurs`, on top of each member's own per-rule bounds.
 *
 * `format->is_constructed` receives `format->context`; `NULL` treats values as
 * opaque.
 *
 * @param[in]  data          Encoded input.
 * @param[in]  size          Input size in bytes.
 * @param[in]  format        Reader format.
 * @param[in]  schema        Structural schema to validate against.
 * @param[in]  max_depth     Runtime nesting limit; actual depth is also bounded by
 * TLV_SCHEMA_MAX_DEPTH.
 * @param[in]  max_elements  Maximum total elements, as for tlv_tree_reader_visit().
 * @param[out] diagnostic Optional first failure, including kind and location anchor.
 * Definition and argument failures have no byte location.
 *
 * @return #TLV_OK if the data conforms to the schema.
 * @return #TLV_ERR_INVALID_SCHEMA for an invalid definition, checked before input.
 * @return #TLV_ERR_SCHEMA for a valid schema rejecting input, including MISSING.
 * @return #TLV_ERR_NULL_ARG for a missing required pointer.
 * @return Any other error of tlv_tree_reader_visit().
 */
TLV_API tlv_result_t tlv_schema_validate(const uint8_t* data, size_t size,
                                         const tlv_format_t* format,
                                         const tlv_structure_schema_t* schema, size_t max_depth,
                                         size_t max_elements, tlv_schema_diagnostic_t* diagnostic);
#endif

/**
 * @brief Caller-provided storage for the violations of tlv_schema_validate_all_diag().
 *
 * @see tlv_schema_validate_all_diag
 */
typedef struct tlv_schema_diagnostic_report {
    /** Destination for the first `capacity` violations; may be `NULL` only if `capacity` is
     * zero. */
    tlv_schema_diagnostic_t* diagnostics;
    /** Number of entries `diagnostics` can hold. */
    size_t capacity;
    /** Receives the total number of violations found, which can exceed `capacity`. */
    size_t count;
} tlv_schema_diagnostic_report_t;

#if OPENTLV_READER
/**
 * @brief Validates a TLV structure and reports every schema violation.
 *
 * Applies the same rules as tlv_schema_validate() (required and optional
 * tags, occurrence limits, ordering, alternative groups, parent-child
 * membership, primitive or constructed form, and per-tag length bounds), but
 * continues after a violation and records each one with its enclosing scope path, affected tag,
 * field name, byte offset and expected-versus-actual detail. The tag and length rules come from the
 * same #tlv_structure_rule_t entries, so nothing is defined twice. Never
 * decodes values. No allocation and no recursion.
 *
 * Wire-level errors (a truncated or malformed element, or an exceeded limit)
 * make the input unparseable and abort the call before any violation is
 * recorded. The contents of a scope that violates its rules are still
 * checked: an element rejected as unexpected or of the wrong form is not
 * descended into, but its siblings are checked.
 *
 * The entire reachable definition is checked before reading input. Missing
 * findings use the enclosing scope end, with SCOPE_END anchor, including offset
 * zero at an empty root.
 *
 * Violations are recorded in scope order; the order of violations within one
 * scope is not part of the contract.
 *
 * @param[in]     data          Encoded input.
 * @param[in]     size          Input size in bytes.
 * @param[in]     format        Reader format.
 * @param[in]     schema        Structural schema to validate against.
 * @param[in]     max_depth     Runtime nesting limit; actual depth is also bounded by
 * TLV_SCHEMA_MAX_DEPTH.
 * @param[in]     max_elements  Maximum total elements, as for tlv_tree_reader_visit().
 * @param[in]     unknown       Policy for tags without a rule.
 * @param[in,out] report        Receives the violations; `count` is set on #TLV_OK
 *                              and #TLV_ERR_SCHEMA and is zero on other errors.
 * @param[out]    error_offset  Optional. Receives the failing offset for errors
 *                              other than #TLV_ERR_SCHEMA; see tlv_tree_reader_visit().
 *
 * @return #TLV_OK if the data conforms; `report->count` is zero.
 * @return #TLV_ERR_SCHEMA if at least one violation was found; `report->count`
 *         is their total number, of which the first `report->capacity` are stored.
 * @return #TLV_ERR_NULL_ARG for missing required arguments.
 * @return #TLV_ERR_INVALID_SCHEMA for an invalid rule or group table.
 * @return #TLV_ERR_INVALID_ARG for an invalid `unknown` value.
 * @return #TLV_ERR_LIMIT if the schema nests deeper than #TLV_DIAGNOSTIC_PATH_MAX
 *         tags, or as for tlv_tree_reader_visit().
 * @return Any other error of tlv_tree_reader_visit().
 *
 * @see tlv_schema_diagnostic_t
 */
TLV_API tlv_result_t tlv_schema_validate_all_diag(const uint8_t* data, size_t size,
                                                  const tlv_format_t* format,
                                                  const tlv_structure_schema_t* schema,
                                                  size_t max_depth, size_t max_elements,
                                                  tlv_schema_unknown_policy_t unknown,
                                                  tlv_schema_diagnostic_report_t* report,
                                                  size_t* error_offset);
#endif

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* OPENTLV_SCHEMA_H */
