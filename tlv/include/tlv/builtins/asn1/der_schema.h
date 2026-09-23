#ifndef OPENTLV_BUILTINS_ASN1_DER_SCHEMA_H
#define OPENTLV_BUILTINS_ASN1_DER_SCHEMA_H

#include "tlv/error.h"
#include "tlv/builtins/asn1/der_profile.h"
#include "tlv/builtins/asn1/der.h"
#include "tlv/view.h"
#include "tlv/export.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup schemas
 * @brief Schema-aware ASN.1 DER validation and encoding.
 *
 * A small, fixed subset of ASN.1 (SEQUENCE, SET, SET OF, CHOICE, UNIVERSAL
 * leaves, IMPLICIT/EXPLICIT tagging, REQUIRED/OPTIONAL/DEFAULT components,
 * and an unrestricted ANY escape hatch), layered on top of
 * tlv/builtins/asn1/der_profile.h to enforce canonical rules raw TLV structure alone
 * cannot express: SET vs SET OF ordering, underlying-type validation of
 * implicitly tagged content, explicit-tag wrapper structure, CHOICE
 * resolution and DEFAULT-value omission.
 *
 * This is not an ASN.1 compiler or an unrestricted type system. Schemas are
 * borrowed, immutable, caller-authored static tables (as with
 * tlv/schema/schema.h's #tlv_structure_schema_t, which this module does not
 * use or extend: that type is format-agnostic and has no ASN.1 semantics).
 * Every entry point here is unconditionally as strict as
 * tlv_der_read_strict(): there is no permissive mode, so unresolved CHOICE
 * tags, unsupported universal types and inconsistent schemas are always
 * explicit errors. No allocation and no unbounded C recursion are used.
 */

/** @addtogroup schemas
 * @{
 */

/**
 * @brief Kind of an ASN.1 type expression in a #tlv_der_schema_type_t.
 *
 * Leaf UNIVERSAL types are validated by content against the canonical DER
 * rules, as in tlv_der_read_strict(); SEQUENCE, SET and CHOICE list
 * components; SET OF repeats one element type.
 */
typedef enum tlv_der_schema_kind {
    /** A UNIVERSAL leaf, validated by content. */
    TLV_DER_SCHEMA_UNIVERSAL = 0,
    /** SEQUENCE: components in schema order. */
    TLV_DER_SCHEMA_SEQUENCE,
    /** SET: components in canonical tag order. */
    TLV_DER_SCHEMA_SET,
    /** SET OF: repeats one element type, ordered by complete encoding. */
    TLV_DER_SCHEMA_SET_OF,
    /** CHOICE: exactly one of the listed alternatives. */
    TLV_DER_SCHEMA_CHOICE,
    /**
     * ANY: accepts exactly one well-formed DER-TLV element (recursively, for
     * constructed content) without further ASN.1 semantics. Legal only as a
     * direct SEQUENCE component, because its wildcard tag would make
     * SET/CHOICE/SET-OF matching ambiguous.
     */
    TLV_DER_SCHEMA_ANY
} tlv_der_schema_kind_t;

/**
 * @brief How a component's identifier relates to its underlying type's own.
 *
 * IMPLICIT is invalid on a CHOICE-typed component, because CHOICE has no
 * natural tag to replace; use EXPLICIT. tlv_der_schema_check() rejects it.
 */
typedef enum tlv_der_tagging_mode {
    /** Keeps the underlying type's own natural wire identifier. */
    TLV_DER_TAG_NONE = 0,
    /**
     * Replaces the natural identifier with (`tag_class`, `tag_number`),
     * validating content against the underlying type directly.
     */
    TLV_DER_TAG_IMPLICIT,
    /**
     * Wraps the underlying type's own complete, natural encoding as the value
     * of an outer constructed (`tag_class`, `tag_number`).
     */
    TLV_DER_TAG_EXPLICIT
} tlv_der_tagging_mode_t;

/**
 * @brief Whether a component must appear.
 *
 * DER requires a DEFAULT component to be absent whenever its encoded value
 * would equal `default_encoding`: parsing rejects an explicit encoding equal
 * to the default, and encoding omits it.
 */
typedef enum tlv_der_presence {
    /** The component must be present exactly once. */
    TLV_DER_REQUIRED = 0,
    /** The component may be absent. */
    TLV_DER_OPTIONAL,
    /** The component may be absent and has a default value. */
    TLV_DER_DEFAULT
} tlv_der_presence_t;

/** @brief An ASN.1 type expression; see the struct definition below. */
typedef struct tlv_der_schema_type tlv_der_schema_type_t;

/**
 * @brief One component of a SEQUENCE, SET or CHOICE, or the repeated element of a SET OF.
 *
 * All pointers are borrowed and must outlive use. CHOICE alternatives must
 * have presence #TLV_DER_REQUIRED and no default (enforced by
 * tlv_der_schema_check()).
 */
typedef struct tlv_der_schema_component {
    /** Component type; borrowed and must outlive use. */
    const tlv_der_schema_type_t* type;
    /** Tagging mode applied to the component. */
    tlv_der_tagging_mode_t tagging;
    /** Tag class for IMPLICIT or EXPLICIT tagging. */
    tlv_asn1_class_t tag_class;
    /** Tag number for IMPLICIT or EXPLICIT tagging. */
    uint64_t tag_number;
    /** Presence requirement. */
    tlv_der_presence_t presence;
    /**
     * For #TLV_DER_DEFAULT, the complete canonical DER-TLV encoding (tag,
     * length and value) this component's own effective identifier would
     * produce for the default value. Borrowed; must remain constant.
     */
    const uint8_t* default_encoding;
    /** Length of `default_encoding` in bytes. */
    size_t default_encoding_length;
} tlv_der_schema_component_t;

/**
 * @brief An ASN.1 type expression.
 *
 * `components` and `component_count` apply to SEQUENCE, SET and CHOICE (at
 * most #TLV_DER_SCHEMA_MAX_COMPONENTS direct components). `element` applies
 * to SET OF, with `min_elements` and `max_elements` (inclusive, `SIZE_MAX`
 * for unbounded) bounding its element count. `universal_number` applies to
 * #TLV_DER_SCHEMA_UNIVERSAL leaves. Fields unused by a given kind are
 * ignored. All pointers are borrowed and must outlive use.
 */
struct tlv_der_schema_type {
    /** Kind of type expression. */
    tlv_der_schema_kind_t kind;
    /** UNIVERSAL tag number of a #TLV_DER_SCHEMA_UNIVERSAL leaf. */
    uint64_t universal_number;
    /** Components of a SEQUENCE, SET or CHOICE. */
    const tlv_der_schema_component_t* components;
    /** Number of entries in `components`. */
    size_t component_count;
    /** Repeated element of a SET OF. */
    const tlv_der_schema_component_t* element;
    /** Minimum SET OF element count, inclusive. */
    size_t min_elements;
    /** Maximum SET OF element count, inclusive; `SIZE_MAX` is unbounded. */
    size_t max_elements;
};

/**
 * @brief Bound on schema type-graph recursion while resolving a single wire position.
 *
 * Covers CHOICE alternatives and EXPLICIT unwrapping. Schemas are trusted,
 * caller-authored static data, not attacker input; this only guards against
 * an accidentally self-referential table.
 */
enum { TLV_DER_SCHEMA_MAX_TYPE_DEPTH = 32 };

/**
 * @brief Maximum direct components of one SEQUENCE, SET or CHOICE.
 *
 * Presence is tracked with a 64-bit bitmap.
 */
enum { TLV_DER_SCHEMA_MAX_COMPONENTS = 64 };

/** @brief Resource limits for schema-aware DER reading and writing. */
typedef struct tlv_der_schema_limits {
    /**
     * Depth, input size, value size and total visited element count, with
     * the semantics of #tlv_der_limits_t.
     */
    tlv_der_limits_t base;
    /**
     * Bounds the scratch record capacity tlv_der_schema_write() needs to
     * sort one SET OF's elements by their complete encodings. Not used by
     * tlv_der_schema_read(), which validates SET/SET OF order with a single
     * adjacent-pair scan and needs no scratch storage.
     */
    size_t max_set_elements;
} tlv_der_schema_limits_t;

/** @brief Default limits used when a function receives `NULL` limits. */
extern TLV_API const tlv_der_schema_limits_t tlv_der_schema_default_limits;

/**
 * @brief One-time structural self-check of a schema table.
 *
 * Verifies distinct effective identifiers among a SET's or CHOICE's direct
 * components; that CHOICE alternatives are #TLV_DER_REQUIRED with no default;
 * that no CHOICE-typed component uses IMPLICIT tagging; that `component_count`
 * is within #TLV_DER_SCHEMA_MAX_COMPONENTS; and that type-graph depth is
 * within #TLV_DER_SCHEMA_MAX_TYPE_DEPTH.
 *
 * Intended to validate a hand-authored table once (for example in a unit
 * test). tlv_der_schema_read() and tlv_der_schema_write() already enforce the
 * depth bound live and do not require this to have been called first.
 *
 * @param[in]  root         Root type to check.
 * @param[out] error_offset Optional. When set, always 0: the offset is
 *                          schema-relative, not input-relative.
 *
 * @return #TLV_OK if the schema is consistent.
 * @return #TLV_ERR_SCHEMA or another error code describing the inconsistency.
 */
TLV_API tlv_result_t tlv_der_schema_check(const tlv_der_schema_type_t* root, size_t* error_offset);

/**
 * @brief Validates encoded data against a schema.
 *
 * Reports the single complete element consumed, with the same zero-copy,
 * `error_offset` and limit conventions as tlv_der_read_strict(). Every
 * UNIVERSAL leaf is content-validated; SET and SET OF wire order is
 * checked; DEFAULT-equal components are rejected.
 *
 * @param[in]  data         Encoded input.
 * @param[in]  size         Input size in bytes.
 * @param[in]  root         Root schema type.
 * @param[in]  limits       Limits, or `NULL` for #tlv_der_schema_default_limits.
 * @param[out] view         Receives the element; its value borrows `data`.
 * @param[out] consumed     Receives the encoded size of the element.
 * @param[out] error_offset Optional. Offset of the failure, as for tlv_der_read_strict().
 *
 * @return #TLV_OK if the data conforms.
 * @return #TLV_ERR_SCHEMA and related codes for schema violations.
 * @return Any error of tlv_der_read_strict().
 *
 * @warning The caller must keep `data` alive while `view` is used.
 */
TLV_API tlv_result_t tlv_der_schema_read(const uint8_t* data, size_t size,
                                         const tlv_der_schema_type_t* root,
                                         const tlv_der_schema_limits_t* limits, tlv_view_t* view,
                                         size_t* consumed, size_t* error_offset);

/**
 * @brief Callback supplying one component's raw inner content for tlv_der_schema_write().
 *
 * Supplies the content of one component, CHOICE alternative or SET OF
 * element: the bytes that belong inside its own effective tag and length,
 * before any IMPLICIT/EXPLICIT wrapping that tlv_der_schema_write() applies.
 * Content is requested only for a #TLV_DER_SCHEMA_UNIVERSAL or
 * #TLV_DER_SCHEMA_ANY component.
 *
 * For every component, whatever its underlying kind, the callback is first
 * called with `NULL` data purely to learn presence through `*absent`. This
 * lets an OPTIONAL or DEFAULT component, a CHOICE alternative, or (reusing
 * the same signal to mean "no more elements") a SET OF's next element report
 * absence without producing bytes. `*absent` is 0 on entry; the callback
 * sets it nonzero and returns #TLV_OK to report absence, in which case
 * `data`, `capacity` and `written` are ignored.
 *
 * Once presence is confirmed for a UNIVERSAL or ANY component, the callback
 * is called again with `NULL` data and zero capacity to size the content (as
 * with #tlv_codec_t), then once more with a real buffer to produce it.
 *
 * All calls for one (component, index) pair within one
 * tlv_der_schema_write() call must report the same presence and, when
 * present, the same content.
 *
 * @param[in]  context   Caller context passed to tlv_der_schema_write().
 * @param[in]  component Component whose content is requested.
 * @param[in]  index     0 for a SEQUENCE, SET or CHOICE component; 0, 1, 2, ...
 *                       for successive SET OF elements. Iteration stops at
 *                       the first index reporting absent, so real elements
 *                       must be reported present at every lower index.
 * @param[out] data      Destination, or `NULL` for a presence or size query.
 * @param[in]  capacity  Destination capacity in bytes.
 * @param[out] written   Receives the content size.
 * @param[out] absent    Set nonzero to report absence.
 *
 * @return #TLV_OK on success (including reporting absence), or an error
 *         code that propagates unchanged.
 *
 * @note A #TLV_DER_REQUIRED component, or an element below a SET OF's
 *       `min_elements`, reporting absent is a caller/schema mismatch
 *       (#TLV_ERR_SCHEMA).
 */
typedef tlv_result_t (*tlv_der_schema_encode_fn)(const void* context,
                                                 const tlv_der_schema_component_t* component,
                                                 size_t index, uint8_t* data, size_t capacity,
                                                 size_t* written, int* absent);

/**
 * @brief An `{offset, length}` byte range within the `scratch_bytes` arena.
 *
 * tlv_der_schema_write() uses these records to compose and sort SET and
 * SET OF content.
 */
typedef struct tlv_der_schema_record {
    /** Offset of the range within the scratch byte arena. */
    size_t offset;
    /** Length of the range in bytes. */
    size_t length;
} tlv_der_schema_record_t;

/**
 * @brief Encodes a schema's canonical DER-TLV bytes.
 *
 * Invokes `encode` for each UNIVERSAL or ANY component's or SET OF element's
 * content, and for every component's presence. The engine chooses component
 * order (sorting SET components by effective tag, and SET OF elements by
 * complete encoding), applies IMPLICIT/EXPLICIT wrapping, and omits a
 * DEFAULT component whose complete encoding equals its `default_encoding`.
 *
 * Unlike tlv_der_write(), this always composes the complete output in
 * `scratch_bytes` first, and only then copies it to `data`. That arena is
 * bump-allocated by the engine and is needed to compare and reorder SET OF
 * elements' complete encodings, and to compare DEFAULT components against
 * their `default_encoding` before omitting or keeping them. Its capacity
 * must be large enough for the complete composed output, which can
 * temporarily exceed the final size by a factor proportional to nesting
 * depth, because each SEQUENCE, SET, CHOICE or EXPLICIT layer concatenates
 * its already complete children into a new region rather than mutating them
 * in place.
 *
 * `scratch_bytes` and `scratch_bytes_capacity` are required even for a
 * `NULL`-`data` size query, and are still fully used then. `scratch` and
 * `scratch_capacity` are the SET OF sort's own record storage
 * (#tlv_der_schema_limits_t::max_set_elements bounds how many are needed);
 * both may be `NULL`/0 only for a schema with no SET OF.
 *
 * @param[out] data             Destination. `NULL` with zero `capacity` queries
 *                              the size that would be written.
 * @param[in]  capacity         Destination capacity in bytes.
 * @param[in]  root             Root schema type.
 * @param[in]  encode           Callback supplying component content and presence.
 * @param[in]  context          Passed to `encode` unchanged.
 * @param[in]  limits           Limits, or `NULL` for #tlv_der_schema_default_limits.
 * @param[out] scratch_bytes    Byte arena for composing output. Required.
 * @param[in]  scratch_bytes_capacity Capacity of `scratch_bytes` in bytes.
 * @param[out] scratch          SET OF sort records; `NULL` only for a schema
 *                              with no SET OF.
 * @param[in]  scratch_capacity Number of records in `scratch`.
 * @param[out] written          Receives the encoded (or required) size.
 * @param[out] error_offset     Optional. Offset of the failure, using the
 *                              would-be-output conventions of tlv_der_write().
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_SCHEMA for a schema violation, including a missing
 *         #TLV_DER_REQUIRED component; this fails deterministically without
 *         partial output.
 * @return #TLV_ERR_BUFFER_TOO_SHORT if `capacity` or a scratch buffer is insufficient.
 * @return Any callback error, propagated unchanged.
 *
 * @note All outputs remain unchanged on error.
 */
TLV_API tlv_result_t tlv_der_schema_write(uint8_t* data, size_t capacity,
                                          const tlv_der_schema_type_t* root,
                                          tlv_der_schema_encode_fn encode, const void* context,
                                          const tlv_der_schema_limits_t* limits,
                                          uint8_t* scratch_bytes, size_t scratch_bytes_capacity,
                                          tlv_der_schema_record_t* scratch, size_t scratch_capacity,
                                          size_t* written, size_t* error_offset);

#ifdef __cplusplus
}
#endif
/** @} */

#endif /* OPENTLV_BUILTINS_ASN1_DER_SCHEMA_H */
