#ifndef OPENTLV_DER_SCHEMA_H
#define OPENTLV_DER_SCHEMA_H

#include "tlv/profiles/der.h"
#include "tlv/formats/asn1/der.h"
#include "tlv/view.h"
#include "tlv/export.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Schema-aware ASN.1 DER validation and encoding: a small, fixed subset of
 * ASN.1 (SEQUENCE, SET, SET OF, CHOICE, UNIVERSAL leaves, IMPLICIT/EXPLICIT
 * tagging, REQUIRED/OPTIONAL/DEFAULT components, and an unrestricted ANY
 * escape hatch), layered on top of tlv/profiles/der.h to enforce canonical
 * rules raw TLV structure alone cannot express: SET vs SET OF ordering,
 * underlying-type validation of implicitly tagged content, explicit-tag
 * wrapper structure, CHOICE resolution and DEFAULT-value omission.
 *
 * This is not an ASN.1 compiler or an unrestricted type system: schemas are
 * borrowed, immutable, caller-authored static tables (as with
 * tlv/schemas/schema.h's tlv_structure_schema_t, which this module does not
 * use or extend -- that type is format-agnostic and has no ASN.1 semantics).
 * Every entry point here is unconditionally as strict as tlv_der_read_strict:
 * there is no permissive mode, so unresolved CHOICE tags, unsupported
 * universal types and inconsistent schemas are always explicit errors.
 * No allocation and no unbounded C recursion are used.
 */

/* An ASN.1 type expression. Leaf UNIVERSAL types are validated by content
 * (tlv_der_validate_universal_value); SEQUENCE/SET/CHOICE list components;
 * SET OF repeats one element type. ANY accepts exactly one well-formed
 * DER-TLV element (recursively, for constructed content) without further
 * ASN.1 semantics, and is legal only as a direct SEQUENCE component (its
 * wildcard tag would make SET/CHOICE/SET-OF matching ambiguous). */
typedef enum tlv_der_schema_kind {
    TLV_DER_SCHEMA_UNIVERSAL = 0,
    TLV_DER_SCHEMA_SEQUENCE,
    TLV_DER_SCHEMA_SET,
    TLV_DER_SCHEMA_SET_OF,
    TLV_DER_SCHEMA_CHOICE,
    TLV_DER_SCHEMA_ANY
} tlv_der_schema_kind_t;

/* NONE keeps the underlying type's own natural wire identifier. IMPLICIT
 * replaces it with (tag_class, tag_number), validating content against the
 * underlying type directly. EXPLICIT wraps the underlying type's own
 * complete, natural encoding as the value of an outer constructed
 * (tag_class, tag_number). IMPLICIT is invalid on a CHOICE-typed component
 * (CHOICE has no natural tag to replace; use EXPLICIT), rejected by
 * tlv_der_schema_check. */
typedef enum tlv_der_tagging_mode {
    TLV_DER_TAG_NONE = 0,
    TLV_DER_TAG_IMPLICIT,
    TLV_DER_TAG_EXPLICIT
} tlv_der_tagging_mode_t;

/* REQUIRED components must be present exactly once. OPTIONAL components may
 * be absent. DEFAULT components may be absent, and DER requires them to be
 * absent whenever their encoded value would equal default_encoding: parsing
 * rejects an explicit encoding equal to the default, and encoding omits it. */
typedef enum tlv_der_presence {
    TLV_DER_REQUIRED = 0,
    TLV_DER_OPTIONAL,
    TLV_DER_DEFAULT
} tlv_der_presence_t;

typedef struct tlv_der_schema_type tlv_der_schema_type_t;

/* One component of a SEQUENCE/SET/CHOICE, or the repeated element of a
 * SET OF. type is borrowed and must outlive use. default_encoding, when
 * presence is TLV_DER_DEFAULT, is the complete canonical DER-TLV encoding
 * (tag, length and value) this component's own effective identifier would
 * produce for the default value; it is borrowed and must remain constant.
 * CHOICE alternatives must have presence TLV_DER_REQUIRED and no default
 * (enforced by tlv_der_schema_check). */
typedef struct tlv_der_schema_component {
    const tlv_der_schema_type_t* type;
    tlv_der_tagging_mode_t tagging;
    tlv_asn1_class_t tag_class;
    uint64_t tag_number;
    tlv_der_presence_t presence;
    const uint8_t* default_encoding;
    size_t default_encoding_length;
} tlv_der_schema_component_t;

/* components/component_count apply to SEQUENCE, SET and CHOICE (at most 64
 * direct components: presence is tracked with a 64-bit bitmap). element
 * applies to SET OF; min_elements/max_elements (inclusive, SIZE_MAX for
 * unbounded) bound its element count. universal_number applies to
 * TLV_DER_SCHEMA_UNIVERSAL leaves. Unused fields for a given kind are
 * ignored. All pointers are borrowed and must outlive use. */
struct tlv_der_schema_type {
    tlv_der_schema_kind_t kind;
    uint64_t universal_number;
    const tlv_der_schema_component_t* components;
    size_t component_count;
    const tlv_der_schema_component_t* element;
    size_t min_elements;
    size_t max_elements;
};

/* Bounds schema type-graph recursion (CHOICE alternatives, EXPLICIT
 * unwrapping) while resolving a single wire position. Schemas are trusted,
 * caller-authored static data, not attacker input; this only guards against
 * an accidentally self-referential table. */
enum { TLV_DER_SCHEMA_MAX_TYPE_DEPTH = 32 };

/* Maximum direct components of one SEQUENCE, SET or CHOICE (presence is
 * tracked with a 64-bit bitmap). */
enum { TLV_DER_SCHEMA_MAX_COMPONENTS = 64 };

typedef struct tlv_der_schema_limits {
    /* Reused from tlv/profiles/der.h: depth, input size, value size and
     * total visited element count, with identical semantics. */
    tlv_der_limits_t base;
    /* Bounds the scratch record capacity tlv_der_schema_write needs to sort
     * one SET OF's elements by their complete encodings. Not used by
     * tlv_der_schema_read, which validates SET/SET OF order with a single
     * adjacent-pair scan and needs no scratch storage. */
    size_t max_set_elements;
} tlv_der_schema_limits_t;
extern TLV_API const tlv_der_schema_limits_t tlv_der_schema_default_limits;

/* One-time structural self-check of a schema table: distinct effective
 * identifiers among a SET's or CHOICE's direct components; CHOICE
 * alternatives are TLV_DER_REQUIRED with no default; no IMPLICIT tagging of
 * a CHOICE-typed component; component_count within
 * TLV_DER_SCHEMA_MAX_COMPONENTS; type-graph depth within
 * TLV_DER_SCHEMA_MAX_TYPE_DEPTH. Intended to validate a hand-authored table
 * once (e.g. in a unit test); tlv_der_schema_read/write already enforce the
 * depth bound live and do not require this to have been called first.
 * error_offset, when set, is always 0 (schema-relative, not input-relative). */
TLV_API tlv_result_t tlv_der_schema_check(const tlv_der_schema_type_t* root, size_t* error_offset);

/* Validates data against root and reports the single complete element
 * consumed, with the same zero-copy, error_offset and limit conventions as
 * tlv_der_read_strict. Every UNIVERSAL leaf is content-validated; SET and
 * SET OF wire order is checked; DEFAULT-equal components are rejected.
 * limits may be NULL to select tlv_der_schema_default_limits. */
TLV_API tlv_result_t tlv_der_schema_read(const uint8_t* data, size_t size,
                                         const tlv_der_schema_type_t* root,
                                         const tlv_der_schema_limits_t* limits, tlv_view_t* view,
                                         size_t* consumed, size_t* error_offset);

/* Supplies one component's, CHOICE alternative's, or SET OF element's raw
 * inner content: the bytes that belong inside this component's own
 * effective tag/length, before any IMPLICIT/EXPLICIT wrapping
 * tlv_der_schema_write applies. Called only for a TLV_DER_SCHEMA_UNIVERSAL
 * or TLV_DER_SCHEMA_ANY component's content, and, for every component
 * (whatever its underlying kind), first with NULL data purely to learn
 * presence via *absent -- this lets an OPTIONAL/DEFAULT component, a CHOICE
 * alternative, or (reusing the same signal to mean "no more elements") a
 * SET OF's next element report absence without producing bytes. *absent is
 * 0 on entry; the callback sets it to nonzero and returns TLV_OK to report
 * absence, in which case data/capacity/written are ignored. index is 0 for
 * a SEQUENCE/SET/CHOICE component and 0, 1, 2, ... for successive SET OF
 * elements (iteration stops at the first index reporting absent, so real
 * elements must be reported present at every index below that). A
 * TLV_DER_REQUIRED component or an element below a SET OF's min_elements
 * reporting absent is a caller/schema mismatch (TLV_ERR_SCHEMA). Once
 * presence is confirmed for a UNIVERSAL/ANY component, the callback is
 * called again with NULL data and zero capacity to size the content (as
 * with tlv_codec_t), then once more with a real buffer to produce it; all
 * calls for one (component, index) pair within one tlv_der_schema_write
 * call must report the same presence and, when present, the same content. */
typedef tlv_result_t (*tlv_der_schema_encode_fn)(const void* context,
                                                 const tlv_der_schema_component_t* component,
                                                 size_t index, uint8_t* data, size_t capacity,
                                                 size_t* written, int* absent);

/* Indexes a {offset, length} byte range within the scratch_bytes arena
 * tlv_der_schema_write uses to compose and sort SET/SET-OF content. */
typedef struct tlv_der_schema_record {
    size_t offset;
    size_t length;
} tlv_der_schema_record_t;

/* Encodes root's canonical DER-TLV bytes, invoking encode for each
 * UNIVERSAL/ANY component's or SET OF element's content and for every
 * component's presence. The engine chooses component order (sorting SET
 * components by effective tag, a schema-bounded operation, and SET OF
 * elements by complete encoding), applies IMPLICIT/EXPLICIT wrapping, and
 * omits a DEFAULT component whose complete encoding equals its
 * default_encoding.
 *
 * Unlike tlv_der_write, this always composes the complete output in
 * scratch_bytes first (an arena the engine bump-allocates from, needed to
 * compare and reorder SET OF elements' complete encodings and to compare
 * DEFAULT components against their default_encoding before committing to
 * omitting or keeping them) and only then copies it to data; scratch_bytes
 * and scratch_bytes_capacity are required even for a NULL-data size query,
 * and scratch_bytes_capacity must be large enough for the complete
 * composed output, which can temporarily exceed the final size by a factor
 * proportional to nesting depth (each SEQUENCE/SET/CHOICE/EXPLICIT layer
 * concatenates its already-complete children into one new region rather
 * than mutating them in place). scratch/scratch_capacity are the SET OF
 * sort's own {offset,length} record storage (tlv_der_schema_limits_t.
 * max_set_elements bounds how many are needed); both may be NULL/0 only
 * for a schema with no SET OF. data may be NULL with capacity 0 to query
 * the size that would be written, as with tlv_der_write; scratch_bytes and
 * scratch (when needed) are still required and still fully used. All
 * outputs remain unchanged on error, and a missing TLV_DER_REQUIRED
 * component fails deterministically without partial output. limits may be
 * NULL to select tlv_der_schema_default_limits. */
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
#endif /* OPENTLV_DER_SCHEMA_H */
