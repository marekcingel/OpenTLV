# ASN.1 DER-TLV

Include `tlv/profiles/der.h` for allocation-free DER-TLV processing. Tags use the existing
`tlv_tag_t` wire-byte representation; values are borrowed `tlv_value_t` ranges.
The caller owns input and output storage. Existing BER behavior is unchanged.

## Supported scope

The implementation enforces the identifier and length rules in
[ITU-T X.690](https://www.itu.int/rec/T-REC-X.690-202102-I/en), sections 8.1,
10.1 and 10.2. It supports all four ASN.1 classes, primitive and constructed
tags, low and high tag numbers, and definite short and long lengths.

Validation rejects indefinite lengths, redundant length octets, long lengths
below 128, zero initial high-tag digits, high-tag form for numbers below 31,
and malformed or truncated fields. Universal tag 0 (end-of-contents) and
reserved tag 15 are rejected. Universal EXTERNAL (8), EMBEDDED PDV (11),
SEQUENCE/SEQUENCE OF (16), SET/SET OF (17), and CHARACTER STRING (29) must be
constructed. Other assigned universal tags through 36 must be primitive,
including BIT STRING, OCTET STRING and restricted character strings. Unknown
universal tags retain their primitive/constructed bit without type validation.
Application, context-specific and private tags permit either form.

This is a **TLV-layer validator, not a complete ASN.1 DER validator**. Primitive
contents are opaque by default: BOOLEAN representations, INTEGER minimality, BIT
STRING padding, OID components and string/time/REAL encodings are only checked
by the `_strict` functions described below. Schema constraints, implicit/explicit
tagging, CHOICE resolution, DEFAULT omission and SET/SET OF ordering are still
outside this scope: use [`tlv/profiles/der_schema.h`](#schema-aware-validation-and-encoding)
when those are required. Callers must supply canonical ASN.1 contents and
ordering when full DER conformance is required beyond what `_strict` (or the
schema-aware layer) covers. The encoder preserves contents and child order; it
does not convert arbitrary BER or repair noncanonical input.

## Read and inspect a tag

```c
#include "tlv/profiles/der.h"

const uint8_t input[] = {0x30, 3, 0x02, 1, 42};
tlv_view_t view;
size_t consumed, error_offset;
tlv_result_t rc = tlv_der_read(input, sizeof(input), NULL,
                              &view, &consumed, &error_offset);
if (rc == TLV_OK) {
    tlv_asn1_class_t cls = tlv_der_tag_class(&view.tag); /* UNIVERSAL */
    int constructed = tlv_der_tag_is_constructed(&view.tag); /* 1 */
    uint64_t number;
    rc = tlv_der_tag_number(&view.tag, &number); /* 16 */
    (void)cls;
    (void)constructed;
}
```

`tlv_der_read` validates one element and all of its descendants before returning
its view and complete encoded size. Trailing input is ignored. Empty input
returns `TLV_ERR_END_OF_BUFFER`. View and consumed outputs are required and
remain unchanged on failure. Keep the input alive while using returned views.

Class and constructed accessors require a valid DER tag. `tlv_der_tag_number`
validates a tag and extracts a `uint64_t`; larger numbers return
`TLV_ERR_INVALID_TAG` without changing the output. Raw parsing accepts tags up
to `TLV_TAG_CAPACITY` (default 8 bytes, configurable from 1 to 255 consistently
across library and consumers), including numbers larger than `uint64_t`.
`tlv_der_tag_make(class, constructed, number, &tag)` creates minimal wire bytes
from a `uint64_t`, rejects invalid universal forms or insufficient tag capacity,
and leaves the output unchanged on failure. Empty tags and insufficient tag
capacity return `TLV_ERR_INVALID_TAG_SIZE`; invalid encodings return
`TLV_ERR_INVALID_TAG`. `constructed` must be 0 or 1.

## Traverse and limit work

`tlv_der_walk(data, size, limits, visitor, context, &error_offset)` processes all
concatenated elements in preorder, including nested constructed values. A NULL
visitor performs validation only. Empty input succeeds. Each callback receives
a temporary view, its depth (top-level is zero), and its absolute tag offset.
Return `TLV_VISIT_CONTINUE`, `TLV_VISIT_STOP` (successful early termination), or
`TLV_VISIT_ERROR` (returns `TLV_ERR_VISITOR`). Other callback results also return
`TLV_ERR_VISITOR`. Stopping does not validate the remaining input. Callback
effects from earlier elements persist if later validation fails.

All DER operations accept NULL limits for `tlv_der_default_limits`:

| Field | Default | Meaning |
| --- | --- | --- |
| `max_depth` | 32 | Maximum constructed ancestors of an element |
| `max_input_size` | 16 MiB | Supplied read/walk buffer or complete encoded output |
| `max_value_size` | 16 MiB | Value length of each element |
| `max_elements` | 100,000 | Total elements, including the root and descendants |

Copy the default struct and change individual fields to customize limits. All
limits are inclusive, and zero is a real limit. A depth of zero allows only
top-level elements (including empty constructed values). `max_depth` must not
exceed `TLV_DER_MAX_DEPTH` (64); invalid configurations and exceeded limits
return `TLV_ERR_LIMIT`. Traversal uses a fixed array of 65 offsets, no heap
allocations and no C recursion. Work is linear in visited framing bytes and
element count; primitive value bytes are not scanned.

## Encode

```c
tlv_tag_t tag;
const uint8_t children[] = {0x02, 1, 42};
uint8_t output[5];
size_t required, written, error_offset;
tlv_result_t rc = tlv_der_tag_make(TLV_ASN1_UNIVERSAL, 1, 16, &tag);
if (rc == TLV_OK)
    rc = tlv_der_write(NULL, 0, tag, children, sizeof(children), NULL,
                       &required, &error_offset);
if (rc == TLV_OK && required <= sizeof(output))
    rc = tlv_der_write(output, sizeof(output), tag, children, sizeof(children),
                       NULL, &written, &error_offset);
/* Success: output contains 30 03 02 01 2A. */
```

Build nested values from the inside out in caller-owned buffers.
`tlv_der_write` validates the supplied tag and all constructed descendants
before writing. Tags must already be minimal; lengths are always emitted in
their shortest definite form. Primitive contents are copied verbatim. Parsing
and encoding accepted input preserves the element byte-for-byte and gives
deterministic output within the supported TLV scope.

NULL output with zero capacity is a validating size query. A NULL value is valid
only for zero length. Otherwise the source value must not overlap the complete
destination element. Failures leave destination bytes and `written` unchanged.
Insufficient capacity returns `TLV_ERR_BUFFER_TOO_SHORT`. Encoded size overflow
returns `TLV_ERR_INVALID_LENGTH`.

## Strict universal value validation

`tlv_der_read_strict`, `tlv_der_walk_strict` and `tlv_der_write_strict` are drop-in
counterparts of `tlv_der_read`, `tlv_der_walk` and `tlv_der_write`: identical
signatures, offsets and resource limits, but every UNIVERSAL-class **primitive**
element they encounter (including nested ones, and the top-level element given
to `tlv_der_write_strict`) additionally has its content checked against ASN.1
DER canonical rules. Non-UNIVERSAL classes and constructed values (SEQUENCE,
SET, EXTERNAL, EMBEDDED PDV, CHARACTER STRING) are unaffected: their contents
are validated structurally only, exactly as with the non-strict functions.
`tlv_der_read`, `tlv_der_walk` and `tlv_der_write` themselves are unchanged.

Recognized types with invalid or noncanonical content return
`TLV_ERR_INVALID_VALUE`. A UNIVERSAL primitive tag number without an
implemented rule returns `TLV_ERR_UNSUPPORTED_TYPE` instead of silently
passing, so callers can tell "checked and canonical" apart from "not checked".

| Group | Supported types |
| --- | --- |
| Simple | BOOLEAN, INTEGER, BIT STRING, OCTET STRING (unconstrained), NULL, OBJECT IDENTIFIER, RELATIVE-OID, REAL, ENUMERATED |
| String | UTF8String, NumericString, PrintableString, IA5String, VisibleString, UniversalString, BMPString |
| Date/time | UTCTime, GeneralizedTime |

UTCTime/GeneralizedTime checks are structural (digit patterns, mandatory `Z`,
canonical fraction rules, and range checks such as month 01-12 or day 01-31);
they do not perform full Gregorian calendar validation (e.g. do not detect
"30 February"). Structured types (SEQUENCE, SET, EXTERNAL, EMBEDDED PDV,
CHARACTER STRING) have no additional value semantics in this scope, and
CHOICE/ANY have no wire tag of their own, so neither applies here.

Recognized but explicitly unsupported (return `TLV_ERR_UNSUPPORTED_TYPE` in
strict mode rather than being silently accepted): ObjectDescriptor,
TeletexString, VideotexString, GraphicString, GeneralString, TIME, DATE,
TIME-OF-DAY, DATE-TIME, DURATION, OID-IRI, RELATIVE-OID-IRI, and any
UNIVERSAL primitive tag number beyond 36.

## Schema-aware validation and encoding

Include `tlv/profiles/der_schema.h` when canonical rules depend on ASN.1 type
information that raw TLV structure alone cannot express: distinguishing SET
from SET OF, validating implicitly tagged content against its underlying
type, checking explicit-tag wrapper structure, resolving CHOICE alternatives,
and enforcing REQUIRED/OPTIONAL/DEFAULT components (including DEFAULT
omission). This is a fixed, small ASN.1 subset, **not an ASN.1 compiler or an
unrestricted type system**; a schema is a borrowed, immutable, caller-authored
static table, similar in spirit to [`tlv/schemas/schema.h`](../../schemas.md)
but distinct from it: `tlv_structure_schema_t` is format-agnostic and only
expresses occurrence/membership, while `tlv_der_schema_type_t` is ASN.1-
specific and expresses DER canonical semantics. A component's underlying
`type` is always a `tlv_der_schema_type_t`, never the other kind of schema.

Supported type kinds: `TLV_DER_SCHEMA_UNIVERSAL` (a specific universal tag
number, content-validated the same way `_strict` validates it), `SEQUENCE`,
`SET`, `SET_OF`, `CHOICE`, and `ANY` (exactly one well-formed DER-TLV element
with no further ASN.1 semantics; legal untagged only as a direct SEQUENCE
component, since its wildcard tag would make SET/CHOICE/SET-OF matching
ambiguous). Each component of a SEQUENCE/SET/CHOICE, and a SET OF's element,
carries a tagging mode (untagged, `TLV_DER_TAG_IMPLICIT` or
`TLV_DER_TAG_EXPLICIT`, with a class and number for the latter two) and a
presence (`TLV_DER_REQUIRED`, `TLV_DER_OPTIONAL`, or `TLV_DER_DEFAULT` with a
complete canonical encoding to compare against). `tlv_der_schema_check`
validates a hand-authored table's internal consistency once (distinct SET/
CHOICE component tags, CHOICE alternatives required with no default, no
IMPLICIT tagging of a CHOICE or ANY component, and bounds on component count
and type-graph depth); `tlv_der_schema_read`/`tlv_der_schema_write` also
enforce the depth bound live and do not require it to have been called first.

```c
const tlv_der_schema_type_t integer_type = {TLV_DER_SCHEMA_UNIVERSAL, 2};
const tlv_der_schema_type_t octet_string_type = {TLV_DER_SCHEMA_UNIVERSAL, 4};
const tlv_der_schema_component_t set_components[] = {
    {&integer_type, TLV_DER_TAG_NONE, TLV_ASN1_UNIVERSAL, 0, TLV_DER_REQUIRED, NULL, 0},
    {&octet_string_type, TLV_DER_TAG_NONE, TLV_ASN1_UNIVERSAL, 0, TLV_DER_REQUIRED, NULL, 0},
};
const tlv_der_schema_type_t set_type = {TLV_DER_SCHEMA_SET, 0, set_components, 2};

tlv_view_t view;
size_t consumed, error_offset;
tlv_result_t rc = tlv_der_schema_read(data, size, &set_type, NULL,
                                      &view, &consumed, &error_offset);
```

`tlv_der_schema_read` rejects a SET whose components are not encoded in
ascending tag order and a SET OF whose elements are not encoded in ascending
order of their complete encodings (both violations return
`TLV_ERR_INVALID_VALUE`); validating SET/SET OF order needs no extra storage,
since DER canonical order is checked with a single adjacent-pair scan.
`tlv_der_schema_write` produces canonical output regardless of the order its
`tlv_der_schema_encode_fn` callback is invoked in: it sorts SET components by
effective tag (schema-bounded, needing no caller scratch) and SET OF elements
by complete encoding (using the caller-supplied `scratch`/`scratch_capacity`
records), and omits a DEFAULT component whose complete encoding equals its
`default_encoding`. Unlike `tlv_der_write`, it always composes the complete
output in a caller-supplied `scratch_bytes` arena first — needed to compare
and reorder content before committing to it — so `scratch_bytes` and
`scratch_bytes_capacity` are required even for a `NULL`-`data` size query;
size `scratch_bytes_capacity` generously, since composing nested content can
temporarily use more arena space than the final output size.

This API is **unconditionally strict**: there is no permissive mode, so every
UNIVERSAL leaf is content-validated, and unresolved CHOICE tags, unsupported
universal types, and schema self-check failures are always explicit errors
rather than silently accepted.

`tlv_der_schema_limits_t` extends `tlv_der_limits_t` (identical `max_depth`,
`max_input_size`, `max_value_size`, `max_elements` semantics) with
`max_set_elements`, which bounds `tlv_der_schema_write`'s SET OF sort-record
capacity; `tlv_der_schema_default_limits` mirrors `tlv_der_default_limits`.
`TLV_DER_SCHEMA_MAX_TYPE_DEPTH` (32) bounds CHOICE/EXPLICIT resolution
recursion over the schema's own type graph — trusted, caller-authored data,
not attacker input — guarding only against an accidentally self-referential
table. `TLV_DER_SCHEMA_MAX_COMPONENTS` (64) bounds a single SEQUENCE, SET or
CHOICE's direct component count.

Existing `tlv_der_read`/`walk`/`write` (and their `_strict` counterparts) and
the generic `tlv_structure_schema_t` engine are unaffected: this is a purely
additive layer.

## Errors and generic I/O

Optional `error_offset` is changed only on failure. It identifies the **start of
the failing field**, relative to the supplied input (or would-be encoded output):
tag errors point to the tag, length errors to the length prefix, and truncated
values to their value start. This includes missing fields at the end of input.
Value-size limits point to the length field; depth/count limits point to the
first disallowed element. Argument, configuration, total-size and destination
capacity errors use offset zero. Nested offsets remain absolute. Truncated
children cannot consume bytes beyond their parent's declared value boundary.

`tlv_reader_format_der` and `tlv_writer_format_der` also work with generic C and
C++ readers and writers, respectively. These descriptors
validates **only the current tag and length**. Generic I/O does not inspect
constructed contents, apply DER resource limits, or provide field offsets.
Use the DER-specific functions above when those guarantees are required.
