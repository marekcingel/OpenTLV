# ASN.1 CER-TLV

Include `tlv/profiles/cer.h` for allocation-free CER-TLV processing. Tags use the existing
`tlv_tag_t` wire-byte representation; values are borrowed `tlv_value_t` ranges.
The caller owns input and output storage. CER is a sibling of the
[DER profile](../der/README.md): it reuses the shared BER wire helpers and, through
private helpers, the universal-value content rules ITU-T X.690 §11 documents as common to
both encodings, but neither profile depends on the other. Existing BER, DER and EMV
behavior is unchanged.

## Supported scope

The implementation enforces ITU-T X.690's Canonical Encoding Rules: a constructed
value's length is always indefinite (EOC-terminated); a primitive value's length is
always definite and minimally encoded. BIT STRING, OCTET STRING and the restricted
character string types (including UTF8String) may additionally be constructed, but
only when their logical content exceeds 1,000 octets, in which case they must be
split into canonical segments (see below); a primitive encoding of such a type with
more than 1,000 content octets is rejected, and so is a constructed encoding whose
total content is 1,000 octets or fewer.

This is a **TLV-layer and framing validator, not a complete ASN.1 CER validator**.
Structural validation (`tlv_cer_read`/`tlv_cer_walk`/`tlv_cer_write`) covers framing,
EOC placement, and canonical segmentation — segment tags, forms and sizes — but not
value semantics. Universal value semantics (BOOLEAN representation, INTEGER
minimality, BIT STRING padding, string charsets, and so on) are checked only by the
`_strict` functions described below. Schema constraints, implicit-tag semantics,
DEFAULT omission and SET/SET OF ordering remain outside this scope regardless.

## Read and traverse

```c
#include "tlv/profiles/cer.h"

const uint8_t input[] = {0x30, 0x80, 0x02, 1, 42, 0, 0}; /* SEQUENCE(indefinite){ INTEGER 42 } */
tlv_view_t view;
size_t consumed, error_offset;
tlv_result_t rc = tlv_cer_read(input, sizeof(input), NULL,
                              &view, &consumed, &error_offset);
```

`tlv_cer_read` validates one element and all of its descendants — indefinite
constructed framing, EOC placement, and canonical string segmentation — before
returning its view and complete encoded size. Trailing input is ignored. Empty
input returns `TLV_ERR_END_OF_BUFFER`. Keep the input alive while using returned
views (see [memory ownership](../../guides/memory.md)).

`tlv_cer_walk(data, size, limits, visitor, context, &error_offset)` processes all
concatenated elements, including nested constructed values. A NULL visitor
performs validation only. Empty input succeeds.

Unlike [`tlv_der_visitor_t`](../der/README.md), which visits every element in
preorder, `tlv_cer_visitor_t` is **postorder for constructed elements**: a
primitive element (including each string segment) is visited immediately when
read, but a constructed element's indefinite length is not known until its
matching EOC is found, so it is visited only afterward, once its true span is
known. This keeps traversal a single linear pass with no rescanning. Primitive
leaves have no descendants, so for them this is the same point either way.

All CER operations accept NULL limits for `tlv_cer_default_limits`, the same
shape and defaults as [`tlv_der_limits_t`](../der/README.md#traverse-and-limit-work):
`max_depth` (32), `max_input_size` (16 MiB), `max_value_size` (16 MiB), `max_elements`
(100,000). `max_depth` must not exceed `TLV_CER_MAX_DEPTH` (64). String segments
count toward `max_elements`. `max_value_size` bounds a constructed element's
assembled indefinite content (all its segments/children together, excluding
framing overhead), not per-segment header bytes. Traversal uses a fixed stack, no
heap allocation and no C recursion.

## Canonical string segmentation

For OCTET STRING, a primitive segment containing 1,000 octets has this header:

```text
04 82 03 E8
```

The canonical length field is `82 03 E8`; `03 E8` alone (without the `82` long-form
prefix) is not a valid encoding of length 1,000 — CER requires the same minimal
definite-length encoding DER does.

When logical content exceeds 1,000 octets, it is split into segments: every
non-final segment is exactly 1,000 content octets; the final segment is 1 to 1,000
octets and never empty. An exact multiple of 1,000 (e.g. 2,000 octets) splits
cleanly into that many 1,000-octet segments with no trailing empty segment.
Empty, nested (constructed), or mistagged segments are rejected structurally,
even without strict content validation.

BIT STRING segments carry the unused-bits accounting separately from OCTET STRING:
each segment's first content octet is the unused-bits count (so a non-final
segment has 999 bit octets plus that count octet, still 1,000 total). Every
non-final segment's unused-bits octet must be `00`; only the final segment may
have a nonzero unused-bits count (0-7), with the same trailing zero-padding rule
DER already enforces for an unsegmented BIT STRING.

Character-string segmentation charset checks apply per segment except for
UTF8String, whose multi-byte characters may legally straddle a segment boundary;
strict validation streams UTF8String content across segments with small, fixed
state rather than concatenating them.

## Zero-copy access to segments

A constructed string's segments are just ordinary CER primitive elements one
level below its own view — `view.value` for a constructed CER element already
excludes the outer EOC, the same convention `tlv_read` uses for BER. Iterate
them with the existing generic `tlv_walk`, no dedicated API needed:

```c
tlv_view_t view; /* a constructed OCTET STRING element from tlv_cer_read/_walk */
tlv_visit_result_t print_segment(const tlv_view_t* segment, void* context) {
    /* segment->value borrows the input; print it, hash it, etc. */
    return TLV_VISIT_CONTINUE;
}
size_t length;
tlv_length_to_size(view.value.length, &length);
tlv_walk(view.value.data, length, &tlv_reader_format_cer, print_segment, NULL);
```

`view.value` here is a view of the **encoded constructed contents** (segment
headers included) — distinct from the **logical string data** each segment's own
`value` borrows. This library never concatenates segments into a contiguous
logical value; assembling one from segment views, if needed, is the caller's
responsibility with caller-owned storage.

## Encode

```c
uint8_t tag_bytes[TLV_ASN1_TAG_MAX_SIZE]; /* the tag borrows these bytes */
tlv_tag_t tag;
const uint8_t children[] = {0x02, 1, 42};
uint8_t output[16];
size_t required, written, error_offset;
tlv_result_t rc = tlv_cer_tag_make(TLV_ASN1_UNIVERSAL, 1, 16, tag_bytes, &tag); /* SEQUENCE */
if (rc == TLV_OK)
    rc = tlv_cer_write(NULL, 0, tag, children, sizeof(children), NULL,
                       &required, &error_offset);
if (rc == TLV_OK && required <= sizeof(output))
    rc = tlv_cer_write(output, sizeof(output), tag, children, sizeof(children),
                       NULL, &written, &error_offset);
/* Success: output contains 30 80 02 01 2A 00 00 (indefinite framing + EOC). */
```

`tlv_cer_write` accepts **pre-encoded** child bytes for a constructed tag (without
the enclosing EOC, added automatically) and validates them recursively as
canonical CER framing — including segmentation, when the tag is itself a
segmentable UNIVERSAL type — before writing. For a primitive tag, `value` is raw
content; content longer than 1,000 octets for a segmentable UNIVERSAL type is
rejected even in the non-strict function, since that is a structural defect, not
a content one.

`tlv_cer_write_segmented_string` instead accepts **logical** string content (not
pre-encoded segments) and automatically emits a single primitive element or a
canonical constructed/segmented one, whichever is canonical for that content's
length:

```c
uint8_t content[2500]; /* fill with logical OCTET STRING data */
uint8_t output[2600];
size_t written, error_offset;
uint8_t tag_bytes[TLV_ASN1_TAG_MAX_SIZE];
tlv_tag_t octet_string;
tlv_cer_tag_make(TLV_ASN1_UNIVERSAL, 0, 4, tag_bytes, &octet_string); /* primitive OCTET STRING */
tlv_cer_write_segmented_string(output, sizeof(output), octet_string,
                              content, sizeof(content), NULL, &written, &error_offset);
/* Success: two 1000-octet segments plus a 500-octet final segment. */
```

NULL output with zero capacity is a validating size query for both functions.
Failures leave destination bytes and `written` unchanged. `tlv_cer_write_segmented_string`
always validates content (there is no non-strict variant — its purpose is producing
correct canonical output from logical content, unlike `tlv_cer_write`'s pre-encoded
pass-through). Size arithmetic, including every segment header and the EOC, is
overflow-checked before writing.

## Strict universal value validation

`tlv_cer_read_strict`, `tlv_cer_walk_strict` and `tlv_cer_write_strict` are drop-in
counterparts of `tlv_cer_read`, `tlv_cer_walk` and `tlv_cer_write`: identical
signatures, offsets and resource limits, but every UNIVERSAL-class element they
encounter additionally has its content validated against ASN.1 canonical rules —
including, for a segmented constructed value, every segment, validated as it is
encountered without ever concatenating them.

| Group | Supported types |
| --- | --- |
| Simple | BOOLEAN, INTEGER, BIT STRING, OCTET STRING, NULL, OBJECT IDENTIFIER, RELATIVE-OID, REAL, ENUMERATED |
| String | UTF8String, NumericString, PrintableString, IA5String, VisibleString, UniversalString, BMPString |
| Date/time | UTCTime, GeneralizedTime |

These are exactly the rules ITU-T X.690 §11 documents as common to both CER and
DER, so results agree with [DER's strict validation](../der/README.md#strict-universal-value-validation)
wherever both apply (DER never segments; CER's segment-aware checks are additional).
UTCTime and GeneralizedTime are never eligible for segmentation (always primitive,
definite length), like every other simple type above.

Recognized but explicitly unsupported (return `TLV_ERR_UNSUPPORTED_TYPE` in strict
mode rather than being silently accepted, **including a constructed/segmented
encoding**): ObjectDescriptor, TeletexString, VideotexString, GraphicString,
GeneralString, TIME, DATE, TIME-OF-DAY, DATE-TIME, DURATION, OID-IRI,
RELATIVE-OID-IRI, and any UNIVERSAL primitive tag number beyond 36 — the same set
DER documents, since the underlying content validators are shared.

## Errors, offsets and limits

Optional `error_offset` is changed only on failure, following the same
conventions as DER: it identifies the absolute start of the failing tag, length,
or value field, relative to the supplied input (or would-be encoded output for
writes). A missing EOC is reported at the position where it was expected (the
enclosing element's length field); a truncated or unexpected EOC is reported at
its own position. A segment-level structural or content defect is reported at
the start of the offending segment. Value-size limit failures point to the
length field; depth/count limits point to the first disallowed element.
Argument, configuration, total-size and destination-capacity errors use offset
zero.

`tlv_reader_format_cer` and `tlv_writer_format_cer` also work with generic C and
C++ readers and writers. These descriptors validate **only the current tag and
length** — generic I/O does not inspect constructed contents, EOC placement, or
canonical segmentation, and provides no field offsets. Use the CER-specific
functions above when those guarantees are required.

See also the [C API reference: profiles](../../reference/c-api.md#profiles).
