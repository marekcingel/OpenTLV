# ASN.1 DER-TLV

Include `tlv/profiles/der.h` for allocation-free DER-TLV processing. Tags use the existing
`tlv_tag_t` wire-byte representation; values are borrowed `tlv_buffer_t` ranges.
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
contents are opaque: BOOLEAN representations, INTEGER minimality, BIT STRING
padding, OID components, string/time/REAL encodings, schema constraints,
implicit-tag semantics, DEFAULT omission and SET/SET OF ordering are outside
this scope. Callers must supply canonical ASN.1 contents and ordering when
full DER conformance is required. The encoder preserves contents and child
order; it does not convert arbitrary BER or repair noncanonical input.

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
to `TLV_TAG_MAX_SIZE` (default 8 bytes, configurable from 1 to 255 consistently
across library and consumers), including numbers larger than `uint64_t`.
`tlv_der_tag_make(class, constructed, number, &tag)` creates minimal wire bytes
from a `uint64_t`, rejects invalid universal forms or insufficient tag capacity,
and leaves the output unchanged on failure. `constructed` must be 0 or 1.

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
