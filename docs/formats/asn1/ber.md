# BER-TLV

[Format documentation](../README.md)

## API and build

| Setting | Value |
| --- | --- |
| Format header | `tlv/builtins/asn1/ber.h` |
| Reader descriptor | `tlv_reader_format_ber` |
| Writer descriptor | `tlv_writer_format_ber` |
| CMake option (default ON) | `OPENTLV_FORMAT_BER` |
| Link target | `tlv` |

## Scope and limits

Multi-byte tags of up to `TLV_ASN1_TAG_MAX_SIZE` (8) bytes; definite lengths and constructed indefinite input. Ordinary writes use definite lengths.

See [shared memory ownership rules](../../guides/memory.md) before retaining a parsed view.

## Minimal C usage

This complete example writes and reads one opaque byte. Exit code zero means success.

```c
#include "tlv/builtins/asn1/ber.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"

int main(void) {
    const tlv_tag_t tag = TLV_TAG(0x04);
    const uint8_t value[] = {0x2A};
    uint8_t output[8];
    size_t written = 0, consumed = 0;
    tlv_view_t view;
    if (tlv_write(output, sizeof(output), &tlv_writer_format_ber,
                  tag, value, sizeof(value), &written) != TLV_OK)
        return 1;
    if (tlv_read(output, written, &tlv_reader_format_ber,
                 &view, &consumed) != TLV_OK)
        return 1;
    return consumed == written && view.tag.size == 1 &&
           view.tag.data[0] == 0x04 && view.value.length == 1 &&
           view.value.data[0] == 0x2A ? 0 : 1;
}
```

Use `tlv_reader_format_ber` with the reader and `tlv_writer_format_ber` with
the writer for raw BER-TLV tags
such as `5A`, `5F 2A`, `9F 1C`, and `9F 81 01`. Tags retain their wire bytes,
including class and constructed bits. High-tag-number form ends at the first
subsequent byte with bit 7 clear; its first subsequent byte must have a nonzero
low seven-bit value. Tags longer than `TLV_ASN1_TAG_MAX_SIZE` (8) bytes are rejected with `TLV_ERR_INVALID_TAG_SIZE`; that is a limit of the BER family of formats, not of `tlv_tag_t`. Tags read by the format borrow the input. The format accepts raw
identifiers such as `9F 1C` without enforcing ASN.1 tag-number minimality or
universal-tag semantics. Definite values remain opaque during single-element
reading; resolving an indefinite element inspects descendant framing.

### Tag model: class, form and number

`tlv_asn1_class_t` (`TLV_ASN1_UNIVERSAL`, `TLV_ASN1_APPLICATION`,
`TLV_ASN1_CONTEXT_SPECIFIC`, `TLV_ASN1_PRIVATE`) and the ASN.1 identifier-octet
model (class, primitive/constructed form, low- and high-tag-number number)
are wire-format concepts, not specific to any encoding-rule profile; every
BER-family format shares them. ASN.1 type semantics such as `INTEGER` or
`SEQUENCE` stay outside this layer.

```c
const uint8_t input[] = {0xA0, 3, 0x02, 1, 42}; /* Context-specific, constructed, tag 0 */
tlv_view_t view;
size_t consumed;
if (tlv_read(input, sizeof(input), &tlv_reader_format_ber, &view, &consumed) == TLV_OK) {
    tlv_asn1_class_t cls = tlv_ber_tag_class(&view.tag);         /* TLV_ASN1_CONTEXT_SPECIFIC */
    int constructed = tlv_ber_tag_is_constructed(&view.tag);     /* 1 */
    uint64_t number;
    tlv_ber_tag_number(&view.tag, &number);                      /* 0 */
}
```

`tlv_ber_tag_class()` and `tlv_ber_tag_is_constructed()` read a successfully
parsed or created, nonempty tag directly. `tlv_ber_tag_number(tag, &number)`
re-validates the tag's wire encoding and extracts a `uint64_t`; numbers beyond
`uint64_t` return `TLV_ERR_INVALID_TAG`, and an empty tag or one exceeding
`TLV_ASN1_TAG_MAX_SIZE` returns `TLV_ERR_INVALID_TAG_SIZE`.
`tlv_ber_tag_make(class, constructed, number, storage, &tag)` builds minimal
wire bytes from these three parts into `storage`
(`TLV_ASN1_TAG_MAX_SIZE` writable bytes, which the returned tag then borrows
and must outlive), using low-tag-number form below 31 and high-tag-number form
otherwise. These reuse `tlv_tag_t` rather than a separate ASN.1 tag type.

Unlike the corresponding DER and CER tag accessors, none of these functions
apply a canonical primitive/constructed rule tied to a universal type number
(for example DER's `must be constructed` rule for `SEQUENCE`): BER accepts
either form for every tag number. The only identifier `tlv_ber_tag_make()`
rejects outright is the reserved EOC tag (universal class, tag number 0, in
either form), matching `tlv_reader_format_ber` and `tlv_writer_format_ber`.
See [DER](der.md) for the canonical restrictions.

Definite lengths range from zero through `SIZE_MAX` (the complete element must
also fit `size_t`). The writer uses short form below 128 and the shortest
big-endian long form otherwise: 128 is `81 80`, 256 is `82 01 00`.
The reader also accepts nonminimal definite lengths, including leading zeros.
Reserved length prefix `FF` and lengths overflowing `size_t` return
`TLV_ERR_INVALID_LENGTH`. The length-only callback still accepts definite
lengths only: `80` needs the parsed tag and surrounding bytes, supplied through
the optional value-boundary callback.

Constructed elements may use indefinite length `80`, terminated by `00 00`.
For example, `30 80 04 02 00 00 00 00` has a four-byte value `04 02 00 00`
and consumes eight bytes. The zeros inside primitive tag `04` are data.
Only the enclosing EOC is excluded from the value; EOCs belonging to children
remain part of their complete encodings within that value.

EOC matching uses an allocation-free iterative stack and permits mixed definite
and indefinite descendants. Every definite parent bounds all its descendants;
an EOC beyond that boundary cannot close a child. `TLV_BER_MAX_DEPTH` is 64
simultaneous constructed scopes, counting the outer indefinite element and
definite constructed descendants, including empty ones. Exceeding it returns
`TLV_ERR_LIMIT`. This framing limit is independent of walker depth/element limits.
Resolving one indefinite element takes linear time in the inspected framing;
tree traversal and schemas can rescan nested encodings.

Indefinite primitive values and malformed EOC length fields return
`TLV_ERR_INVALID_LENGTH`. Unexpected EOC in a scanned definite scope and reserved
universal tag zero used as an ordinary element return `TLV_ERR_INVALID_TAG`.
Missing/truncated EOC or child encodings return `TLV_ERR_BUFFER_TOO_SHORT`.
Single-element definite reads still defer child validation to tree traversal.

### Explicit indefinite writing

`tlv_write`, `tlv_writer_write`, and `tlv_encoded_size` retain definite BER output.
Use the BER-specific functions for an already encoded sequence of children:

```c
const tlv_tag_t sequence = TLV_TAG(0x30);
const uint8_t children[] = {0x04, 0x02, 0x00, 0x00};
uint8_t output[8];
size_t required, written;
tlv_result_t rc = tlv_ber_indefinite_encoded_size(sequence, sizeof(children), &required);
if (rc == TLV_OK && required <= sizeof(output)) {
    rc = tlv_ber_write_indefinite(output, sizeof(output), sequence,
                                 children, sizeof(children), &written);
}
```

The size query validates the constructed tag and size overflow. Writing also
validates all child framing and the same nesting limit before modifying the
destination. Do not supply the enclosing EOC; the writer appends it. Source and
destination must not overlap. Capacity failures leave bytes and outputs unchanged.
An empty sequence accepts `NULL, 0` children. NULL destination with zero capacity
reports insufficient capacity; use the separate size query for sizing.
`tlv_ber_writer_write_indefinite` appends to a stateful writer initialized with
`&tlv_writer_format_ber` and advances its position only on success.

The C++ `tlv::reader`, traversal, and schema wrappers support indefinite input
through the same BER descriptor. Include `tlv++/builtins/asn1/ber.hpp` for
`tlv::ber_write_indefinite(buffer, capacity, tag, children)`, returning
`expected<size_t, error>`. The ordinary C++ writer remains definite-length.
The C core does not allocate; C++ error construction retains its existing
`std::string` behavior.

`tlv_copy_view` with the BER writer re-encodes the outer header as definite;
child bytes remain unchanged. Use `tlv_copy_encoded` with the full consumed
range to preserve the original indefinite representation. Flat walkers,
recovery scanning, structural schemas and structure codecs use the resolved
value range. Scanner results remain recovery candidates, not proof of a valid
surrounding tree. DER still rejects indefinite lengths.

### Standalone definite-length codec

`tlv_ber_length_decode(data, data_size, &value, &consumed)` and
`tlv_ber_length_encode(value, out, out_capacity, &written)` inspect or produce
one BER definite-length field on its own, independent of any tag or value
payload and of the format callbacks above. They use `tlv_length_t` (from
`tlv/length.h`) for the decoded value, so it has the same 64-bit range on
every build regardless of the current build's `size_t` width:

```c
#include "tlv/builtins/asn1/ber.h"
#include "tlv/length.h"

uint8_t out[TLV_BER_LENGTH_MAX_ENCODED_SIZE];
size_t written;
if (tlv_ber_length_encode(300, out, sizeof(out), &written) == TLV_OK) {
    /* out[0..written) is 82 01 2C. */
}

tlv_length_t value;
size_t consumed;
if (tlv_ber_length_decode(out, written, &value, &consumed) == TLV_OK) {
    size_t available; /* bytes actually held by the value buffer at hand */
    size_t needed;
    /* Convert the portable decoded length before using it as a native size,
     * then separately check it against the buffer that is actually available;
     * a successful conversion does not by itself prove that much data exists. */
    if (tlv_length_to_size(value, &needed) == TLV_OK && needed <= available) {
        /* needed bytes of value payload may now be read from the buffer. */
    }
}
```

`tlv_ber_length_decode` accepts short form and long form, including nonminimal
(zero-padded) long-form encodings whose numeric value still fits `tlv_length_t`
-- the same nonminimal acceptance as `tlv_reader_format_ber`, just against the
full 64-bit range instead of the current build's `size_t`. The indefinite
marker (`80` alone) and the reserved `FF` prefix are rejected with
`TLV_ERR_INVALID_LENGTH`, as is a padded value wider than `tlv_length_t` or
nonzero excess padding. A field that declares more length octets than
`data_size` provides returns `TLV_ERR_BUFFER_TOO_SHORT`. It does not process
the indefinite-length marker's associated content or constructed EOC framing;
use `tlv_reader_format_ber` or `tlv_ber_write_indefinite` for that.

`tlv_ber_length_encode` always produces the shortest definite form and
supports a size query: pass `out == NULL` with `out_capacity == 0` to receive
the required size in `*written` without writing. `TLV_BER_LENGTH_MAX_ENCODED_SIZE`
(9) is enough to hold the encoding of any `tlv_length_t` value, including
`UINT64_MAX` (`88 FF FF FF FF FF FF FF FF`); it is smaller than the largest
field `tlv_ber_length_decode` can still accept, since nonminimal input may use
up to 127 length octets. Insufficient `out_capacity` returns
`TLV_ERR_BUFFER_TOO_SHORT` with no partial write. Both functions leave their
outputs unchanged on failure, and neither allocates or requires the length's
value payload to be present.

These framing rules follow [ITU-T X.690 (02/2021), sections 8.1.3 and 8.1.5](https://www.itu.int/rec/T-REC-X.690-202102-I/en).

### Universal-type value codecs

`tlv/builtins/asn1/asn1_codec.h` (built with `OPENTLV_FORMAT_BER`) adds
[`tlv_codec_t`](../../guides/codecs.md) descriptors that convert the raw
value bytes of the ASN.1 primitive universal types to and from C
representations, independent of any particular BER-family format or
profile. The format layer above never reads ASN.1 type semantics into a
tag; callers pick the matching codec themselves, typically from a schema or
dictionary:

```c
#include "tlv/builtins/asn1/asn1_codec.h"

/* view.value already read through tlv_reader_format_ber, DER or CER */
int64_t number;
size_t  length;
if (tlv_length_to_size(view.value.length, &length) == TLV_OK &&
    tlv_codec_decode(&tlv_asn1_codec_integer, view.value.data, length,
                      &number, sizeof(number)) == TLV_CODEC_OK) {
    /* number holds the decoded INTEGER */
}
```

A codec is provided for each of BOOLEAN (`tlv_asn1_codec_boolean`, `bool`),
INTEGER and ENUMERATED (`tlv_asn1_codec_integer`, `tlv_asn1_codec_enumerated`,
`int64_t`), BIT STRING (`tlv_asn1_codec_bit_string`, `tlv_asn1_bit_string_t`),
OCTET STRING (`tlv_asn1_codec_octet_string`, `tlv_asn1_octet_string_t`), NULL
(`tlv_asn1_codec_null`, no representation) and OBJECT IDENTIFIER /
RELATIVE-OID (`tlv_asn1_codec_oid`, `tlv_asn1_codec_relative_oid`, both
`tlv_asn1_oid_t`, an arc array up to `TLV_ASN1_OID_MAX_ARCS`). BIT STRING and
OCTET STRING decode into a representation that borrows the input value
bytes; every other representation is self-contained.

Every codec enforces the same canonical content rules ITU-T X.690 section 11
defines for DER and CER, even when the raw value was read through the more
permissive `tlv_reader_format_ber`: for example a BOOLEAN of `01`, or a
non-minimal two's complement INTEGER, is rejected with
`TLV_CODEC_ERR_INVALID_VALUE`. See `tlv/builtins/asn1/asn1_codec.h` for each
codec's exact content and representation rules.

Malformed tags and unterminated tags on write return `TLV_ERR_INVALID_TAG`,
unless continuation requires bytes beyond `TLV_ASN1_TAG_MAX_SIZE`. Empty tags on write and
tags longer than `TLV_ASN1_TAG_MAX_SIZE` return `TLV_ERR_INVALID_TAG_SIZE`. Missing tag continuation or length bytes return
`TLV_ERR_BUFFER_TOO_SHORT`; a continuation requiring bytes beyond `TLV_ASN1_TAG_MAX_SIZE`
returns `TLV_ERR_INVALID_TAG_SIZE` even if those bytes are missing. Empty input to
the generic reader returns `TLV_ERR_END_OF_BUFFER`. All BER-specific encoding
and validation live in the format callbacks.

## Layout and typical use

An element is identifier octets, length octets, and contents. A constructed value's
contents are more elements with the same layout, so the structure is recursive.

```text
+------------------+----------------------+-----------------------+---------+
| Identifier       | Length               | Contents              | EOC     |
| 1+ bytes (tag)   | 1+ bytes             | Length bytes          | 00 00   |
|                  |                      | (child elements if    | only if |
|                  |                      |  constructed)         | length  |
|                  |                      |                       | is 80   |
+------------------+----------------------+-----------------------+---------+
```

| Part | Forms |
| --- | --- |
| Identifier, first octet | Bits 8-7 class (universal, application, context-specific, private), bit 6 constructed, bits 5-1 tag number |
| Identifier, high tag numbers | Tag number bits 5-1 all set (`1F`), then the number in following octets, seven bits each, with bit 8 set on every octet except the last |
| Length, short | One octet `00`-`7F`: the length itself |
| Length, long | `81`-`FE` (`80` plus the count `n`), then `n` length octets |
| Length, indefinite | `80`, constructed values only; contents end with the end-of-contents marker `00 00` |

The definite length covers the contents (all children with their headers), not the
identifier or the length octets. Typical uses are ASN.1-based protocols and smart-card
data objects, where BER is the framing and the meaning of each tag comes from a
[profile](../../profiles/emv/README.md) or a schema. See [DER](der.md) and [CER](cer.md)
for the canonical restrictions of this layout.

## Byte example

### Definite constructed value

```text
E1 08 5A 02 12 34 5F 2A 01 56
Element (10 bytes)
|-- Tag:    E1 (constructed)
|-- Length: 08 = 8 encoded child bytes
`-- Value
    |-- Child (4 bytes)
    |   |-- Tag:    5A (primitive)
    |   |-- Length: 02
    |   `-- Value:  12 34
    `-- Child (4 bytes)
        |-- Tag:    5F 2A (primitive, multi-byte tag)
        |-- Length: 01
        `-- Value:  56
```

The parent's length includes each child's tag, length, and value. These are
illustrative opaque payloads, not an EMV-valid record. Generic `tlv_read`
returns the outer value without automatically visiting definite-length children.
Use `tlv_walk_tree` with `tlv_ber_is_constructed` to traverse the hierarchy.

### Indefinite constructed value

```text
E1 80 5A 02 12 34 00 00
Element (8 bytes)
|-- Tag:    E1 (constructed)
|-- Length: 80 (indefinite)
|-- Value:  5A 02 12 34 (4 bytes)
|   `-- Child
|       |-- Tag:    5A
|       |-- Length: 02
|       `-- Value:  12 34
`-- Trailer: 00 00 (end-of-contents / EOC)
```

The returned outer value excludes its EOC; the consumed byte count includes it.
Primitive indefinite-length values are rejected. Ordinary BER writing emits
definite lengths; use `tlv_ber_write_indefinite` for explicit indefinite output.
Use `tlv_reader_format_ber` / `tlv_writer_format_ber`.
[BER rules and limits](ber.md)
