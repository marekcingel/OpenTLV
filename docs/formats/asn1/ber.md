# BER-TLV

[Format documentation](../README.md)

## API and build

| Setting | Value |
| --- | --- |
| Format header | `tlv/formats/asn1/ber.h` |
| Reader descriptor | `tlv_reader_format_ber` |
| Writer descriptor | `tlv_writer_format_ber` |
| CMake option (default ON) | `OPENTLV_FORMAT_BER` |
| Link target | `tlv` |

## Scope and limits

Multi-byte tags up to TLV_TAG_MAX_SIZE; definite lengths and constructed indefinite input. Ordinary writes use definite lengths.

See [shared memory ownership rules](../../memory.md) before retaining a parsed view.

## Minimal C usage

This complete example writes and reads one opaque byte. Exit code zero means success.

```c
#include "tlv/formats/asn1/ber.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"

int main(void) {
    const tlv_tag_t tag = {{0x04}, 1};
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
low seven-bit value. Tags must fit `TLV_TAG_MAX_SIZE`. The format accepts raw
identifiers such as `9F 1C` without enforcing ASN.1 tag-number minimality or
universal-tag semantics. Definite values remain opaque during single-element
reading; resolving an indefinite element inspects descendant framing.

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
const tlv_tag_t sequence = {{0x30}, 1};
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
through the same BER descriptor. Include `tlv++/ber.hpp` for
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

These framing rules follow [ITU-T X.690 (02/2021), sections 8.1.3 and 8.1.5](https://www.itu.int/rec/T-REC-X.690-202102-I/en).

Malformed tags, unterminated tags on write, and tags exceeding capacity return
`TLV_ERR_INVALID_TAG`. Missing tag continuation or length bytes return
`TLV_ERR_BUFFER_TOO_SHORT`; a continuation requiring bytes beyond tag capacity
returns `TLV_ERR_INVALID_TAG` even if those bytes are missing. Empty input to
the generic reader returns `TLV_ERR_END_OF_BUFFER`. All BER-specific encoding
and validation live in the format callbacks.


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

