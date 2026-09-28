# Bluetooth LTV

[Format documentation](../README.md)

Bluetooth advertising data, scan-response data and Generic Access Profile (GAP)
data are a sequence of **Length | Type | Value** structures. OpenTLV reads and
writes them through the same generic reader and writer as every other format;
only the format descriptor differs.

## API and build

| Setting | Value |
| --- | --- |
| Format header | `tlv/builtins/bluetooth/bluetooth_ltv.h` |
| Descriptor | `tlv_format_bluetooth_ltv` |
| CMake option (default ON, independent of `OPENTLV_FORMAT_FIXED`) | `OPENTLV_FORMAT_BLUETOOTH_LTV` |
| `otlv` format name | `bluetooth-ltv` |
| Link target | `tlv` |

Bluetooth LTV is a preset of the [configurable Fixed format](../fixed/configurable.md):
`{1, 1, TLV_BYTE_ORDER_BIG_ENDIAN, TLV_ELEMENT_ORDER_LTV,
TLV_LENGTH_SCOPE_TAG_AND_VALUE}`. `tlv_format_bluetooth_ltv` exists so callers
do not have to spell that configuration out themselves; there is no
Bluetooth-specific parser or writer underneath it.

## Advertising Data Type definitions

Include `tlv/builtins/bluetooth/ad_types.h` to resolve AD type names with
`tlv_definition_find(&tlv_bluetooth_ad_types, &element.tag)`. The result is a
borrowed `const tlv_definition_t*`: `tag` preserves the one-byte identifier and
`name` provides its official Bluetooth SIG name. For `02 01 06`, lookup resolves
`01` to `Flags`; the value remains the borrowed byte `06`.

The initial registry covers `01` through `0A`, `16`, `20`, `21`, and `FF`, using
the [Bluetooth SIG Assigned Numbers](https://www.bluetooth.com/specifications/assigned-numbers/).
It is not exhaustive. Lookup returns `NULL` for an unlisted type such as `FE`;
that does not prevent the format from reading or writing the element.

The registry uses the generic `tlv_definition_t` and
`tlv_definition_registry_t` model from `tlv/definition.h`. Applications can
provide their own immutable tables and use the same lookup, which compares tag
size and bytes, returns the first match, and never allocates. Definition
metadata does not impose schema constraints or interpret values. Both the
generic API and Bluetooth registry are available even with
`OPENTLV_FORMAT_BLUETOOTH_LTV=OFF`.

## Advertising Data schema

Include `tlv/builtins/bluetooth/ad_schema.h` and pass
`&tlv_bluetooth_ad_schema` to `tlv_schema_validate()` with
`&tlv_format_bluetooth_ltv`. The immutable schema is available even when the
Bluetooth format is disabled; it has no dependency on codecs or the registry.

| AD types | Value-length constraint | Occurrences per AD block |
| --- | --- | --- |
| Flags (`01`) | Any, including empty | At most one |
| Shortened / Complete Local Name (`08`, `09`) | 0 through 248 bytes | At most one across both types |
| Tx Power (`0A`) | Exactly 1 byte | Unrestricted |
| Service UUID lists (`02`–`07`) | Multiple of 2, 4 or 16 bytes; empty allowed | At most one list per width, across complete and incomplete variants |
| Service Data (`16`, `20`, `21`) | At least 2, 4 or 16 bytes | Unrestricted |
| Manufacturer Specific Data (`FF`) | At least 2 bytes | Unrestricted |

These rules follow [Bluetooth CSS v12, Part A](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/CSS_v12/out/en/supplement-to-the-bluetooth-core-specification/data-types-specification.html),
Table 1.1 and sections 1.1–1.5 and 1.11. All fields are optional in this
context-free schema. Unknown types are accepted. Conditional requirements
based on connectability and relationships between separate AD/SRD blocks
require additional context and are not checked.

`02 0A FC` passes; `03 0A FC FD` parses successfully but fails schema
validation with `TLV_ERR_INVALID_LENGTH`. Likewise, `04 03 0F 18 00`
fails because three value bytes cannot form a 16-bit UUID list.
`tlv_schema_validate_all()` and `tlv_schema_validate_all_diag()` report these
as length issues; the detailed diagnostic includes `length_multiple`.

This schema checks lengths and occurrences only. It does not check UTF-8,
flag-bit contents, numeric ranges, assigned UUIDs/company identifiers or
service/manufacturer payloads. The format still enforces the 254-byte value
limit. Pass only significant AD structures; trailing zero padding remains a
framing error and needs separate container handling.

## Wire layout and logical model

On the wire the length comes first:

```text
[Length][Type][Value]
   1 B    1 B   Length - 1 bytes
```

OpenTLV always presents an element as the logical triple **Type (tag), Length,
Value**, whatever the wire order. For Bluetooth LTV:

| Logical field | Where it comes from |
| --- | --- |
| Tag | The one-byte type, exposed as a tag of size 1 (`element.tag.data[0]`) |
| Length | The number of value bytes, which is the wire length byte minus 1 |
| Value | The bytes after the type, borrowed from the input (`element.value`) |

The wire order is a property of the format descriptor, not of the data model.
Nothing in OpenTLV requires a format to put the tag first, and Bluetooth LTV is
the built-in example of a format that does not.

## Length semantics

The Bluetooth length byte counts the **type byte plus the value bytes**. It does
not count itself. This differs from the length in conventional TLV, which counts
only the value.

| Wire length byte | Structure size | Value bytes |
| --- | --- | --- |
| `00` | rejected | none (see [malformed input](#malformed-input)) |
| `01` | 2 bytes | 0 |
| `03` | 4 bytes | 2 |
| `FF` | 256 bytes | 254 (the maximum) |

A structure is `length + 1` bytes and carries at most 254 value bytes. The
logical length reported by OpenTLV is the value length, so a wire length of `03`
is reported as a value of 2 bytes.

## Differences from conventional TLV

| | Conventional TLV (for example [Fixed](../fixed/configurable.md)) | Bluetooth LTV |
| --- | --- | --- |
| Wire order | Tag, length, value | Length, type, value |
| Length counts | Value bytes only | Type byte and value bytes |
| Tag size | Format specific, may be multi-byte | Always 1 byte |
| Maximum value | Format specific | 254 bytes |
| Zero length | Empty value | Invalid |
| Constructed types | Depends on the format | None |
| Canonical operations | `decode`, `measure`, `encode` | `decode`, `measure`, `encode` |

## Parsing

Select the format by passing `tlv_format_bluetooth_ltv` to
`tlv_reader_init`, then call `tlv_reader_next` until it stops returning
`TLV_OK`. Each `tlv_element_t` gives the type in `element.tag` and the value in
`element.value`.

```c
#include "tlv/builtins/bluetooth/bluetooth_ltv.h"
#include "tlv/size.h"
#include "tlv/reader/reader.h"

#include <stdio.h>

int main(void) {
    /* Flags (01) = 06, then Complete Local Name (09) = "Hi". */
    const uint8_t advertising[] = {0x02, 0x01, 0x06, 0x03, 0x09, 'H', 'i'};
    tlv_reader_t reader;
    tlv_element_t element;
    tlv_result_t rc;

    if (tlv_reader_init(&reader, advertising, sizeof(advertising),
                        &tlv_format_bluetooth_ltv) != TLV_OK)
        return 1;

    while ((rc = tlv_reader_next(&reader, &element)) == TLV_OK) {
        size_t length;
        if (tlv_size_to_native(element.value.size, &length) != TLV_OK) return 1;
        printf("type 0x%02X, %u value byte(s)\n", (unsigned)element.tag.data[0],
               (unsigned)length);
        /* element.value.data[0 .. length) holds the value. */
    }
    /* rc is not TLV_OK here; at_end distinguishes a clean finish from an error. */
    return tlv_reader_at_end(&reader) ? 0 : 1;
}
```

This prints:

```text
type 0x01, 1 value byte(s)
type 0x09, 2 value byte(s)
```

The value is not interpreted. Decoding it (flags bits, UTF-8 names, UUID lists,
manufacturer data) is up to the caller, keyed on the type. The views borrow the
input buffer; see the [shared memory ownership rules](../../guides/memory.md)
before retaining one.

The reader is also usable through the scanner, walker, schemas and the `otlv`
CLI:

```text
$ otlv dump --format bluetooth-ltv --hex "02 01 06 03 09 48 69"
offset=0 tag=01 length=1 value=06
offset=3 tag=09 length=2 value=4869
```

## Encoding

Writing uses `tlv_format_bluetooth_ltv` with the same `tlv_write` and
`tlv_writer_write` calls as any other format. The writer emits the length byte
(`value length + 1`) followed by the type byte and the value.

| Condition | Result |
| --- | --- |
| Tag size is not 1 | `TLV_ERR_INVALID_TAG_SIZE` |
| Value longer than 254 bytes | `TLV_ERR_INVALID_LENGTH` |
| Output buffer too small | `TLV_ERR_BUFFER_TOO_SHORT` |

## Unknown types

The format never inspects the type value, so every type is structurally valid.
An unknown or vendor-specific type is returned like any other, and the reader
moves to the next structure using the length alone. Callers decide which types
they handle and ignore the rest.

## Malformed input

| Input | Result |
| --- | --- |
| No input left | `TLV_ERR_END_OF_BUFFER`; `tlv_reader_at_end` reports a clean finish |
| Length byte `00` | `TLV_ERR_INVALID_LENGTH`: there is no type byte |
| Length larger than the remaining bytes | `TLV_ERR_BUFFER_TOO_SHORT` |

A length byte of zero has no type byte to report. In Bluetooth data it also
starts the non-significant zero padding that may follow the last structure, so
a buffer with trailing zero padding stops with `TLV_ERR_INVALID_LENGTH` after the
last real structure. Callers that receive padded buffers should trim it first
(or stop on that error once all wanted structures have been read).

On error the reader position does not advance, so a truncated structure is
never returned partially.

## Limitations

- The type is exposed as a one-byte tag and the value is opaque; the AD Type
  registry and schema do not decode values.
- Values are limited to 254 bytes, and the tag is always one byte.
- There are no constructed types; nesting is left to the caller.
- Framing and optional schema validation do not implement a Bluetooth stack.

## Byte example

```text
03 09 48 69
Element (4 bytes)
|-- Length: 03 = type byte + 2 value bytes
|-- Type:   09 (Complete Local Name), exposed as the tag
`-- Value:  48 69 ("Hi")
```

## How it fits the format architecture

Bluetooth is a configuration of the public binary-field layout primitives in
`tlv/layout.h`: one-byte Tag and Length, Length before Tag, Length counting Tag
and Value. It has no dependency on Fixed-private code or the Fixed build option.
Both formats expose the same canonical decode/measure/encode contract.

See [Format/Element contract](../../concepts/format-contract.md).
