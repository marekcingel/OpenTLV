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

- The type is exposed as a one-byte tag and the value is opaque; there is no
  built-in GAP or assigned-numbers dictionary.
- Values are limited to 254 bytes, and the tag is always one byte.
- There are no constructed types; nesting is left to the caller.
- Only the framing is implemented, not any part of a Bluetooth stack.

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
