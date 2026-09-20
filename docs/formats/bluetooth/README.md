# Bluetooth LTV

[Format documentation](../README.md)

## API and build

| Setting | Value |
| --- | --- |
| Format header | `tlv/formats/bluetooth/bluetooth_ltv.h` |
| Reader descriptor | `tlv_reader_format_bluetooth_ltv` |
| Writer descriptor | `tlv_writer_format_bluetooth_ltv` |
| CMake option (default ON) | `OPENTLV_FORMAT_BLUETOOTH_LTV` |
| `otlv` format name | `bluetooth-ltv` |
| Link target | `tlv` |

## Scope and limits

Bluetooth advertising data, scan-response data and Generic Access Profile data
types are a sequence of Length | Type | Value structures. Unlike every other
built-in format, the length comes **before** the type, and it counts the type
byte plus the value bytes.

- The type is exposed as a one-byte tag; the value is opaque.
- A structure is `length + 1` bytes and carries at most 254 value bytes.
- Unknown types are structurally valid and skipped by length alone.
- A length byte of zero is rejected with `TLV_ERR_INVALID_LENGTH`: it has no
  type byte, and in Bluetooth data it starts the non-significant zero padding.
- There are no constructed types; nesting is left to the caller.

See [shared memory ownership rules](../../guides/memory.md) before retaining a parsed view.

## Minimal C usage

The generic reader and writer work unchanged; only the format descriptor
differs. Exit code zero means success.

```c
#include "tlv/formats/bluetooth/bluetooth_ltv.h"
#include "tlv/reader/reader.h"

int main(void) {
    /* Flags (01) = 06, then Complete Local Name (09) = "Hi". */
    const uint8_t advertising[] = {0x02, 0x01, 0x06, 0x03, 0x09, 'H', 'i'};
    tlv_reader_t reader;
    tlv_view_t view;
    size_t count = 0;
    if (tlv_reader_init(&reader, advertising, sizeof(advertising),
                        &tlv_reader_format_bluetooth_ltv) != TLV_OK)
        return 1;
    while (tlv_reader_next(&reader, &view) == TLV_OK) ++count;
    return count == 2 && tlv_reader_at_end(&reader) ? 0 : 1;
}
```

Writing uses `tlv_writer_format_bluetooth_ltv` with the same `tlv_write` and
`tlv_writer_write` calls as any other format. Writing a tag whose size is not 1
returns `TLV_ERR_INVALID_TAG_SIZE`; a value longer than 254 bytes returns
`TLV_ERR_INVALID_LENGTH`.

## Byte example

```text
03 09 48 69
Element (4 bytes)
|-- Length: 03 = type byte + 2 value bytes
|-- Type:   09 (Complete Local Name), exposed as the tag
`-- Value:  48 69 ("Hi")
```

## How it fits the format architecture

Other formats decode a tag, then a length, through the `read_tag` and
`read_length` callbacks. That split cannot describe a format whose length
precedes its type, so Bluetooth LTV uses the optional whole-element callbacks
`read_element` (reader) and `write_header` (writer) described in the
[generic interface](../README.md#generic-interface). They report the tag, the
size of everything before the value, and the value size in one step, so the
reader, scanner, walker, schemas, copy helpers and the CLI work on it with no
format-specific code. Bluetooth-specific wire rules stay in
`tlv/src/formats/bluetooth/`.
