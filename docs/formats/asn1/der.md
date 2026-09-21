# DER-TLV

[Format documentation](../README.md)

## API and build

| Setting | Value |
| --- | --- |
| Format header | `tlv/formats/asn1/der.h` |
| Reader descriptor | `tlv_reader_format_der` |
| Writer descriptor | `tlv_writer_format_der` |
| CMake option (default ON) | `OPENTLV_FORMAT_DER` |
| Link target | `tlv` |

## Scope and limits

Canonical tag/length framing with definite lengths only. Generic I/O does not validate nested contents or full ASN.1 value semantics.

See [shared memory ownership rules](../../guides/memory.md) before retaining a parsed view.

## Minimal C usage

This complete example writes and reads one opaque byte. Exit code zero means success.

```c
#include "tlv/formats/asn1/der.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"

int main(void) {
    const tlv_tag_t tag = {{0x04}, 1};
    const uint8_t value[] = {0x2A};
    uint8_t output[8];
    size_t written = 0, consumed = 0;
    tlv_view_t view;
    if (tlv_write(output, sizeof(output), &tlv_writer_format_der,
                  tag, value, sizeof(value), &written) != TLV_OK)
        return 1;
    if (tlv_read(output, written, &tlv_reader_format_der,
                 &view, &consumed) != TLV_OK)
        return 1;
    return consumed == written && view.tag.size == 1 &&
           view.tag.data[0] == 0x04 && view.value.length == 1 &&
           view.value.data[0] == 0x2A ? 0 : 1;
}
```

## Layout and typical use

DER uses the [BER layout](ber.md#layout-and-typical-use) with one encoding chosen for
every value, so equal values always encode to the same bytes.

```text
+------------------+----------------------+-----------------------+
| Identifier       | Length               | Contents              |
| 1+ bytes (tag)   | shortest definite    | Length bytes          |
|                  | form only            | (child elements if    |
|                  |                      |  constructed)         |
+------------------+----------------------+-----------------------+
```

There is no indefinite length and no end-of-contents marker, and the length uses the
fewest octets possible. Typical uses are signed or hashed structures such as
certificates and keys, where the exact bytes must be reproducible. The generic reader
checks only this framing; canonical values and ordering come from the `_strict`
functions and [schemas](../../profiles/der/README.md).

## Byte example

```text
30 06 02 01 2A 04 01 FF
Element (8 bytes)
|-- Tag:    30 (constructed SEQUENCE)
|-- Length: 06 = 6 encoded child bytes
`-- Value
    |-- Child (3 bytes)
    |   |-- Tag:    02 (INTEGER)
    |   |-- Length: 01
    |   `-- Value:  2A (42)
    `-- Child (3 bytes)
        |-- Tag:    04 (OCTET STRING)
        |-- Length: 01
        `-- Value:  FF
```

The annotations explain ASN.1 meanings; raw I/O does not decode those values.
Use `tlv_der_read` for bounded validation of the element and its descendants.
The generic `tlv_reader_format_der` / `tlv_writer_format_der` descriptors validate
only the current tag and length. Indefinite lengths are rejected. Full ASN.1
value canonicalization and SET ordering remain outside the supported scope.
[DER profile](../../profiles/der/README.md)
