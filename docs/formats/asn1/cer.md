# CER-TLV

[Format documentation](../README.md)

## API and build

| Setting | Value |
| --- | --- |
| Format header | `tlv/builtins/asn1/cer.h` |
| Descriptor | `tlv_format_cer` |
| CMake option (default ON) | `OPENTLV_FORMAT_CER` |
| Link target | `tlv` |

CER is a sibling of DER over the same BER-TLV wire helpers: `OPENTLV_FORMAT_CER`
cascades from `OPENTLV_FORMAT_BER`, not from `OPENTLV_FORMAT_DER`, and neither
sibling depends on the other. `OPENTLV_PROFILE_EMV` cascades only from
`OPENTLV_FORMAT_DER` and is unaffected by `OPENTLV_FORMAT_CER` either way.

## Scope and limits

Canonical tag/length framing: a constructed value's length must be
indefinite (EOC-terminated); a primitive value's length must be definite and
minimally encoded. Generic I/O validates only the current element's
identifier and length, not nested framing, EOC placement, or canonical
string segmentation across descendants — use [tlv/builtins/asn1/cer_profile.h](../../profiles/cer/README.md)
for that.

See [shared memory ownership rules](../../guides/memory.md) before retaining a
parsed element.

## Minimal C usage

This complete example writes and reads one opaque primitive byte. Exit code
zero means success.

```c
#include "tlv/builtins/asn1/cer.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"

int main(void) {
    const tlv_tag_t tag = TLV_TAG(0x04);
    const uint8_t value[] = {0x2A};
    uint8_t output[8];
    size_t written = 0, consumed = 0;
    tlv_element_t element;
    if (tlv_write(output, sizeof(output), &tlv_format_cer,
                  tag, value, sizeof(value), &written) != TLV_OK)
        return 1;
    if (tlv_read(output, written, &tlv_format_cer,
                 &element, &consumed) != TLV_OK)
        return 1;
    return consumed == written && element.tag.size == 1 &&
           element.tag.data[0] == 0x04 && element.value.size == 1 &&
           element.value.data[0] == 0x2A ? 0 : 1;
}
```

## Layout and typical use

CER uses the [BER layout](ber.md#layout-and-typical-use) and makes the choice of length
form depend on the kind of value.

```text
Primitive:    | Identifier | shortest definite Length | Contents |

Constructed:  | Identifier | 80 | child elements ... | 00 00 |
```

A primitive value always has a minimal definite length. A constructed value always has
the indefinite length `80` and ends with `00 00`. Long strings are split into
segments by the canonical rules. Typical uses are canonical encodings that can be
produced in one pass without knowing the total length in advance. Generic I/O checks
only the current element's identifier and length; nested framing is checked by the
[CER profile](../../profiles/cer/README.md).

## Byte example: nested indefinite-length containers

```text
30 80 02 01 05 30 80 04 02 00 00 00 00 00 00
Element (15 bytes, indefinite length)
|-- Tag:    30 (constructed SEQUENCE)
|-- Length: 80 = indefinite
|-- Value
|   |-- Child (3 bytes)
|   |   |-- Tag:    02 (INTEGER)
|   |   |-- Length: 01
|   |   `-- Value:  05 (5)
|   `-- Child (10 bytes, indefinite length)
|       |-- Tag:    30 (constructed SEQUENCE)
|       |-- Length: 80 = indefinite
|       |-- Value
|       |   `-- Child (4 bytes)
|       |       |-- Tag:    04 (OCTET STRING)
|       |       |-- Length: 02
|       |       `-- Value:  00 00
|       `-- EOC:    00 00
`-- EOC:    00 00
```

The innermost OCTET STRING's content is the literal bytes `00 00` — the same
bit pattern as an EOC. It never affects nesting: a primitive element's
content is always skipped by its declared definite length, so a `00 00`
inside it is just data, and `00 00` is only ever recognized as EOC when it
appears at a TLV element boundary of an open indefinite container. Raw I/O
does not decode ASN.1 meanings; use [`tlv_cer_read`](../../profiles/cer/README.md)
for bounded validation of the element and its descendants, including EOC
placement.

[CER profile](../../profiles/cer/README.md)
