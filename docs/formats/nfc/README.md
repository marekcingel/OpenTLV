# NFC Forum Type 2 Tag TLV framing

Select `tlv_format_nfc_type2` from `tlv/builtins/nfc/type2.h`, or
`tlv::nfc_type2_format()` from `tlv++/builtins/nfc/type2.hpp`.
The independent `OPENTLV_NFC` option defaults to `ON`;
`tlv_config_nfc()` reports availability in the linked library.

This implements the TLV block framing in the
[NFC Forum Type 2 Tag Operation Specification 1.1, section 2.3](https://community.nxp.com/pwmxy87654/attachments/pwmxy87654/nfc/3252/1/NFCForum-Type-2-Tag_1.1%20Specification.pdf).
Type 2 uses **Tag, Length, Value**, not LTV ordering.

| Identifier | Name | Framing |
| --- | --- | --- |
| `00` | NULL | Tag only |
| `01` | Lock Control | Tag, Length, opaque Value |
| `02` | Memory Control | Tag, Length, opaque Value |
| `03` | NDEF Message | Tag, Length, opaque Value |
| `FD` | Proprietary | Tag, Length, opaque Value |
| `FE` | Terminator | Tag only |
| Other bytes | Reserved identifiers | Tag, Length, opaque Value |

The header exposes `TLV_NFC_TYPE2_*` constants for the named identifiers.
Reserved identifiers remain readable without a dictionary. Framing does not
validate control Values, their ordering, or the contents of an NDEF message.

## Length encoding

Values of 0 through 254 bytes use a one-byte Length. Values of 255 through
65534 bytes use `FF` followed by a two-byte big-endian count. For example,
`03 FF 01 00` introduces a 256-byte NDEF Value. Extended counts below 255 and
the reserved `FFFF` count return `TLV_ERR_INVALID_LENGTH`; incomplete fields
or Values return `TLV_ERR_BUFFER_TOO_SHORT`.

NULL and Terminator have no Length or wire Value. They expose an empty
semantic Value and are returned as ordinary elements. The Reader does not
skip NULL or stop at Terminator. The caller applies those policies.

## Input and source ownership

Supply a **contiguous TLV stream from the data area**. This API does not
interpret a complete physical memory dump, Capability Container, lock bits,
reserved memory holes, RF commands, or tag lifecycle. Dynamic memory mapping
requires separate handling before using this descriptor; compacting physical
memory changes the relationship between stream offsets and physical addresses.
No full Type 2 device conformance is claimed.

Tag and Value borrow the supplied immutable buffer. Decode does not allocate.
`tlv_decoded_t` pairs the semantic Element with source metadata. Within each
element, Tag is at `(0, 1)`; Length is at `(1, 1)` or `(1, 3)`. Value starts
at offset 2 or 4. For tag-only elements, Length is absent and Value/Trailer
are present empty ranges at offset 1. Reader/Query diagnostics locate elements
within the supplied stream, not a physical tag address space.

Measure does not read Value storage. Encode rejects non-one-byte identifiers,
nonempty tag-only Values and Values larger than 65534 bytes. Normal encoding
regenerates the wire representation; `tlv_source_preserve()` reproduces the
original bytes only while the source and semantic content remain unchanged.
Retain NULL elements if the desired result must preserve padding.

## Example

Build and run `example-tlv-nfc_type2`; its source is
[`examples/tlv/src/nfc_type2.c`](https://github.com/marekcingel/OpenTLV/blob/main/examples/tlv/src/nfc_type2.c).
The example reads and re-encodes `00 03 09 D1 01 05 54 02 65 6E 48 69 FE` byte-for-byte, retains
NULL in the encoded result, hides it in the display, and stops after Terminator:

```text
NDEF_MESSAGE: D1 01 05 54 02 65 6E 48 69
TERMINATOR
```

The Value is opaque: this example demonstrates TLV framing, not NDEF validation.

The supported file corpus lives in
[`examples/nfc/type2`](https://github.com/marekcingel/OpenTLV/tree/main/examples/nfc/type2).
It includes this sample, control TLVs, empty Values, short/extended length
boundaries, reserved identifiers, and malformed inputs. The corpus README
documents the bytes, expected Elements, and synthetic provenance. Integration
tests read the checked-in files and independently verify decoding, encoding
from expected Elements, and Reader -> Element -> Writer byte equality.

With `OPENTLV_BUILD_CLI=ON` and `OPENTLV_NFC=ON`, run from the repository root:

```sh
otlv decode --format nfc-type2 --input examples/nfc/type2/sample.bin
```

The JSON contains `00` and `FE` as empty Values and the `03` Value as
`D101055402656E4869`. CLI format selection is explicit; no format detection
or NDEF interpretation is performed. `otlv formats` and shell completion
include `nfc-type2` when enabled. See the corpus README for binary re-encoding.

## Bindings

| Binding | Preset | Availability |
| --- | --- | --- |
| C++ | `tlv::nfc_type2_format()` | `OPENTLV_NFC` |
| Python | `Format.NFC_TYPE2` | Present when native `HAS_NFC` is true |
| Rust | `Format::NfcType2` / `"nfc-type2"` | Default-enabled Cargo feature `nfc` |
| Lua | `opentlv.formats.nfc_type2` | Present when `OPENTLV_NFC` is enabled |
| WASM/JavaScript | `"nfc-type2"` | Listed in instance `formats` when compiled in |

All use the C format through their existing operations. None interprets NDEF
or automatically stops traversal at Terminator.

## Generic composition

The NFC implementation is immutable configuration over
`tlv_escaped_format_t` from `tlv/formats/escaped.h`. This reusable format
combines fixed-width identifiers, configurable escape-prefixed lengths,
field ordering, count scope and an optional tag-only identifier table.
The standalone `tlv_escaped_length_read()` / `tlv_escaped_length_write()`
primitives in `tlv/field/escaped.h` also support different markers, count widths
and byte orders.
The minimum extended count and maximum count are configuration, not NFC
branches in the generic code.

`tlv_tagged_fields_composition_t` composes tag-only selection with arbitrary field
codecs. The existing DHCP binary composition delegates to this same mechanism.
Neither mechanism imposes protocol termination or padding policy. These
generic capabilities remain built when `OPENTLV_NFC=OFF`.
