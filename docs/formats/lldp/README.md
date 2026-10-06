# LLDP TLV support

[Format overview](../README.md) · [Requirements review](../lldp-review.md)

The LLDP built-in implements the packed Type/Length framing used by IEEE
802.1AB LLDP. The selected review target is IEEE 802.1AB-2016; full normative
verification is deferred to separate work across formats, outside #360, as
documented in the [review](../lldp-review.md).
The built-in provides framing, base Type names, LLDPDU structural validation and
allocation-free value codecs. It does not implement an LLDP agent.
The [reference and conformance notes](conformance.md) distinguish tested
contracts from the remaining full-edition normative audit.

## API and build

| Setting | Value |
| --- | --- |
| C header | `tlv/builtins/lldp/lldp.h` |
| Descriptor | `tlv_format_lldp` |
| Definitions | `tlv_lldp_types`, lookup with `tlv_definition_find()` |
| C++ header/preset | `tlv++/builtins/lldp/lldp.hpp`, `tlv::lldp_format()` |
| CMake option | `OPENTLV_LLDP` (ON by default, independent of ASN.1 and Bluetooth) |
| Availability query | `tlv_config_lldp()` |
| Structural API | `tlv/builtins/lldp/schema.h`: `tlv_lldp_schema`, `tlv_lldp_validate()` |
| Value codecs | `tlv/builtins/lldp/codec.h` |

<!-- markdownlint-disable-next-line MD033 -->
<a id="wire-layout-and-logical-model"></a>

## Wire representation and logical model

```text
15              9 8                 0
+----------------+-------------------+
| Type (7 bits)   | Length (9 bits)   |
+----------------+-------------------+
| Value: exactly Length octets ...   |
+------------------------------------+
```

The header is two bytes in big-endian order. Type is 0..127; Length is 0..511
and counts only Value bytes. Encoded size is `2 + Length`, at most 513 bytes.
The logical Tag is a **single byte containing Type**, independent of Length.
`ttl` and `text` are source aliases of `tlv_codec_uint16_be` and `tlv_codec_bytes`,
with no LLDP dispatcher or exported alias symbols. Field Schema owns the maximum
lengths for text, IDs and organisational Values. Standalone codecs therefore
accept representable Values beyond those limits; apply Schema before treating
them as valid LLDP fields. Compound codecs retain required prefixes, subtype
checks and inner-length consistency. Rebuild consumers of the former symbols.

For example, `06 02 00 78` becomes Tag `03` and Value `00 78`.

The adapter composes two `tlv_packed_field_t` configurations from `tlv/field/packed.h`:
Type uses offset 9 and width 7; Length uses offset 0 and width 9. Both use
two-byte big-endian storage. The primitive handles unsigned extraction and
insertion; the adapter maps Type to canonical Tag bytes and validates framing.

Decoded Tags borrow a static immutable table with `TLV_TAG_BINDING_FORMAT`.
Value borrows the original input. Source Header covers two bytes; the Tag wire
envelope covers the first byte and Length covers both bytes, so they overlap.
These raw envelopes are not canonical Tag bytes. Trailer is empty.

## Scope and errors

All Type/Length combinations in the framing ranges are representable, including
reserved Types and zero-length Values. This permits inspection of semantically
invalid LLDP data without making Schema a dependency of Reader.

- Type 0 is returned as an ordinary element; parsing does not stop automatically
  at End of LLDPDU. The caller supplies the TLV region and handles termination
  and Ethernet padding separately.
- Type 127 retains the entire OUI/subtype/payload sequence in Value. No vendor
  dispatch or nested TLV traversal is performed.
- Base names cover Types 0..8 and 127. Reserved Types 9..126 have no definition.
- Truncated headers or Values return `TLV_ERR_BUFFER_TOO_SHORT`. Non-single-byte
  Tags return `TLV_ERR_INVALID_TAG_SIZE`, Types above 127 `TLV_ERR_INVALID_TAG`,
  and Values larger than 511 `TLV_ERR_INVALID_LENGTH`.
- Structural and value checks are explicit APIs above framing, described below.
  Generic Reader, Writer, Document and Query never invoke them implicitly.

Ordinary encoding regenerates the header. `tlv_source_preserve()` copies the
original encoded bytes only while semantic content remains unchanged. Reader,
Writer, Schema, Document and Query use the normal generic contracts; Query
addresses the canonical Type, for example `7F`, not its packed header byte `FE`.

## Schema and sequence validation

`tlv_lldp_schema` is an ordinary `tlv_structure_schema_t` for base lengths and
occurrences. Use `tlv_lldp_validate(data, size, max_elements, diagnostic)` to
also check the mandatory prefix and End position. It delegates length and
occurrence rules to generic Schema, then checks sequence rules in the LLDP
module. No core Reader, Writer, Document or Query branch is needed.

| Type | Value length | Occurrence rule |
| --- | --- | --- |
| 0: End | 0 | Optional, at most once, last if present |
| 1: Chassis ID | 2..256 | Exactly once, first |
| 2: Port ID | 2..256 | Exactly once, second |
| 3: Time To Live | 2 | Exactly once, third |
| 4..6: Port Description, System Name, System Description | 0..255 | Each at most once |
| 7: System Capabilities | 4 | At most once |
| 8: Management Address | 9..167 | May repeat |
| 127: Organisationally Specific | 4..511 | May repeat |

Other Types are accepted after the mandatory prefix. Optional Types may appear
in any order. The input is the exact TLV region: bytes after End, including
Ethernet padding, are rejected. End may be omitted when the region ends after
a complete TLV. A TTL of zero is representable; agent shutdown behavior is
outside this library.

`max_elements` is a hard bound, including End and unknown TLVs; zero permits
no elements. Diagnostics use `tlv_diagnostic_t` with the first error's byte
offset and static descriptions. Missing fields use the end-of-region offset.
For an aggregate length/occurrence report, use generic
`tlv_schema_validate_all_diag()` with `tlv_lldp_schema`; that report does not include
the extra prefix/End-position checks.

The validator is strict structural validation, not the standard's agent
receive/discard procedure. It does not decode Value contents, compare repeated
management addresses, or enforce vendor-specific occurrence rules.

## Value codecs

Use the normal `tlv_codec_decode()` / `tlv_codec_encode()` APIs. A size query
uses NULL output and zero capacity. Descriptors are immutable, allocation-free,
and independent of the Format and Schema. Borrowed spans must outlive their
use. Input and output must not overlap.

| Descriptor suffix (`tlv_lldp_codec_`) | C representation | Behavior |
| --- | --- | --- |
| `chassis_id`, `port_id` | `tlv_lldp_id_t` | Subtype 1..7 plus a nonempty borrowed ID; separate MAC/network subtype namespaces; MAC length 6 and IPv4/IPv6 lengths checked |
| `ttl` | `uint16_t` | Generic uint16 BE alias, 0..65535 seconds |
| `text` | `tlv_value_t` | Types 4..6; generic bytes alias preserving arbitrary octets, including empty strings and embedded NUL, without character validation or a terminator |
| `capabilities` | `tlv_lldp_capabilities_t` | Two big-endian bitmaps; enabled must be a subset of supported; reserved bits preserved |
| `management_address` | `tlv_lldp_management_address_t` | Family, borrowed address, numbering subtype 1..3, big-endian interface number and borrowed OID; exact inner lengths and full consumption checked |
| `organisation` | `tlv_lldp_organisation_t` | Three OUI octets, subtype, and borrowed opaque payload; outer length checked by Schema; no vendor dispatch |

Management addresses contain 1..31 address octets, excluding the nonzero family
byte; IPv4/IPv6 use 4/16 octets. OIDs contain 0..128 opaque octets. Other address
families, non-address identifier syntax, character encodings, OID validity,
capability role restrictions and OUI ownership are not validated. These are
explicit limits of the supported value subset, not claims of full conformance.

For example, `06 02 00 78` is Type 3 with a two-byte Value: the TTL codec yields
120 seconds. `FE 06 00 80 C2 01 00 2A` is Type 127 with OUI `00 80 C2`, subtype
1, and opaque payload `00 2A`. `00 00` is the optional End marker.

## Coverage of #362 and #363

The combined implementation provides framing, definitions, structural rules,
value codecs, shared diagnostics and generic layer integration. The independent
build option is `OPENTLV_LLDP`, following the `OPENTLV_BLUETOOTH` package naming
convention. It removes all LLDP implementation sources when disabled.

Framing tests cover all 65,536 Type/Length combinations, canonical identity,
borrowed Values, exact source preservation and round trips. Codec and structural
tests cover bounds, malformed values, ordering, duplicates, End, diagnostics and
composition with Reader/Writer. Existing tests cover Document and Query. See
[reference and conformance notes](conformance.md) for provenance and the remaining
normative verification boundary.

## Presets in bindings

All presets select the shared C descriptor; bindings do not reimplement packing.

| Binding | Selection | Availability |
| --- | --- | --- |
| C++ | `tlv::lldp_format()` | Requires the LLDP C package |
| Rust | `Format::Lldp`, name `lldp` | Cargo feature `lldp`, enabled by default |
| Python | `Format.LLDP` | Member exists only when `_opentlv.HAS_LLDP` is true |
| Lua | `opentlv.formats.lldp` | Field exists only when LLDP is built |
| JavaScript/WASM | `{ format: "lldp" }` | Listed in the loaded module's `opentlv.formats` only when built |

Rust's `--no-default-features` removes the LLDP preset and disables its C
package when building from source. For a prebuilt library selected through
`OPENTLV_LIB_DIR`, match the Cargo `lldp` feature to `OPENTLV_LLDP` in that library.
The Python native extension and its Python package must be rebuilt/updated
together. Lua and WASM currently expose parsing, so their presets do not add a
new writing API.

### C

<!-- example: examples/tlv/src/lldp.c -->
```c
// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/builtins/lldp/lldp.h"
#include "tlv/builtins/lldp/schema.h"
#include "tlv/builtins/lldp/codec.h"
#include "tlv/reader/reader.h"

int main(void) {
    /* Local IDs "c"/"p", TTL 120 seconds, optional End. No Ethernet padding. */
    const uint8_t    wire[] = {2, 2, 7, 'c', 4, 2, 7, 'p', 6, 2, 0, 120, 0, 0};
    tlv_diagnostic_t diagnostic;
    tlv_reader_t     reader;
    tlv_element_t    element;
    tlv_result_t     rc;
    if (tlv_lldp_validate(wire, sizeof(wire), 16, &diagnostic) != TLV_OK) return 1;
    if (tlv_reader_init(&reader, wire, sizeof(wire), &tlv_format_lldp) != TLV_OK) return 1;
    while ((rc = tlv_reader_next(&reader, &element)) == TLV_OK) {
        if (!tlv_definition_find(&tlv_lldp_types, &element.tag)) return 1;
        if (element.tag.data[0] == 3) {
            uint16_t seconds;
            size_t   size;
            if (tlv_size_to_native(element.value.size, &size) != TLV_OK) return 1;
            if (tlv_codec_decode(&tlv_lldp_codec_ttl, element.value.data, size, &seconds,
                                 sizeof(seconds)) != TLV_CODEC_OK)
                return 1;
            if (seconds != 120) return 1;
        }
    }
    return rc == TLV_ERR_END_OF_BUFFER ? 0 : 1;
}
```

### C++

The C++ layer reuses the C semantic types and codecs, with the shared LLDP
Format preset for traversal.

<!-- example: examples/tlv++/src/lldp.cpp -->
```cpp
// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv++/tlv.hpp"
#include "tlv++/builtins/lldp/lldp.hpp"
#include "tlv/builtins/lldp/schema.h"
#include "tlv/builtins/lldp/codec.h"

int main() {
    const uint8_t    wire[] = {2, 2, 7, 'c', 4, 2, 7, 'p', 6, 2, 0, 120, 0, 0};
    tlv_diagnostic_t diagnostic{};
    if (tlv_lldp_validate(wire, sizeof(wire), 16, &diagnostic) != TLV_OK) return 1;
    size_t count = 0;
    try {
        for (auto element :
             tlv::lldp::parse(tlv::bytes(reinterpret_cast<const tlv::byte*>(wire), sizeof(wire)))) {
            if (element.tag() == tlv::tag_bytes<3>()) {
                uint16_t seconds = 0;
                auto     value = element.value();
                if (tlv_codec_decode(&tlv_lldp_codec_ttl,
                                     reinterpret_cast<const uint8_t*>(value.data()), value.size(),
                                     &seconds, sizeof(seconds)) != TLV_CODEC_OK ||
                    seconds != 120)
                    return 1;
            }
            ++count;
        }
    } catch (const tlv::parse_error&) {
        return 1;
    }
    return count == 4 ? 0 : 1;
}
```

### Rust

```rust
use opentlv::{Format, Reader};
let wire = [0x06, 0x02, 0x00, 0x78];
let element = Reader::with_format(&wire, Format::Lldp).next().unwrap().unwrap();
assert_eq!(element.tag().as_bytes(), &[3]);
```

### Python

```python
from opentlv import Format, Reader
element, = Reader(bytes.fromhex("06 02 00 78"), format=Format.LLDP)
assert bytes(element.tag) == b"\x03"
```

### Lua

```lua
local opentlv = require("opentlv")
for element in opentlv.reader(string.char(6, 2, 0, 120), opentlv.formats.lldp) do
    assert(element.tag == string.char(3))
end
```

### JavaScript/WASM

```javascript
// After loadOpenTLV() resolves to opentlv:
const result = opentlv.parse(new Uint8Array([6, 2, 0, 120]), { format: "lldp" });
console.assert(result.elements[0].tag === "03");
```
