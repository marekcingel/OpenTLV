# LLDP TLV framing

[Format overview](../README.md) · [Requirements review](../lldp-review.md)

The LLDP built-in implements the packed Type/Length framing used by IEEE
802.1AB LLDP. The selected review target is IEEE 802.1AB-2016; full normative
verification is deferred to separate work across formats, outside #360, as
documented in the [review](../lldp-review.md).
This implementation provides framing and base Type names, not LLDPDU semantic
validation or an LLDP agent.

## API and build

| Setting | Value |
| --- | --- |
| C header | `tlv/builtins/lldp/lldp.h` |
| Descriptor | `tlv_format_lldp` |
| Definitions | `tlv_lldp_types`, lookup with `tlv_definition_find()` |
| C++ header/preset | `tlv++/builtins/lldp/lldp.hpp`, `tlv::lldp_format()` |
| CMake option | `OPENTLV_LLDP` (ON by default, independent of ASN.1 and Bluetooth) |
| Availability query | `tlv_config_lldp()` |

## Wire layout and logical model

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
For example, `06 02 00 78` becomes Tag `03` and Value `00 78`.

The adapter composes two `tlv_packed_field_t` configurations from `tlv/layout.h`:
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
- Schema checks for ordering, occurrences, End, and per-Type lengths, as well
  as value codecs, remain work for [#363](https://github.com/marekcingel/OpenTLV/issues/363).

Ordinary encoding regenerates the header. `tlv_source_preserve()` copies the
original encoded bytes only while semantic content remains unchanged. Reader,
Writer, Schema, Document and Query use the normal generic contracts; Query
addresses the canonical Type, for example `7F`, not its packed header byte `FE`.

## Presets in bindings

All presets select the shared C descriptor; bindings do not reimplement packing.

| Binding | Selection | Availability |
| --- | --- | --- |
| C++ | `tlv::lldp_format()` | Requires the LLDP C package |
| Rust | `Format::Lldp`, name `lldp` | Cargo feature `lldp`, enabled by default |
| Python | `Format.LLDP` | Member exists only when `opentlv_native.HAS_LLDP` is true |
| Lua | `opentlv.formats.lldp` | Field exists only when LLDP is built |
| JavaScript/WASM | `{ format: "lldp" }` | Listed in the loaded module's `opentlv.formats` only when built |

Rust's `--no-default-features` removes the LLDP preset and disables its C
package when building from source. For a prebuilt library selected through
`OPENTLV_LIB_DIR`, match the Cargo `lldp` feature to `OPENTLV_LLDP` in that library.
The Python native extension and its Python package must be rebuilt/updated
together. Lua and WASM currently expose parsing, so their presets do not add a
new writing API.

### C

```c
#include <tlv/builtins/lldp/lldp.h>
#include <tlv/reader/reader.h>

const uint8_t wire[] = {0x06, 0x02, 0x00, 0x78};
tlv_element_t element;
size_t consumed;
tlv_result_t rc = tlv_read(wire, sizeof(wire), &tlv_format_lldp, &element, &consumed);
/* On success: tag = {03}, value = {00, 78}, consumed = 4. */
```

### C++

```cpp
#include <tlv++/format.hpp>
#include <tlv++/builtins/lldp/lldp.hpp>

const tlv::byte wire[] = {tlv::byte{6}, tlv::byte{2}, tlv::byte{0}, tlv::byte{120}};
auto decoded = tlv::decode(tlv::lldp_format(), tlv::bytes(wire, sizeof(wire)));
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
