# Format and Element contract

This page extends the [canonical architecture overview](architecture.md#conceptual-model);
it specifies or audits these responsibilities without defining another model.

The [generic Format capability space](format-capabilities.md) introduces the
wire dimensions and distinguishes supplied configurations, custom callbacks,
future capabilities and protocol policy.

The format is the only layer that interprets wire mechanics. An element is a
canonical optional byte identifier and contiguous Value bytes; `value.size`
is its logical byte count, excluding framing. It has no raw Length member.
No numeric tag interpretation or host byte order is implied. `{NULL, 0}` is
an absent identifier; formats without an explicit Tag field are supported.

## Semantic content and source

`tlv_format_decode()` returns semantic content and separate source information.
`tlv_source_t` borrows the complete original bytes, Header/Value/Trailer ranges,
optional Tag/Length ranges, the original semantic content and originating
format descriptor. All source offsets are relative to that element's start.
Header, Value and Trailer are contiguous and partition the encoded range.
Additional header bytes and trailers remain available without adding protocol
fields to the semantic element.

The buffer, format and immutable context must outlive source information.
A format-supplied semantic identifier also borrows immutable storage that must
outlive every element, source, tag and shallow copy returned from decoding.
Never mutate the source buffer while a source is live. Struct copies copy only
borrowed descriptors, not bytes or ownership. The implementation cannot detect
external mutation of borrowed storage; immutability is a caller obligation.

## Encoding and preservation

For every successful bidirectional encoding:

```text
decode(F, encode(F, E)).element == E
```

Equality compares identifier presence/bytes and Value size/bytes, not pointers
or framing. Read-only and write-only capability groups remain possible.
Encoding regenerates framing according to the selected format/context policy.
BER normally writes minimal definite lengths; `tlv_format_ber_indefinite`
writes constructed elements with indefinite framing. CER chooses indefinite
framing for constructed identifiers. Strict canonical validation remains a
separate operation; framing equality does not promise application semantics.

Exact preservation is explicit:

```text
D = decode(F, W)
preserve(D.source, D.element) == W
```

`tlv_source_preserve()` verifies semantic equality and copies the original
encoded bytes. It rejects changed identifiers or values, including same-size
mutations. It supports a NULL/zero size query and overlapping copies. Changing
an element never updates or invalidates the old source bytes themselves; it
invalidates their association with the changed content.

For `04 81 01 AA`, preservation retains `81 01`. Changing Value to `BB CC`
requires fresh encoding; ordinary BER produces `04 02 BB CC`. No stale raw
length or checksum is silently reused. Reusing representation preferences after
mutation must be explicitly implemented by a format policy and revalidated;
source preservation never performs that operation or falls back to encoding.
Conversion to another format is fresh encoding, and fails if the destination
cannot represent the identifier/content. Identifier mapping is not implicit.
Canonical transformations that change Value bytes are separate content
transformations, not semantic identity at this boundary.

## Field ordering and length scope

Format owns wire representation rules and composes reusable Field Encoding
mechanics with field ordering and framing. Reader and Writer delegate decoding
and encoding to Format; they do not interpret field order. Layout records the
resulting source ranges, while Element retains only the semantic identifier
and Value. Schema does not select wire field order.

The existing generic field composition supports two orders, with Value last:

- `TLV_ELEMENT_ORDER_TLV`: Type (Tag), Length, Value.
- `TLV_ELEMENT_ORDER_LTV`: Length, Type (Tag), Value.

These are defined compositions, not configurable arbitrary field permutations.
Formats requiring other arrangements can implement the canonical Format
operations while preserving the same Element and source contracts. Reusable
mechanics belong in generic primitives; protocol wire restrictions belong in
the corresponding Format implementation.

Field order and length scope are independent. `TLV_LENGTH_SCOPE_VALUE` counts
only Value bytes; `TLV_LENGTH_SCOPE_TAG_AND_VALUE` counts the encoded identifier
and Value bytes, excluding the Length field itself. Both orders support both
scopes. In every case, `element.value.size` counts only Value bytes.

For one-byte Type and Length fields, these inputs describe the same semantic
Tag `09` and Value `41 42`:

| Composition | Length scope | Wire bytes | Tag offset | Length offset |
| --- | --- | --- | --- | --- |
| TLV | Value | `09 02 41 42` | 0 | 1 |
| LTV | Value | `02 09 41 42` | 1 | 0 |
| Bluetooth LTV | Tag and Value | `03 09 41 42` | 1 | 0 |

All three have Header `[0, 2)`, Value `[2, 4)` and a present empty Trailer at
offset 4. Their Elements compare equal by identifier and Value bytes, even
though their borrowed pointers and original wire representations differ.
[Bluetooth Advertising Data](../formats/bluetooth/README.md) uses the third
configuration; Type `09` identifies a Complete Local Name, here `AB`.
This demonstrates framing equivalence without requiring a Definition lookup
or interpreting Value during decoding.

Use `tlv_fixed_format_init()` with `identifier.size = 1`, `length.size = 1`, an explicit
`length.byte_order`, and the selected `element_order` and `length_scope` to reproduce
these compositions. Fixed delegates to the generic binary-field composition;
custom field encodings can use `tlv_field_composition_t` and `tlv_fields_format_init()`.
Format configuration must outlive its descriptor and all retained sources.

Encoding an Element uses the destination Format's order and count scope.
Explicit `tlv_source_preserve()` (or `tlv_writer_preserve()`) instead reproduces
the original bytes for unchanged semantic content. Source ranges describe
that original representation, not a later encoding in another Format.

The regression test `EquivalentElementsKeepTheirOwnLayoutAcrossOrdersAndScopes`
in `tests/integration/formats/format_fixed_test.cpp` checks these examples,
source ranges, explicit preservation and encoding each decoded Element into
each destination composition through the shared Reader/Writer APIs. Existing
Fixed and Variable tests cover both orders crossed with both length scopes;
Tree Reader and Tree Writer tests exercise LTV through the same upper layers.
NFC Type 2 support and its control rules are outside this ordering contract's
validation scope.

## Field Encoding and Format composition

Field Encoding provides individual-field mechanics under `tlv/field/`:

| Level | Public headers and responsibility |
| --- | --- |
| Low-level bit, byte and integer primitives | `tlv/field/packed.h` extracts and inserts unsigned fields within backing integers. Shared byte-order primitives remain in `tlv/endian.h`. |
| Identifier and Length encodings | `tlv/field/encoding.h` defines the read/write callback contracts; `tlv/field/fixed.h`, `tlv/field/variable.h` and `tlv/field/escaped.h` provide standalone encoding primitives. |

Format composition owns ordering, count scope, tag-only selection and optional
boundary resolution. Its types, callbacks and initializers live in
`tlv/formats/compose.h`. The complete Fixed, Variable and Escaped configurations
and their adapters remain under `tlv/formats/`. Field primitives do not depend
on these complete formats, Reader, Writer, Document, Schema, Codec or builtins.
Generic composition helpers are optional; an implementation may supply the same
complete Format contract directly. Reader and Writer use that contract without
requiring Definition, Schema or Codec. Writer encodes an Element without needing
a previously parsed source Layout. Codec converts between Value bytes and
application values; Identifier and Length mechanics are field encodings.

The [standalone fixed-field primitives](../formats/fixed/configurable.md#standalone-field-encoding)
preserve identifier bytes and read/write unsigned `tlv_size_t` counts with
explicit byte order. Binary composition adapts them to field callbacks and
retains ordering, count normalization, bounds resolution, tag-only selection,
source ranges and element-relative errors. The Escaped format reuses the same
fixed identifier primitive. All adapters follow the canonical single-field
contract: required pointers, configuration, field constraints, then capacity.
Argument/configuration failures preserve outputs, including `consumed`;
incomplete input reports the available prefix. Measuring validates the real
configuration, including count byte order.

## Format operations

The descriptor has one decode operation, one measure operation and one encode
operation. Reader and Writer have no alternate field-callback path. Field
composition is a public Format primitive (`tlv_field_composition_t`); fixed binary
fields use `tlv_binary_composition_t`. Identifier-selected tag-only framing uses
`tlv_tagged_fields_composition_t` or `tlv_tagged_binary_composition_t`.
TLV and LTV use the same composition with explicit order and count scope.
Bluetooth does not depend on Fixed internals.

Packed fields sharing a wire integer use `tlv_packed_field_t` from `tlv/field/packed.h`.
It describes 1..8 backing bytes, explicit byte order, bit offset counted from
the decoded integer's least significant bit, and bit width. The read/write
helpers operate on unsigned `uint64_t` values and require the complete backing
storage. Writes preserve other bits, reject values that do not fit, and leave
the destination unchanged on failure. Initialize storage before first insertion.
For example, two fields in a three-byte little-endian header can be composed as:

```c
const tlv_packed_field_t kind = {3, 13, 11, TLV_BYTE_ORDER_LITTLE_ENDIAN};
const tlv_packed_field_t count = {3, 0, 13, TLV_BYTE_ORDER_LITTLE_ENDIAN};
uint8_t header[3] = {0};
tlv_result_t rc = tlv_packed_field_write(&kind, header, sizeof(header), 5);
if (rc == TLV_OK)
    rc = tlv_packed_field_write(&count, header, sizeof(header), 300);
```

These helpers encode individual fields. Format composition and complete Format
callbacks retain responsibility for Tag mapping and its storage lifetime,
logical Length semantics, Value bounds and diagnostics. LLDP uses this primitive
without depending on Fixed or changing the canonical Format operations.

Decode must validate the entire framing, including a required trailer, before
publishing a result. BER indefinite scanning resolves matching nested EOC in
the ASN.1 implementation. An outer EOC is Trailer; a nested EOC remains part of
the enclosing Value. Formats may have an empty Header or no explicit Tag/Length.
Successful decoding must consume at least one byte so sequential reads progress.

Failure detail comes from the original operation: region, position, available
field ranges and known logical requirements. Unknown is distinct from zero.
Only in-buffer ranges can describe borrowed data. Generic diagnostics translate
relative positions and never infer wire rules from an error code.

## Size domains

Logical Value and planned encoded sizes use `tlv_size_t`, always unsigned
64-bit. `tlv_format_measure()` works before a native destination exists and
reports Header, Value, Trailer and their checked total. It accepts a null Value
pointer for content-independent queries; content-dependent formats require
readable content even for exact sizing.

Actual buffer extents, field ranges, offsets and consumed/written counts use
`size_t`. Narrow only after validation. `tlv_element_encoded_size()` is Writer's
native-sized measurement of a complete semantic Element. `tlv_encoded_size()`
is its tag/length convenience wrapper for content-independent queries. Neither
replaces logical measurement or allocates output storage.

- `TLV_ERR_OVERFLOW`: logical arithmetic exceeds the logical size domain.
- `TLV_ERR_INVALID_LENGTH`: the quantity is invalid for the wire encoding.
- `TLV_ERR_NATIVE_SIZE`: a valid logical size exceeds the native address space.
- `TLV_ERR_BUFFER_TOO_SHORT`: the concrete buffer is insufficient.

Wire integer byte order is explicit and independent of the host. A format's
accepted logical range must not silently change between 32-bit and 64-bit builds.

## Migration

For the Field Encoding / Format composition split (#423), replace
`tlv/layout.h` with `tlv/formats/compose.h` for composition and the appropriate
`tlv/field/` header for individual-field operations. Rename the four configuration
types ending in `_layout_t` to `_composition_t`: `tlv_field_composition_t`,
`tlv_binary_composition_t`, `tlv_tagged_fields_composition_t` and
`tlv_tagged_binary_composition_t`. There are no compatibility headers or aliases.
Fixed/binary configurations now embed `identifier` and `length` field
configurations: use `identifier.size`, `length.size` and `length.byte_order`.
Escaped Format replaces `tag_size` with `identifier.size`; Escaped Format and
generic field composition rename `order`/`scope` to `element_order`/`length_scope`.
Convert positional initializers to nested braces, for example
`{{1}, {2, TLV_BYTE_ORDER_BIG_ENDIAN}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE}`.
There are no compatibility members. Rebuild native consumers and FFI mirrors.

Adapters follow Field Encoding validation: a mismatched nonempty tag with NULL
bytes returns `TLV_ERR_NULL_ARG`; invalid length configuration preserves
`consumed`; direct binary/tagged-binary measurement rejects unsupported byte
order when a Length is present. Tag-only elements do not process a Length.
Incomplete fixed/variable identifiers now report their available prefix.
Fixed initialization returns `TLV_ERR_NULL_ARG` for missing pointers and checks
field configuration before composition policy. NULL output with nonzero capacity
is rejected by field writes, including tag-only callback writes. Valid wire
representations, borrowing and runtime source-range meanings are unchanged.

Rebuild all consumers: `tlv_source_t` now includes `tag_binding`, which also
changes the layout of `tlv_decoded_t`. Existing decoders retain direct source
binding when this field is zero; zero-initialize callback results. Earlier
format migrations also changed `tlv_format_t` and `tlv_element_t`.
Replace old format callback tables with canonical operations or public field
composition. No compatibility callback table remains. Obtain raw Length from
source ranges (`tlv_read_source_diag()` also returns reader diagnostics).
The historical nonstandard default/compact encoding has been removed, together
with its descriptor, header and build option. Select a named standard such as
BER, or configure Fixed explicitly for a protocol with fixed-width fields.
These formats are not wire-compatible replacements for every legacy input.

C++ provides `tlv::decode`, `measure`, `encode` and `preserve` in `tlv++/format.hpp`.
Rust separates semantic `Element` from `Decoded`, available through `decode()`
and `decode_fixed()`; raw Length belongs to `Decoded::raw_length()`.
Lua/WASM semantic visitor records no longer expose raw Length. Python's existing
raw-length inspection is populated from separate source information.

### Decoded identifier consistency

`source.tag_binding` makes identifier storage explicit:

- `TLV_TAG_BINDING_SOURCE` (zero/default): a present `source.tag` range must
  match `element.tag` in pointer and size. An absent range requires `{NULL, 0}`.
- `TLV_TAG_BINDING_FORMAT`: `element.tag` borrows immutable storage supplied by
  the format, such as a lookup table in its context or static storage. Its
  pointer must be non-NULL; zero size is an explicit empty identifier. The
  optional `source.tag` is only a byte envelope locating the encoded identifier;
  it may overlap Length and need not match semantic Tag size or bytes. An absent
  envelope means the wire location is unavailable, not that the Tag is absent.

Every present range still must fit inside the encoded element. Value always
borrows its exact source range. Unknown bindings, NULL format-bound Tags and
inconsistent direct bindings are rejected with `TLV_ERR_INVALID_ARG` without
publishing the decoded result.

Format-bound identifier storage must remain valid and unchanged for **all**
retained results, including after subsequent reads and shallow copies. Do not
return stack arrays, mutable scratch buffers or pointers into temporary decode
results. Core checks the binding and ranges, not the external storage's extent
or lifetime; these remain callback obligations. Arbitrary transformations that
cannot provide stable storage are not supported by this binding.

For a finite packed Type field, a format can return a one-byte identifier from
an immutable table while preserving the packed header as source bytes. The
identifier is a deterministic byte sequence, never a host integer or a raw
header with Length bits mixed into identity. No bit-field interpreter is added
to Reader or Writer.

Source preservation compares semantic Tag bytes and Value bytes with the
original semantic snapshot, independent of wire envelopes. Ordinary copies and
Writer encode semantic identifiers; Document copies their bytes into owned
nodes, and Query/Schema compare those bytes. Failure diagnostics remain raw
wire ranges: `error.tag` describes an envelope, not a transformed semantic Tag.

For zero-length identifiers, a NULL pointer denotes absence and a non-NULL pointer denotes an explicit empty field. Source preservation checks this distinction but does not compare non-NULL pointer addresses; the original source range retains the wire location.
