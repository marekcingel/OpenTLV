# Format and Element contract

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
framing for constructed identifiers. Strict profile validation remains a
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
Canonical profile transformations that change Value bytes are separate content
transformations, not semantic identity at this boundary.

## Format operations

The descriptor has one decode operation, one measure operation and one encode
operation. Reader and Writer have no alternate field-callback path. Field
composition is a public Format primitive (`tlv_field_layout_t`); fixed binary
fields use `tlv_binary_layout_t`. TLV and LTV use the same composition with
explicit order and count scope. Bluetooth does not depend on Fixed internals.

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
`size_t`. Narrow only after validation. `tlv_encoded_size()` is the native-sized
convenience wrapper; it does not replace logical measurement.

- `TLV_ERR_OVERFLOW`: logical arithmetic exceeds the logical size domain.
- `TLV_ERR_INVALID_LENGTH`: the quantity is invalid for the wire encoding.
- `TLV_ERR_NATIVE_SIZE`: a valid logical size exceeds the native address space.
- `TLV_ERR_BUFFER_TOO_SHORT`: the concrete buffer is insufficient.

Wire integer byte order is explicit and independent of the host. A format's
accepted logical range must not silently change between 32-bit and 64-bit builds.

## Migration

Rebuild all consumers: both `tlv_format_t` and `tlv_element_t` changed layout.
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
Lua/WASM semantic walker records no longer expose raw Length. Python's existing
raw-length inspection is populated from separate source information.
