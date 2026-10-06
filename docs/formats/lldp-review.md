# LLDP requirements, Format and runtime Layout review

<!-- markdownlint-disable-next-line MD033 -->
<a id="lldp-requirements-and-formatlayout-review"></a>

Architecture review for [#360](https://github.com/marekcingel/OpenTLV/issues/360).
[LLDP base support](lldp/README.md) now includes framing, definitions, structural
validation and value codecs through the combined #362/#363 implementation. The review found a decoded-identifier restriction;
the generic `TLV_TAG_BINDING_FORMAT` extension now allows canonical Type bytes
in immutable format storage. The follow-up #361 adds a reusable packed-field
primitive used by the LLDP adapter; it is independent of that storage extension.

Normative verification is deferred to separate work covering multiple formats.
It is outside the agreed scope of #360 and is not a closure criterion for this
architecture review. This scope decision does not establish IEEE conformance.

## Issue coverage

| Issue | Current coverage |
| --- | --- |
| [#360: requirements review](https://github.com/marekcingel/OpenTLV/issues/360) | Architecture assessment, layer mapping and generic Tag storage support are complete. Normative verification is tracked separately and does not block closure. |
| [#361: packed Field Encoding primitive](https://github.com/marekcingel/OpenTLV/issues/361) | Implemented as `tlv_packed_field_t` in `tlv/field/packed.h` with bounded unsigned extraction/insertion. LLDP uses it within its complete Format callbacks. |
| [#362: LLDP format and definitions](https://github.com/marekcingel/OpenTLV/issues/362) | Implemented with #363; see [combined coverage](lldp/README.md#coverage-of-362-and-363). Full normative verification remains separate. |
| [#363: schemas, codecs and conformance](https://github.com/marekcingel/OpenTLV/issues/363) | Base structural validator, value codecs, reference tests and C/C++ examples implemented. See the [conformance boundary](lldp/conformance.md); full IEEE conformance is not established. |

## Evidence and scope

The target is **IEEE Std 802.1AB-2016**, basic single-frame LLDPDU TLVs.
The [IEEE publication record](https://standards.ieee.org/ieee/802.1AB/6047/)
identifies this edition and its amendments. Amendments, LLDP agents, Ethernet
transport, MIB/YANG management and organisation-specific payload definitions are
outside this review's proposed implementation subset.

**Normative verification is incomplete.** The full 2016 standard could not be
retrieved during this review: IEEE Xplore required browser verification. The
public IEEE contributions below support preliminary requirements, but are not
a substitute for reading the published standard. Do not mark the candidate
normatively verified on this evidence alone. Completing that verification is
separate from closing the architecture scope of #360.

- [IEEE LLDP overview, slide 9](https://www.ieee802.org/1/files/public/docs2025/new-bottorff-lldp-for-lsvr-0425-v02.pdf)
  shows the packed header and Chassis ID, Port ID and TTL mandatory prefix.
- [IEEE-hosted organisational TLV proposal, 4.4](https://www.ieee802.org/1/files/public/docs2025/new-bottorff-lldp-tlvs-for-lsvr-0425-v00.pdf)
  describes Type 127, OUI, subtype and their lengths.
- [IEEE proxy discussion, Table 8-1 and Figure 8-11](https://www.ieee802.org/1/files/public/docs2024/60802-woods-proxy-considerations-1024-v02.pdf)
  reproduces the basic Type assignments and Management Address structure.
  Its table labels End of LLDPDU **optional**. The later
  [published-text excerpt](lldp/conformance.md#evidence) confirms optional End in
  10.2.3; full receive/padding semantics still need the complete edition.

## Preliminary wire requirements

The two-byte header carries Type in its upper seven bits and Length in its lower
nine bits. Value immediately follows it. Deriving byte operations from that
representation, independently of host byte order:

```text
type   = b0 >> 1
length = ((b0 & 1) << 8) | b1
b0     = (type << 1) | (length >> 8)
b1     = length & 0xff
```

Length counts Value octets, excluding the header: 0..511, with total element
extent 2 + Length. Type 127 Value starts with a three-octet OUI and one-octet
subtype; Length is 4..511, leaving 0..507 payload octets. Keep this prefix in
Value and retain Type 127 as the outer identifier. OUI/subtype dispatch belongs
to Definition/Codec composition, not a composite outer Tag.

## Deferred normative verification checklist

Clause references below are reading targets, not claims that their full text
was inspected. Record transmit requirements separately from receive/discard
behaviour during the separate normative verification work.

| Requirement | Reading target in 802.1AB-2016 | OpenTLV responsibility |
| --- | --- | --- |
| Bit/octet order, header packing, Length and maximum extent | 8.1–8.4 | Format; byte ranges in runtime Layout |
| Type 0: End of LLDPDU | 8.5.1 and LLDPDU receive procedures | Verify zero-length encoding, omission conditions, termination and padding handling; LLDP sequence consumer |
| Type 1: Chassis ID; Type 2: Port ID | 8.5.2–8.5.3 | Definition, subtype Codec, value-size Schema; verify identifier length and allowed subtypes |
| Type 3: Time To Live | 8.5.4 | Codec and Schema; verify two-octet value and shutdown semantics |
| Types 4, 5, 6: Port Description, System Name, System Description | 8.5.5–8.5.7 | Definition, text Codec and value-size Schema |
| Type 7: System Capabilities | 8.5.8 | Codec and Schema; verify bitmap relationships and length |
| Type 8: Management Address | 8.5.9 | Codec for address, interface and OID subfields; verify internal lengths |
| Types 9–126: reserved; Type 127: organisational extensions | Table 8-1, 8.6 | Definition and extension dispatch; preserve unknown Values in the framing layer |
| Mandatory prefix, optional order, duplicates and repeated management addresses | LLDPDU structure, individual TLV usage rules and receive procedures | Schema composition plus an LLDP sequence validator |
| OUI/subtype namespace, multiplicity and unknown extensions | 8.6 and each selected extension specification | Definition, Codec and extension-specific validation |
| Nested TLVs | Basic Value definitions and each selected extension | Explicit child Codec/Format only when specified; no automatic descent based on Type 127 |

Management Address has internal length-delimited fields; that alone does not
establish a nested sequence of LLDP TLVs. This review does not establish that
every organisational extension is flat. A later adapter should leave Values
opaque (`is_constructed = NULL`) until a separately reviewed extension explicitly
selects a child format and payload boundary.

## Mapping to the current implementation

| Layer | LLDP mapping and current fit |
| --- | --- |
| Definition | Describe the Type namespace; describe OUI/subtype namespaces separately. No wire packing in definitions. |
| Format | Full `decode`, `measure`, `encode` callbacks unpack/pack the two-byte header with `tlv/field/packed.h` and validate bounds. Canonical decoded Tags use `TLV_TAG_BINDING_FORMAT` as described below. The helpers in `tlv/formats/compose.h` compose sequential byte fields; LLDP supplies complete callbacks for its shared packed header. |
| Layout | Header `[0,2)`, Value `[2,2+L)`, empty Trailer at `2+L`. Runtime byte ranges cannot express individual bits; Header retains all original bits. |
| Element | Proposed Tag is one stable byte `{type}` in 0..127; Value borrows the complete information string. Logical Length is `element.value.size`; there is no separate `element.length` member. |
| Schema | Existing length and occurrence bounds are useful after Tag identity is resolved. Current sequence ordering alone cannot express the complete LLDP grammar. |
| Codec | Interpret identifiers, TTL, text, capability flags, management-address subfields and organisational payloads. Framing must remain usable without these codecs. |

### Original restriction: canonical Tag versus source range

The [decoded identifier contract](../concepts/format-contract.md#decoded-identifier-consistency)
and `tlv_format_decode()` in `tlv/src/format.c` originally required a present `source.tag`
to have exactly the same pointer and size as `element.tag`. An absent source
Tag required an absent semantic Tag. A successful callback result was rejected
with `TLV_ERR_INVALID_ARG` otherwise.

For Type 1, these illustrative headers encode lengths 1, 255 and 256:

```text
02 01    02 ff    03 00
```

All must yield the same semantic identifier `{01}`. Neither a one-byte slice
nor a two-byte slice of these headers does that. Borrowing the first byte leaks
the high Length bit into identity; borrowing both bytes makes identity depend
on the entire Length. Arbitrary Value bytes cannot supply the identifier either.

A static immutable table of canonical Type bytes would avoid allocation and
mutable scratch storage, but the original source-pointer check rejected it.
Marking `source.tag` absent did not bypass that check. Returning stack storage
or reusing mutable context storage would also violate lifetime requirements.
Calling a callback directly to bypass validation is not Reader integration.

This is a generic semantic-identifier/source-location restriction, not a need
for LLDP branches in Reader, Writer, Document or Query. A raw-header identifier
is not an acceptable substitute for the requested Type identity.

### Schema and LLDPDU boundaries

`tlv_structure_schema_t` provides occurrence bounds and either unordered or
sequence-ordered rules. Sequence order applies to matched rules; permitted
unknown tags are unconstrained. It therefore cannot by itself prove an exact
mandatory prefix followed by freely ordered optional TLVs and a termination
boundary. Sorting all optional types into rule order would overconstrain them.

Use an LLDP-specific sequence consumer above Reader to establish the TLV region,
check the prefix/termination policy once verified, and apply schemas to the
appropriate regions. Treat Ethernet padding outside that region. Generic
Reader/Document/Query must not learn that Type 0 ends an LLDPDU. Likewise,
OUI/subtype-specific occurrence checks require decoded Value context, not just
an occurrence bound on the shared outer Type 127.

## Decision and follow-up

The original #360 review selected a small LLDP adapter implementing the existing
three Format operations. The sequential field helpers cannot model this packed
header, but the callback signatures can. Follow-up #361 adds a deliberately
bounded `tlv_packed_field_t` primitive for fixed wire integers of 1..8 bytes,
used inside that adapter. It does not introduce a generic packed Format or a
bitstream framework. Canonical identifier mapping and protocol bounds remain
in LLDP. This helper does not address the separate identifier-storage restriction.

The implemented generic extension adds `tlv_source_t::tag_binding`. Direct
source binding remains the zero/default value with its existing strict checks.
`TLV_TAG_BINDING_FORMAT` explicitly allows semantic identifier bytes in immutable
format-supplied storage, independently of the optional wire Tag envelope. An
immutable table of 128 one-byte identifiers can therefore represent LLDP Type
without allocation. Header/Value/Trailer and all source envelopes remain bounded.
Bit-accurate highlighting is a separate optional metadata capability.

The packed-header integration fixture verifies identity across Length 255/256,
Length 511 and rejection of 512, truncated inputs, retained identifiers, source
preservation and semantic re-encoding. It also exercises Reader, Writer,
Query, Schema and Document without protocol branches. The fixture is not an
LLDP built-in and does not validate LLDP semantics.

The C++ aliases reuse the extended C source type. Rust's native declaration
matches the changed layout; its safe API exposes `Format::Lldp` with the default `lldp` Cargo feature.
Python copies semantic Tag bytes; Lua/WASM compile against the C headers.
Consumers must rebuild because `tlv_source_t` and `tlv_decoded_t` changed ABI.

The architecture scope of #360 is complete: LLDP requirements are mapped to
the generic layers, the canonical Tag restriction is resolved, and integration
tests exercise the shared contracts without protocol-specific core branches.

Separate normative verification work across formats should read the selected
edition and resolve every checklist item above, particularly End TLV omission,
duplicate handling and per-type bounds. The combined #362/#363 implementation now adds sequence validation and base
value codecs above the shared framing adapter. The validator accepts optional
End and rejects bytes following it because its input is the exact TLV region,
not an Ethernet frame. Unknown extensions remain opaque. See the documented
[subset and limitations](lldp/README.md) and [reference evidence](lldp/conformance.md).
No further generic core change was needed.
