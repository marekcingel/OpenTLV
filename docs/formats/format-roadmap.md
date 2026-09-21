# Format expansion candidates

[Back to documentation](../README.md)

This is a candidate catalogue, not a release schedule. The
[README checklist](../../README.md#format-and-profile-support) records built-in support.
Unchecked entries are not implemented; application-defined callbacks may already
support particular encodings. Each implementation needs a separate scope, chosen
specification edition, limits, and conformance tests before its checkbox is enabled.
**Listing a format here is not a commitment to implement it and is not a claim of
support.**

This page gives the overview: the scope rules, the catalogue tree, the shared framing
requirements, and the dependencies. The per-candidate detail (specification, subset,
components, limits, and what was checked) is in the
[format candidate catalogue](format-catalogue.md).

## Keep the core generic

Keep raw framing, nesting rules, structural schemas, value codecs, and protocol
semantics separate. Concrete adapters should remain selectable (each behind its own
build option, like `OPENTLV_FORMAT_BLUETOOTH_LTV`). Preserve caller-owned storage,
capacity checks, and zero-copy value reads in the C API.

The current callback contract reads a tag before resolving length/value bounds.
An adapter for packed headers, length-before-type framing, padding, or a length
that includes header bytes needs an explicit compatibility review. These formats
are candidates, not a claim that every one fits the existing callbacks unchanged.
Any contract extension should describe a reusable framing requirement rather than
introducing protocol-specific branches in the generic parser.

Users include only what they need: a build that does not enable a candidate must not
contain its code, and the same holds for language bindings. See
[include only what you need](../concepts/architecture.md#include-only-what-you-need),
including the current gap in the Rust bindings.

## Scope principle

OpenTLV covers **binary formats that are encoded as tag-length-value**. Human-readable
formats and binary formats with a different encoding model are not part of the
library. The only accepted variation is a different **ordering or packing of the TLV
fields** (for example length before type, or type and length sharing bits), which a
format adapter can describe. Non-TLV candidates are listed only to record why they are
excluded.

## How to read this catalogue

Every candidate has one **class**. Do not assume a protocol that carries "TLV" in
its name, or that runs over ASN.1, is BER-TLV.

| Class | Meaning |
| --- | --- |
| Adapter | A wire framing that needs a new selectable format adapter (reader/writer descriptors). |
| Profile over BER/DER | Reuses the existing [BER](asn1/ber.md) or [DER](../profiles/der/README.md) framing; the new work is schemas, nesting rules, dictionaries, or value codecs. |
| Adapter + profile | A new framing plus protocol-specific nesting, schemas, or codecs. |
| Not TLV | A binary encoding that is not TLV. Excluded from the library; recorded with a rationale. |
| Out of scope | Needs machinery the library will not grow (for example an ASN.1 PER codec with compiled schemas). |

Status markers used below and in the catalogue:

| Marker | Status |
| --- | --- |
| `[x]` | Implemented and built in. |
| `[ ]` | Candidate; not implemented; scope is understood well enough to list. |
| `[?]` | Candidate whose variant, edition, or scope still needs assessment. |
| `[-]` | Excluded: not TLV or out of scope, with the reason given in the catalogue. |

**Framing is not the protocol.** Supporting a framing (or the BER/DER parser) means
splitting bytes into tag, length, and value. It does not mean validating field
semantics, running a state machine, verifying signatures, or implementing the
protocol or card stack that carries the data. An entry becomes "supported" only for
the encodings and profile functions that its own page names.

## Components

The catalogue names the pieces a candidate would use or add. Each maps to existing code,
so a candidate's "components" show which layers stay separate.

| Component | Existing implementation | Role |
| --- | --- | --- |
| Format adapter | `tlv_reader_format_t` and `tlv_writer_format_t` in `tlv/formats/format.h`; the whole-element callbacks `read_element` and `write_header` handle any field order or packing | Splits bytes into tag, header, value and trailer, and writes a header. |
| Nesting predicate | `tlv_is_constructed_fn`, passed to the tree walker | Says which values contain children in the same format. |
| Structure schema | `tlv_schema_t` and `tlv_structure_schema_t` in `tlv/schemas/schema.h` | Length bounds, occurrence and membership rules. |
| DER schema | `tlv_der_schema_type_t` in `tlv/profiles/der_schema.h` | ASN.1 type rules with canonical DER semantics; a fixed, small subset. |
| Value codecs | `tlv/codec/codec.h` and `tlv/codec/structure.h` | Decode and encode value contents. |
| Dictionary | Tag tables like the [EMV profile](../profiles/emv/README.md) | Names and meanings for tags in one profile. |
| Mixed-format traversal | Not implemented; see [generic processing extensions](#generic-processing-extensions) | Choose a different format per nesting level. |

## Catalogue tree

```text
OpenTLV
├── Implemented (built in)
│   ├── [x] Default TLV, Fixed 1-byte TLV, Bluetooth LTV, configurable fixed-width (C++)
│   ├── [x] Application-defined callbacks
│   ├── [x] ASN.1 framing: BER-TLV, DER-TLV (+ strict values, schemas), CER-TLV
│   └── [x] Profile: EMV Contact Book 3 v4.4 (dictionary, schemas, codecs)
│
├── Candidates: reuse BER/DER (profile over BER/DER)
│   ├── ASN.1 notation (ITU-T X.680 series), the type layer above X.690
│   │   ├── [x] Small hand-authored DER schema subset (existing, see DER profile)
│   │   ├── [?] Wider X.680 type coverage and BER/CER schema variants
│   │   ├── [?] Open types (X.681/X.682 information objects and table constraints)
│   │   └── [?] Offline schema generator from ASN.1 modules (build tool, not runtime)
│   ├── Protocols using BER
│   │   ├── [?] LDAP (RFC 4511)
│   │   └── [?] SNMP (v1 / v2c / v3)
│   ├── ASN.1 profiles (DER unless noted)
│   │   ├── [ ] X.509 certificates and CRLs
│   │   ├── [ ] PKCS#1 keys, PKCS#8 keys, PKCS#10 requests
│   │   ├── [?] PKCS#7 / CMS / S/MIME (BER allowed; parts DER)
│   │   ├── [ ] OCSP
│   │   └── [?] Kerberos v5 messages
│   └── Smart cards and SIM
│       ├── [?] ISO/IEC 7816-4 BER-TLV data objects
│       ├── [?] GlobalPlatform beyond DGI (GET/STORE DATA, registry data)
│       └── [?] eSIM (GSMA SGP.22 / SGP.32 ES10 and profile package)
│
├── Candidates: new adapters
│   ├── Smart cards
│   │   ├── [ ] GlobalPlatform DGI (existing entry)
│   │   ├── [ ] EMV contactless kernels (existing entry)
│   │   ├── [?] ISO 7816-4 SIMPLE-TLV
│   │   ├── [?] SIM Toolkit COMPREHENSION-TLV (ETSI TS 102 223)
│   │   └── [?] NFC Forum Type 1/2 tag TLV container (holds NDEF)
│   ├── Networking, AAA and tunnelling
│   │   ├── [ ] RADIUS (existing entry; VSA and extended attributes are variants)
│   │   ├── [?] Diameter AVP (RFC 6733)
│   │   ├── [ ] PEAP TLV (existing entry)
│   │   └── [ ] NDN packet TLV (existing entry)
│   ├── Networking, link and routing
│   │   ├── [?] LLDP (IEEE 802.1AB)
│   │   ├── [?] IS-IS TLVs and sub-TLVs (ISO 10589 and extensions)
│   │   ├── [?] DHCPv4 options (RFC 2132, RFC 3396, RFC 3046)
│   │   ├── [?] DHCPv6 options (RFC 8415)
│   │   ├── [?] LDP (RFC 5036 and extensions)
│   │   └── [?] RFC 5444 TLV blocks (TLVs only)
│   ├── Telecommunications (3GPP)
│   │   ├── [?] PFCP information elements (TS 29.244)
│   │   ├── [?] GTPv2-C information elements (TS 29.274)
│   │   ├── [?] GTPv1-C information elements (TS 29.060)
│   │   └── [?] NAS standard IE formats (TS 24.007; message layouts stay with the caller)
│   └── IoT
│       └── [ ] OMA LwM2M TLV (existing entry)
│
└── Excluded (not TLV or out of scope)
    ├── [-] CBOR (RFC 8949)
    ├── [-] CWT (RFC 8392) and COSE (RFC 9052/9053), CBOR profiles
    ├── [-] QUIC frames (RFC 9000)
    ├── [-] NFC NDEF records (NFC Forum NDEF 1.0)
    ├── [-] RFC 5444 packet header, message header, and address blocks
    ├── [-] S1AP, X2AP, NGAP (ASN.1 aligned PER)
    └── [-] ASN.1 PER (X.691), OER (X.696), XER (X.693) as encoding rules
```

## Previously catalogued candidates

These entries existed before the expanded catalogue and are not repeated in the
[catalogue](format-catalogue.md). Variants and open questions for them follow the table.

| Area | Candidate | Intended boundary and reference |
| --- | --- | --- |
| ASN.1 | Remaining DER gaps | Beyond the implemented structural, `_strict` universal-value and schema-aware layers: the universal types strict mode still rejects, full calendar validation of time values, and schema constraints. See the [ASN.1 notation rows](format-catalogue.md#asn1-notation-itu-t-x680-series) and the [DER limits](../profiles/der/README.md#supported-scope). |
| ASN.1 | Remaining CER gaps | Canonical SET/SET OF ordering is not yet checked, and there is no schema-aware CER layer. [Current limits](../profiles/cer/README.md#supported-scope) |
| Smart cards | GlobalPlatform DGI | DGI field encoding and length handling, separately from APDU transport and card management. [Card Specification 2.3, section 11.1.12](https://globalplatform.org/wp-content/uploads/2018/03/GPC_Specification_v2.3.pdf) |
| Payments | EMV contactless | Separate kernel-specific scope and specification selection; not implied by the existing Contact Book 3 dictionary. [Current profile](../profiles/emv/README.md) |
| Networking | NDN | Packet TLV framing and explicit container rules; packet semantics belong in a separate profile. [NDN packet format](https://101.named-data.net/connectivity/packet-format/) |
| Networking | PEAP | Defined TLV structures, independently from TLS transport and authentication state machines. [Microsoft PEAP TLV](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-peap/fa418c4b-b11e-47a5-b86f-d74a9150b822) |
| Networking | RADIUS | Base attribute framing; the length includes Type and Length. Vendor-specific and extended attributes need separately defined coverage. [RFC 2865, section 5](https://www.rfc-editor.org/rfc/rfc2865.html#section-5) |
| IoT | OMA LwM2M TLV | Packed TLV headers and resource/container interpretation; separate from CoAP and device management. [LwM2M Core 1.2.2](https://www.openmobilealliance.org/release/LightweightM2M/V1_2_2-20240613-A/HTML-Version/OMA-TS-LightweightM2M_Core-V1_2_2-20240613-A.html) |

Variants and open questions that these entries need before scoping:

| Entry | Variants to decide | Check |
| --- | --- | --- |
| GlobalPlatform DGI | A DGI is coded on two bytes followed by a length indicator whose coding is defined in the GlobalPlatform scripting language specification (annex B), not in the Card Specification. That document and the later Card Specification editions must be read before scoping. | Verified: Card Specification v2.3 clause 11.1.12. The scripting specification was not read. |
| EMV contactless | Kernel-specific: the contactless books define several kernels; each needs its own dictionary and edition. Book 3 data objects are already covered by the [EMV profile](../profiles/emv/README.md). | Not verified: EMV contactless books not read. |
| RADIUS | Base attributes (RFC 2865), the Vendor-Specific attribute (type 26, vendor ID followed by vendor type and length), extended attribute types ([RFC 6929](https://www.rfc-editor.org/rfc/rfc6929.html): Extended-Type-1 to 3 and the Long Extended Type), and long-attribute fragmentation. [Diameter](format-catalogue.md#networking-aaa-and-tunnelling) is a sibling candidate. | Verified: RFC 2865 vendor-specific layout and RFC 6929 extended-type structure. |
| NDN | Packet specification revision, variable-length number encoding for both type and length, and which packet types get explicit container rules. | Not verified: NDN specification not read. |
| LwM2M TLV | The TLV content format appears across several LwM2M releases; pick one release and record differences. | Not verified: LwM2M specification not read. |

## Framing requirements

These are reusable requirements collected from the candidates. Not one of them is a
commitment. The **fit** column is by inspection of the callback contract in
[`format.h`](../../tlv/include/tlv/formats/format.h): `read_element` sees the bytes from
the start of an element and reports the tag, the header size, the value size and the
trailer size; `write_header` writes only the header. A tag is 1 to `TLV_TAG_CAPACITY`
(8) raw bytes. **No candidate has been prototyped against these callbacks.**

| Requirement | Seen in | Fit with the current callbacks |
| --- | --- | --- |
| Length before type, or any other field order | Bluetooth LTV (implemented) | Covered by `read_element` and `write_header`. |
| Bit-packed type and length, or flag bits sharing a field | LLDP, LDP, RFC 5444, NAS half-octet IEIs | `read_element` sees the whole header, and `write_header` can encode it. The adapter must define the tag bytes (masked or unmasked flags). |
| Length includes the header | RADIUS, Diameter | The adapter subtracts the header size to get `value_size` and rejects a length smaller than the header. |
| Trailing padding after the value | Diameter | Reading fits `trailer_size`. **The writer has no trailer or padding hook**: `write_header` cannot emit bytes after the value, so writing would need a core extension or caller-added padding. |
| Header size depends on the type or flags | PFCP (enterprise ID), GTPv2 (type 254), GTPv1-C (TV versus TLV), RFC 5444 (flags) | `header_size` is reported per element, so this fits. GTPv1-C needs a type-to-length table in the borrowed descriptor context. |
| Elements without a length, and a terminator | DHCPv4 Pad and End, NFC tag TLV NULL and Terminator | Each can be read as a header-only element, but the walker has no built-in "skip padding" or "stop at terminator" policy. Needs an explicit policy. |
| Composite tag identity (type plus instance, vendor or flags) | GTPv2, PFCP, LLDP, Diameter, RADIUS VSA, LDP | Raw tag bytes can carry it (PFCP type plus a 2-byte enterprise ID fits in 8 bytes); the meaning lives in the dictionary. |
| Grouped or nested elements decided by the type | PFCP, GTPv2, Diameter, IS-IS sub-TLVs, DHCPv4 option 82 | `tlv_is_constructed_fn` receives the format context and the tag, so a table in the context can decide; the flags and value are not visible to it. |
| Different formats at successive nesting levels | LDP, SNMP, SIM Toolkit | A caller can parse level by level today; automatic tree walking needs [mixed-format traversal](#generic-processing-extensions). |
| Fixed PDU header followed by a TLV region | IS-IS, DHCP, LDP, PFCP, GTPv2 | The header is outside the core; the caller passes the region. |
| Untagged positional fields | NAS imperative part | Not framing and not TLV: stays with the caller, see the [NAS row](format-catalogue.md#telecommunications). |
| Logical values split across several elements | DHCPv4 (RFC 3396), long RADIUS attributes | Conflicts with zero-copy: needs an explicit, caller-visible policy with no hidden allocation. |
| Mixed BER and DER strictness in one document | CMS | Profile-level checks on top of the BER reader; needs the BER schema variant. |

Every new adapter keeps caller-owned storage, capacity checks before any write, and
zero-copy value reads. A candidate that cannot meet this is not a fit for the library.

## Generic processing extensions

- **Mixed-format child traversal:** select child formats and nesting rules explicitly
  using application context; current traversal uses the same format for descendants.
- **Incremental parsing:** resume across input chunks with clear incomplete-input
  status, buffer ownership, and resource limits. Zero-copy views require their
  backing bytes to remain available; fragmented values need an explicit policy.

The current tree walker already handles nested values without a schema, using
bounded iterative traversal. It does not allocate an object tree. See
[architecture](../concepts/architecture.md#traversal-and-recovery).

## Proposed order

1. Assess DGI, NDN, and RADIUS as concrete adapters with different length rules.
2. Assess packed headers through LwM2M; derive any further generic contract
   extension from those requirements (reordered headers are covered by
   [Bluetooth LTV](bluetooth/README.md)).
3. Add mixed-format traversal and incremental parsing as separately scoped core work.
4. Expand semantic profiles and ASN.1 canonical validation with explicit standard
   coverage, independently of basic wire-format support.

These priorities are proposals. A format adapter can be useful without a full
protocol profile; enabling one must not imply the other is complete. The expanded
candidates in the catalogue are not ranked and have no schedule.

## Verification status

Every row in the [catalogue](format-catalogue.md) has a **Check** entry that says what
was read in the primary text. This is the summary of the documents read in full text.

| Read in the primary text | Used for |
| --- | --- |
| RFC 1157, 1195, 2132, 2315, 2865, 2986, 3046, 3396, 3417, 4120, 4511, 5036, 5280, 5305, 5444, 5652, 5912, 5958, 6733, 6929, 6960, 8017, 8392, 8415, 8551, 8949, 9000, 9052 | BER/DER statements, TLV layouts, restrictions and padding rules |
| 3GPP TS 24.007 v17.5.0, 29.060 v17.4.0, 29.244 v17.9.0, 29.274 v17.10.0, 36.413 v18.4.0, 36.423 v18.4.0, 38.413 v19.1.0 | IE formats and PER transfer syntax |
| ETSI TS 102 223 v17.7.0, ETSI TS 101 220 v17.2.0 | COMPREHENSION-TLV structure |
| GlobalPlatform Card Specification v2.3 | BER-TLV tags and lengths, DGI coding |

Not read, so classified from the specification family and marked `Not verified` in the
catalogue: ISO/IEC 7816-4, ISO/IEC 10589, IEEE 802.1AB, the NFC Forum documents, GSMA
SGP.22 and SGP.32, the EMV contactless books, the NDN and LwM2M specifications, the
GlobalPlatform scripting language specification, and the ITU-T X.680 to X.696
recommendations. Re-check the clause and edition of any candidate when it is scoped.
