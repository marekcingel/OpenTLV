# Format candidate catalogue

[Back to documentation](../README.md) · [Format expansion candidates](format-roadmap.md)

Per-area detail for the candidates in the [format expansion candidates](format-roadmap.md)
page, which also defines the [scope principle](format-roadmap.md#scope-principle),
[classes and markers](format-roadmap.md#how-to-read-this-catalogue), and the
[components](format-roadmap.md#components) named below. **Listing is not a commitment
to implement and is not a claim of support**; TLV framing support never means full
protocol support. Nothing on this page is implemented unless the roadmap tree marks it
`[x]`. See
[wire layouts of verified candidates](#wire-layouts-of-verified-candidates) for block
diagrams.

Columns: **Specification** is the primary document; the edition is chosen when the
candidate is scoped. **Subset** is the part suitable for OpenTLV. **Components** are the
building blocks from the roadmap that the work would use or add. **Reuse and limits**
covers existing support and API impact. **Check** records what was actually read in the
primary text: `Verified` means the framing statements in the row were read in the cited
document; `Partly` means some statements were read; `Not verified` means the document
was not read (with the reason) and the row is classified from the specification family.

## ASN.1 notation (ITU-T X.680 series)

[ITU-T X.680](https://www.itu.int/rec/T-REC-X.680/en) defines the abstract notation:
types, tagging environments, universal types, extensibility, and basic constraints.
[X.690](https://www.itu.int/rec/T-REC-X.690/en) defines how values of those types are
encoded (BER, CER, DER). OpenTLV's implemented BER/CER/DER framing and `_strict`
universal value checks work at the X.690 level. The schema-aware DER layer is a small,
hand-authored subset of X.680 type constructs
([current scope](../profiles/der/README.md#schema-aware-validation-and-encoding)):
universal types, `SEQUENCE`, `SEQUENCE OF`, `SET`, `SET OF`, `CHOICE`, `ANY`,
IMPLICIT/EXPLICIT tagging, `OPTIONAL`/`DEFAULT` components, and `SIZE`/value-range
constraints on a leaf. It is not an ASN.1 compiler. Every ASN.1 profile below
depends on how much of X.680 these rows cover.

| Candidate | Specification | Subset | Components | Reuse and limits | Check |
| --- | --- | --- | --- | --- | --- |
| `AUTOMATIC TAGS` / `COMPONENTS OF` | X.680 | Both are ASN.1 source-notation/compiler concerns resolved when a module is compiled, with no X.690 encoding-rule counterpart and no effect on binary content: `AUTOMATIC TAGS` is a convenience that assigns each component's context-specific tag number for the author, and `COMPONENTS OF` inlines another type's components by copy. A hand-authored `tlv_der_schema_type_t` table already states each component's explicit tag (or leaves it untagged) and already lists whatever components it needs, directly or by sharing entries; there is no distinct library capability to add. | None | None | Confirmed by inspection: out of scope per issue #310's own exclusion of "ASN.1 compiler functionality". |
| BER and CER schema variants (`[?]`) | X.680 with X.690 BER and CER rules | Schema-aware reading with BER leniency (indefinite lengths, non-canonical forms) and CER canonical rules. The schema layer is DER only today, and it is unconditionally strict. | DER schema (new BER and CER variants), structure schema | Needed by [CMS](#asn1-profiles), which mixes BER with DER-only fields, and by LDAP and SNMP. CER canonical SET/SET OF ordering is still open in the [README](../../README.md#format-and-profile-support). | Not verified: as above. |
| Open types (`[?]`) | [X.681](https://www.itu.int/rec/T-REC-X.681/en) (information object classes), [X.682](https://www.itu.int/rec/T-REC-X.682/en) (table constraints); PKIX modules in [RFC 5912](https://www.rfc-editor.org/rfc/rfc5912.html) | The `ANY DEFINED BY` replacement: a value whose type is selected by an identifier (usually an OID) elsewhere in the structure. Used by X.509 extensions, algorithm parameters, CMS attributes. | DER schema, dictionary | The existing `ANY` accepts one well-formed element with no semantics. Needs a caller-supplied resolution step (identifier to schema) with a bounded lookup; the API extension has to be assessed. | Partly: RFC 5912 read (it uses `TYPE-IDENTIFIER` for open types); the X.68x texts were not. |
| Offline schema generator (`[?]`, build tool) | X.680 module syntax; [X.683](https://www.itu.int/rec/T-REC-X.683/en) parameterization | A tool that turns ASN.1 modules into static schema tables so large modules are not hand-authored. Documented subset only. | tool (outside the runtime library) | The runtime library keeps no ASN.1 text parser. Hand-authored tables stay supported. Overlaps the planned runtime format definitions (OTDL) in the long-term [ROADMAP](../../ROADMAP.md); decide the relationship before any work. Module text is human-readable, so this stays a tool question, not a library one. | Not verified: as above. |

## Protocols using BER

| Candidate | Specification | Subset | Components | Reuse and limits | Check |
| --- | --- | --- | --- | --- | --- |
| LDAP (`[?]`) | [RFC 4511](https://www.rfc-editor.org/rfc/rfc4511.html), section 5.1 | `LDAPMessage` envelope and operation PDUs. Encoded with BER and three restrictions: definite length only, OCTET STRING primitive only, BOOLEAN true is `FF`. Not the LDAP schema (RFC 4512) or search behaviour. | BER format adapter (existing), structure schema, dictionary (operation tags), BER schema variant | Reuses BER reading and writing. The existing DER schema cannot be used because it is strict DER; LDAP needs the [BER schema variant](#asn1-notation-itu-t-x680-series). Not a directory client, TLS, or SASL. | Verified: RFC 4511 section 5.1. |
| SNMP (`[?]`) | v1 [RFC 1157](https://www.rfc-editor.org/rfc/rfc1157.html) (section 3.2.2); v2c and v3 transport [RFC 3417](https://www.rfc-editor.org/rfc/rfc3417.html) (section 8); v3 processing [RFC 3412](https://www.rfc-editor.org/rfc/rfc3412.html) | Message wrapper, PDUs, and variable bindings, one scope per version. Encoded with BER, definite length only, primitive form for simple types. | BER format adapter (existing), structure schema, value codecs (SMI application types), BER schema variant | Reuses BER. Application-tagged types need codecs. Not MIB compilation, USM cryptography, or an agent. | Verified: RFC 3417 section 8 and RFC 1157 restrictions. Application types not read. |

## ASN.1 profiles

| Candidate | Specification | Subset | Components | Reuse and limits | Check |
| --- | --- | --- | --- | --- | --- |
| X.509 (`[ ]`) | [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html) (PKIX profile of ITU-T X.509); DER per X.690 | `Certificate`, `TBSCertificate`, extensions, and CRL structures. | DER schema, value codecs (OID, time, names), dictionary (extension OIDs), open types | Reuses [DER schema-aware validation](../profiles/der/README.md#schema-aware-validation-and-encoding). Extension values need [open types](#asn1-notation-itu-t-x680-series). No path validation, revocation, or signature verification. | Verified: RFC 5280 states DER encoding. Field-level syntax not walked. |
| PKCS#1 (`[ ]`) | [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017.html) (v2.2), appendix A | `RSAPublicKey`, `RSAPrivateKey`, `DigestInfo`. `DigestInfo` is DER encoded. | DER schema, value codecs (INTEGER) | Reuses DER. Big INTEGERs stay as borrowed bytes; no arithmetic or RSA operations. | Verified: the three types and the `DigestInfo` DER statement in RFC 8017. |
| PKCS#8 (`[ ]`) | [RFC 5958](https://www.rfc-editor.org/rfc/rfc5958.html) (obsoletes [RFC 5208](https://www.rfc-editor.org/rfc/rfc5208.html), PKCS #8 v1.2) | `OneAsymmetricKey` (formerly `PrivateKeyInfo`) and the encrypted form. | DER schema | Reuses DER. Decrypting or parsing algorithm-specific key material is out of scope. | Verified: RFC 5958 (obsoletes RFC 5208; `OneAsymmetricKey`). |
| PKCS#10 (`[ ]`) | [RFC 2986](https://www.rfc-editor.org/rfc/rfc2986.html) (v1.7) | `CertificationRequest`. | DER schema | Reuses DER; shares name and extension schemas with X.509. No CA or enrolment logic. | Verified: `CertificationRequest` and the DER definition in RFC 2986. |
| PKCS#7 and CMS (`[?]`) | PKCS#7 [RFC 2315](https://www.rfc-editor.org/rfc/rfc2315.html) (v1.5); CMS [RFC 5652](https://www.rfc-editor.org/rfc/rfc5652.html) (section 5.3) | `ContentInfo`, `SignedData`, `EnvelopedData` and related structures. PKCS#7 v1.5 and CMS are separate scopes. | BER format adapter (existing), DER schema, BER schema variant | RFC 2315 is BER (single-pass indefinite-length encoding); in CMS the signed attributes MUST be DER even when the rest is not. This needs BER reading with per-field DER checks, that is, mixed strictness inside one message. No signature verification or encryption. | Verified: RFC 2315 (BER, indefinite length) and RFC 5652 section 5.3 (signed attributes DER). |
| S/MIME (`[?]`) | [RFC 8551](https://www.rfc-editor.org/rfc/rfc8551.html) (S/MIME 4.0; obsoletes RFC 5751) | Only the CMS payload. The MIME and base64 layers around it are text and stay out of scope. | as CMS | Depends on the CMS row. | Verified: RFC 8551 version and obsoletion. |
| Kerberos v5 (`[?]`) | [RFC 4120](https://www.rfc-editor.org/rfc/rfc4120.html), section 5.1.1 and appendix A | Ticket, `KDC-REQ`/`KDC-REP`, `AP-REQ`, `KRB-ERROR`. DER encoding; the ASN.1 module uses `EXPLICIT TAGS`. | DER schema, dictionary | Reuses DER with explicit application tags. Over TCP each message is preceded by a 4-byte length prefix (section 7.2.2), which is not TLV. No KDC, encryption, or key derivation. | Verified: sections 5.1.1 and 7.2.2 and the explicit-tags module header. |
| OCSP (`[ ]`) | [RFC 6960](https://www.rfc-editor.org/rfc/rfc6960.html) | `OCSPRequest` and `OCSPResponse`. DER encoded. | DER schema | Reuses DER and shares certificate schemas with X.509. HTTP transport, nonce handling, and response validation are out of scope. | Verified: DER statement and the HTTP body carrying the DER value. |

## Smart cards and SIM

| Candidate | Specification | Subset | Components | Reuse and limits | Check |
| --- | --- | --- | --- | --- | --- |
| ISO/IEC 7816-4 BER-TLV (`[?]`) | ISO/IEC 7816-4 (data objects clause; edition to be chosen) | BER-TLV data objects with the card-specific restrictions on tag and length forms. Related to the [EMV profile](../profiles/emv/README.md), which already uses BER. | BER format adapter (existing), nesting predicate, dictionary | Reuses BER. Which restrictions differ from generic BER needs a check against the paid text. APDU commands and file systems are out of scope. | Not verified: paid ISO document. |
| ISO/IEC 7816-4 SIMPLE-TLV (`[?]`) | ISO/IEC 7816-4 (same clause) | Single-byte tag, no constructed values. The length forms are to be confirmed. | format adapter | New adapter; it is not [Fixed 1-byte TLV](fixed/README.md) unless the length forms match. | Not verified: paid ISO document. |
| GlobalPlatform beyond DGI (`[?]`) | [Card Specification v2.3](https://globalplatform.org/wp-content/uploads/2018/03/GPC_Specification_v2.3.pdf) (later editions and amendments separately) | Data objects whose tags and lengths are "coded as defined by ASN.1 BER-TLV rules" (ISO 8825-1), for example in `GET DATA`, `STORE DATA`, tokens and registry data. Each data object family is a separate profile. | BER format adapter (existing), nesting predicate, dictionary | Reuses BER. Some length fields are BER with an extra allowance (a length of 128 may also be used). Not secure channel, key management, or life cycle. [DGI](format-roadmap.md#previously-catalogued-candidates) stays a separate adapter. | Verified: v2.3 text on BER-TLV tags and lengths; later editions not read. |
| SIM Toolkit COMPREHENSION-TLV (`[?]`) | [ETSI TS 102 223](https://www.etsi.org/deliver/etsi_ts/102200_102299/102223/) (read at v17.7.0), clause 8 and annex C; tag structure defined in ETSI TS 101 220 | Objects with a one-byte tag and a length coded on one or two bytes (`81` prefix for 128 to 255), carried inside a BER-TLV command object. `00` and `FF` are never tags and padding is not allowed. A Comprehension Required flag exists. | format adapter (new), mixed-format traversal, dictionary | The BER-TLV wrapper contains a second TLV form, so an automatic tree walk needs [mixed-format traversal](format-roadmap.md#generic-processing-extensions); a caller can already parse the wrapper and then the inner region separately. Whether the flag is part of the tag identity must be decided. No toolkit or terminal behaviour. | Verified: TS 102 223 v17.7.0 clause 8 and annex C. The position of the flag in TS 101 220 was not found in the v17.2.0 text read. |
| eSIM (`[?]`) | GSMA SGP.22 (Consumer RSP), SGP.32 (IoT); profile package by the Trusted Connectivity Alliance | ES10 command data and the profile package structure as ASN.1 values; each specification and edition is a separate scope. | DER schema, BER format adapter (existing), dictionary | Which parts are DER versus BER-TLV commands needs a check per edition. No RSP server, certificate chain, or profile installation. | Not verified: documents not read in this pass. |
| NFC Forum Type 1 and Type 2 tag TLV (`[?]`) | NFC Forum Type 1 and Type 2 Tag operation specifications | Tag memory TLVs: NDEF Message, Lock and Memory Control, NULL, and Terminator. The length forms are to be confirmed. | format adapter (new) | NULL and Terminator have no length and the terminator ends the region: needs a skip and stop policy (see [framing requirements](format-roadmap.md#framing-requirements)). The NDEF records inside are [excluded](#excluded-encodings). | Not verified: NFC Forum documents not read. |

## Networking, AAA and tunnelling

RADIUS, PEAP and NDN are [existing entries](format-roadmap.md#previously-catalogued-candidates).

| Candidate | Specification | Subset | Components | Reuse and limits | Check |
| --- | --- | --- | --- | --- | --- |
| Diameter AVP (`[?]`) | [RFC 6733](https://www.rfc-editor.org/rfc/rfc6733.html), section 4.1 | AVP framing: 4-byte code, flag byte, 24-bit length that includes the header, optional 4-byte vendor ID (V flag), data padded to a 32-bit boundary with the padding not counted in the length. Grouped AVPs nest. | format adapter (`read_element`, `write_header`), nesting predicate (grouped types), dictionary | Length includes the header; the trailing padding fits the reader's `trailer_size`, but the writer has no trailer hook (see [framing requirements](format-roadmap.md#framing-requirements)). Command dictionaries and applications are separate profiles. No peer state machine. | Verified: RFC 6733 section 4.1 and the padding rules. |

## Networking, link and routing

These protocols have a fixed PDU header followed by a TLV region. The header is not TLV;
a caller slices the region first.

| Candidate | Specification | Subset | Components | Reuse and limits | Check |
| --- | --- | --- | --- | --- | --- |
| LLDP (`[?]`) | IEEE Std 802.1AB-2016 | LLDPDU TLV region: 7-bit type and 9-bit length packed in two bytes; End of LLDPDU TLV; organisationally specific TLVs (OUI and subtype). | format adapter (`read_element`, `write_header`), dictionary | Packed bit fields (fit by inspection, see the roadmap). Composite tag for organisational TLVs. No LLDP agent or MIB. | Not verified: IEEE standard not read. |
| IS-IS (`[?]`) | ISO/IEC 10589:2002; [RFC 1195](https://www.rfc-editor.org/rfc/rfc1195.html); [RFC 5305](https://www.rfc-editor.org/rfc/rfc5305.html) (sub-TLVs); other extension RFCs per scope | TLV region after the PDU header: type, length, value with the length covering the value; sub-TLVs nest inside selected TLVs. | format adapter, nesting predicate (which TLVs hold sub-TLVs), dictionary | Framing is near [Fixed 1-byte TLV](fixed/README.md); the work is which TLVs contain sub-TLVs. Many extension RFCs: choose a base scope. No routing or SPF. | Partly: RFC 1195 (TLV length is the value length) and RFC 5305 (sub-TLVs) read; the field widths and ISO 10589 not verified. |
| DHCPv4 options (`[?]`) | [RFC 2132](https://www.rfc-editor.org/rfc/rfc2132.html), [RFC 2131](https://www.rfc-editor.org/rfc/rfc2131.html), [RFC 3396](https://www.rfc-editor.org/rfc/rfc3396.html), [RFC 3046](https://www.rfc-editor.org/rfc/rfc3046.html) | Options region: code and length, with Pad (0) and End (255) as the only options that are a single tag octet. Relay agent information holds sub-options in SubOpt/Len/Value form. | format adapter, nesting predicate (option 82), dictionary | Pad and End need a skip and stop policy. RFC 3396 splits one logical option across several occurrences to be concatenated: that conflicts with zero-copy reads and needs an explicit policy. No client or server. | Verified: RFC 2132 (Pad, End), RFC 3396, RFC 3046. |
| DHCPv6 options (`[?]`) | [RFC 8415](https://www.rfc-editor.org/rfc/rfc8415.html), section 21.1 | 16-bit code and 16-bit length that covers the data only; no padding; options nest. | format adapter (or [configurable fixed-width TLV](fixed/configurable.md), 2/2 big-endian), nesting predicate, dictionary | Verified framing similar to the configurable fixed-width format plus nesting rules. No client or server. | Verified: RFC 8415 section 21.1. |
| LDP (`[?]`) | [RFC 5036](https://www.rfc-editor.org/rfc/rfc5036.html); extensions such as capabilities are separate scopes | Three levels: PDU header (10 bytes), messages, TLVs. TLV header: U bit, F bit, 14-bit type, 16-bit length of the value only. | format adapter (`read_element`, `write_header`), mixed-format traversal, dictionary | The flag bits share the type field, so the tag identity must decide whether U/F are part of the tag. Multi-level nesting with a different format per level needs [mixed-format traversal](format-roadmap.md#generic-processing-extensions) for automatic walks. "LDP" here is the Label Distribution Protocol. No LSR behaviour. | Verified: RFC 5036 PDU and TLV layouts. |
| RFC 5444 TLV blocks (`[?]`) | [RFC 5444](https://www.rfc-editor.org/rfc/rfc5444.html); consumers include [RFC 6130](https://www.rfc-editor.org/rfc/rfc6130.html) (NHDP) and [RFC 7181](https://www.rfc-editor.org/rfc/rfc7181.html) (OLSRv2) | TLV blocks only: a 16-bit block length, then TLVs with type, flags, optional type extension, optional indexes, optional length and value. | format adapter (`read_element`), dictionary | The flags decide which fields exist, so the header size varies per element. Address-block index semantics are separate. The packet and message structure is [excluded](#excluded-encodings). No MANET routing. | Verified: RFC 5444 TLV block and TLV layout. |

## Telecommunications

All 3GPP specifications are free at the [3GPP archive](https://www.3gpp.org/ftp/Specs/archive/);
choose a release when scoping.

| Candidate | Specification | Subset | Components | Reuse and limits | Check |
| --- | --- | --- | --- | --- | --- |
| PFCP (`[?]`) | [3GPP TS 29.244](https://www.etsi.org/deliver/etsi_ts/129200_129299/129244/17.09.00_60/ts_129244v170900p.pdf) clause 8.1.1 (read at v17.9.0) | IE region: 2-byte type, 2-byte length that excludes the first four octets, optional enterprise ID for vendor-specific types (bit 8 of the type); grouped IEs nest. | format adapter (`read_element`, `write_header`), nesting predicate (grouped IE types), dictionary | The enterprise ID is counted inside the length and present only for types with bit 8 set, so the header size depends on the type. Message header and sessions are separate. No UPF/SMF behaviour. | Verified: TS 29.244 v17.9.0 clause 8.1.1. |
| GTPv2-C (`[?]`) | [3GPP TS 29.274](https://www.etsi.org/deliver/etsi_ts/129200_129299/129274/17.10.00_60/ts_129274v171000p.pdf) clause 8.2 (read at v17.10.0) | TLIV: 1-byte type, 2-byte length that excludes the first four octets, spare and 4-bit instance; grouped IEs nest; type 254 adds a type extension field. | format adapter (`read_element`, `write_header`), nesting predicate, dictionary | IE identity is type plus instance (composite tag). GTP-U and the message header are separate. No core-network behaviour. | Verified: TS 29.274 v17.10.0 clause 8.2. |
| GTPv1-C (`[?]`) | [3GPP TS 29.060](https://www.etsi.org/deliver/etsi_ts/129000_129099/129060/17.04.00_60/ts_129060v170400p.pdf) (read at v17.4.0) | IEs in two formats selected by the most significant bit of the type: TV (fixed length) and TLV. | format adapter with a type-to-length table in its borrowed context, dictionary | A TV element's size is known only from its type, so the descriptor context must carry the table. Older than GTPv2; assess demand first. | Verified: TS 29.060 v17.4.0 (TV/TLV type bit and fixed length of TV). TLV length width not read. |
| NAS (`[?]`, partly in scope) | [TS 24.007](https://www.etsi.org/deliver/etsi_ts/124000_124099/124007/17.05.00_60/ts_124007v170500p.pdf) (read at v17.5.0); message specifications [TS 24.301](https://www.3gpp.org/ftp/Specs/archive/24_series/24.301/) (EPS), [TS 24.501](https://www.3gpp.org/ftp/Specs/archive/24_series/24.501/) (5GS), [TS 24.008](https://www.3gpp.org/ftp/Specs/archive/24_series/24.008/) (2G/3G) | Only the standard information element formats T, TV, TLV, TLV-E (and the length-prefixed LV and LV-E): one-byte IEI or half-octet IEI, length of one octet (LV, TLV) or two octets (LV-E, TLV-E). Each generation and message type is a separate scope. | format adapter (new, per IE format), structure schema, dictionary | The imperative part of a message carries mandatory IEs without an identifier (V, LV, LV-E), so which element sits at which position comes from the message definition. That positional layout is not self-describing TLV: only the length-prefixed and tagged IEs are in scope, the rest stays opaque bytes for the caller. Assess against the existing [structure schemas](../guides/schemas.md). NAS security header and ciphering are out of scope. | Verified: TS 24.007 v17.5.0 clause 11.2 (IE formats, length indicator, imperative part). The message specifications were not read. |

## Wire layouts of verified candidates

Layouts for the candidates whose framing was read in the primary text. They show how
each format is arranged so its shape is clear before any adapter exists. Diagrams are
drawn from the cited specification; nothing here is implemented. "Adapter view" says
how the fields would map to the callback outputs of `read_element` (tag, header size,
value size, trailer size) by inspection of the contract, **not from a prototype**.

No diagram is given for candidates whose specification was not read (LLDP, IS-IS,
ISO 7816-4 SIMPLE-TLV, the NFC Forum tag TLV, eSIM), to avoid drawing fields that were
not checked.

### DHCPv4 options (RFC 2132, RFC 3046)

```text
Pad:         | 00 |                                  1 byte, no length
End:         | FF |                                  1 byte, no length
Option:      | Code | Len | Data ...                 1 + 1 + Len bytes
Sub-option:  | SubOpt | Len | Value ...              inside option 82 (RFC 3046)
```

`Len` does not include the code and length octets. Only options 0 and 255 have no length
octet. Adapter view: tag is the code, header size 2, value size `Len`; Pad and End are
header-only elements of size 1.

### DHCPv6 options (RFC 8415, section 21.1)

```text
+----------------+----------------+---------------------------+
| Option code    | Option-len     | Option data               |
| 2 bytes        | 2 bytes        | Option-len bytes          |
+----------------+----------------+---------------------------+
```

`Option-len` covers the data only and options follow each other with no padding.
Adapter view: tag is the 2-byte code, header size 4, value size `Option-len`. This is the
same shape as the [configurable fixed-width format](fixed/configurable.md) with a 2-byte
tag and length.

### LDP (RFC 5036, sections 3.1, 3.3 and 3.5)

```text
PDU header (10 bytes), followed by messages:
+-------------+----------------+------------------------------+
| Version     | PDU Length     | LDP Identifier               |
| 2 bytes     | 2 bytes        | 6 bytes                      |
+-------------+----------------+------------------------------+
PDU Length counts everything after the PDU Length field.

Message:
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-------------------------+-------------------------------+
|U|      Message Type       |        Message Length         |
+-+-------------------------+-------------------------------+
|                        Message ID                           |
+-------------------------------------------------------------+
| Mandatory Parameters, then Optional Parameters (TLVs)       |
+-------------------------------------------------------------+
Message Length counts the Message ID and the parameters.

TLV:
+-+-+-----------------------+-------------------------------+
|U|F|         Type          |            Length             |
+-+-+-----------------------+-------------------------------+
|                          Value ...                          |
+-------------------------------------------------------------+
Type is 14 bits; Length counts the value only.
```

Adapter view: for a TLV, the tag is the 14-bit type (whether the U and F bits belong to
the tag is an open decision), header size 4, value size `Length`. Messages and TLVs are
two different formats at two nesting levels.

### RFC 5444 TLV block (section 5.4)

```text
TLV block:  | tlvs-length 2 | tlv | tlv | ...         tlvs-length counts the TLVs

TLV:        | type 1 | flags 1 | type-ext 1? | index-start 1? | index-stop 1? | length 1 or 2? | value? |

flags (bit 0 is the most significant bit):
  bit 0 thastypeext        bit 3 thasvalue
  bit 1 thassingleindex    bit 4 thasextlen
  bit 2 thasmultiindex     bit 5 tismultivalue      bits 6-7 reserved
```

A `?` field exists only when the flags say so: `thastypeext` adds `type-ext`; a single
index adds `index-start`, a multi index adds both `index-start` and `index-stop` (address
block TLVs only); `thasvalue` adds an 8-bit length and `thasextlen` makes it 16 bits.
The full type is `256 * type + type-ext`. Adapter view: the header size varies per
element, and the tag can carry the type and the type extension.

### Diameter AVP (RFC 6733, section 4.1)

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+---------------------------------------------------------------+
|                           AVP Code                            |
+-+-+-+-+-+-+-+-+-----------------------------------------------+
|V M P r r r r r|                  AVP Length                   |
+-+-+-+-+-+-+-+-+-----------------------------------------------+
|                     Vendor-ID (only if V = 1)                 |
+---------------------------------------------------------------+
|  Data ...                                       | padding     |
+---------------------------------------------------------------+
```

`AVP Length` counts the header (including the Vendor-ID if present) and the data, but not
the padding. The data is padded to a 32-bit boundary. Grouped AVPs hold further AVPs in
their data, each with its own padding. Adapter view: tag is the code (plus the vendor ID),
header size 8 or 12, value size `AVP Length` minus the header, trailer size the padding.
The writer has no trailer hook (see
[framing requirements](format-roadmap.md#framing-requirements)).

### PFCP information element (TS 29.244 v17.9.0, clause 8.1.1)

```text
3GPP-defined:   | Type 2 | Length 2 | IE data (Length bytes) |             Type 0-32767

Vendor-defined: | Type 2 | Length 2 | Enterprise ID 2 | IE data |         Type 32768-65535
                                       (counted in Length)
```

`Length` excludes the first four octets, so the enterprise ID of a vendor IE is inside
the length. Bit 8 of the first octet (types from 32768) says the enterprise ID is present.
Grouped IEs carry further IEs in their data. Adapter view: tag is the type (plus the
enterprise ID for vendor IEs), header size 4 or 6, value size `Length` minus the
enterprise ID.

### GTPv2-C information element (TS 29.274 v17.10.0, clause 8.2)

```text
Normal:    | Type 1 | Length 2 | Spare 4 bits + Instance 4 bits | IE data |

Type 254:  | 254 | Length 2 | Spare + Instance | IE Type Extension 2 | IE data |
```

`Length` excludes the first four octets (type, length, and the spare/instance octet), so
the type extension of a type 254 IE is inside the length. IE identity is type plus
instance. Adapter view: tag is the type and instance (and the extension), header size 4
or 6.

### GTPv1-C information element (TS 29.060 v17.4.0, clause 7.7)

```text
TV  (type bit 8 = 0):  | Type 1 | Value (fixed length from the type) |

TLV (type bit 8 = 1):  | Type 1 | Length 2 | Value (Length bytes) |
```

`Length` excludes the type and length fields, and TV elements always have a fixed length.
Adapter view: the value size of a TV element comes from a type table, not from the data.

### NAS standard information element formats (TS 24.007 v17.5.0, clause 11.2)

```text
T      | IEI 1 |                                          no value
TV     | IEI 1 | Value ... |     (type 1: the IEI and the value are each a half octet)
LV     | LI 1 | Value 0-255 bytes |
TLV    | IEI 1 | LI 1 | Value 0-255 bytes |
LV-E   | LI 2 | Value 0-65535 bytes |
TLV-E  | IEI 1 | LI 2 | Value 0-65535 bytes |
V      | Value only, no IEI and no length |
```

`LI` counts the value octets. The imperative part of a message has mandatory IEs in the
`V`, `LV` or `LV-E` formats, and the optional part uses the tagged formats, so the
message definition decides which format an element has. Adapter view: only the formats
with an IEI and a length map to a tag, header and value; `V` fields stay opaque bytes for
the caller.

### SIM Toolkit (ETSI TS 102 223 v17.7.0, clause 8 and annex C)

```text
Command:  | BER-TLV tag 1 | Length 1 or 2 | COMPREHENSION-TLV objects ... |

Object:   | Tag 1 | Length 1 or 2 | Value (Length bytes) |
```

The length is one byte for 0-127 and `81 nn` for 128-255. Tags `00` and `FF` are never used
and padding is not allowed. The object tag carries a Comprehension Required flag.
Adapter view: two formats at two levels, the BER-TLV wrapper and then the objects inside
it; header size 2 or 3.

### Kerberos over TCP (RFC 4120, section 7.2.2)

```text
| Length 4 (high bit 0) | DER-encoded Kerberos message (Length bytes) |
```

The four-byte length prefix is not TLV and comes before the DER value, which uses the
[DER layout](asn1/der.md#layout-and-typical-use). The prefix belongs to the transport,
not to an adapter.

### GlobalPlatform DGI (Card Specification v2.3, clause 11.1.12)

```text
| DGI 2 bytes | Length indicator | Data |
```

A DGI is two bytes in binary followed by a length indicator whose coding is defined in
the GlobalPlatform scripting language specification, which was not read. The width of the
length indicator is therefore not drawn.

## Excluded encodings

These are excluded under the [scope principle](format-roadmap.md#scope-principle): none of
them is encoded as tag-length-value, so they are not candidates for the library. They are
listed so the reason is recorded.

| Encoding | Specification | Why it is excluded | Check |
| --- | --- | --- | --- |
| CBOR (`[-]`) | [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949.html) | A data item starts with a major type and an argument; arrays and maps count items, not bytes; lengths can be indefinite, ended by a break stop code. There is no tag/length/value element. | Verified: RFC 8949 major types and indefinite lengths. |
| CWT (`[-]`) | [RFC 8392](https://www.rfc-editor.org/rfc/rfc8392.html) | A CBOR profile (claims) protected with COSE; it depends on CBOR. | Verified: RFC 8392 title and abstract. |
| COSE (`[-]`) | [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html) (STD 96, obsoletes RFC 8152), [RFC 9053](https://www.rfc-editor.org/rfc/rfc9053.html) | CBOR structures; depends on CBOR. Cryptography is out of scope. | Verified: RFC 9052 identity and obsoletion. |
| QUIC frames (`[-]`) | [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html), section 12.4 and clause 19 | The frame type is a variable-length integer and the remaining fields are frame specific; only some frames carry a length and PADDING is the single type byte. A frame parser is a per-type decoder. | Verified: RFC 9000 frame type field and PADDING. |
| NFC NDEF records (`[-]`) | NFC Forum NDEF Technical Specification | Records use a flag byte followed by length fields whose presence depends on the flags. The tag TLV container that holds NDEF is a [separate candidate](#smart-cards-and-sim). | Not verified: NFC Forum document not read. |
| RFC 5444 packet, message, and address blocks (`[-]`) | [RFC 5444](https://www.rfc-editor.org/rfc/rfc5444.html) | Header-driven structures with head/tail compressed address blocks; the message size field includes the message header. Only the TLV blocks are a [candidate](#networking-link-and-routing). | Verified: RFC 5444 (message size includes the header). |
| S1AP, X2AP, NGAP (`[-]`) | [TS 36.413](https://www.etsi.org/deliver/etsi_ts/136400_136499/136413/18.04.00_60/ts_136413v180400p.pdf), [TS 36.423](https://www.etsi.org/deliver/etsi_ts/136400_136499/136423/18.04.00_60/ts_136423v180400p.pdf), [TS 38.413](https://www.etsi.org/deliver/etsi_ts/138400_138499/138413/19.01.00_60/ts_138413v190100p.pdf) | These specifications require the ASN.1 Basic Packed Encoding Rules, aligned variant, as transfer syntax. PER is bit-packed and depends on the compiled ASN.1 schema, so there are no self-delimiting tag/length/value elements. Other 3GPP RAN interfaces that use PER fall in the same category. | Verified: transfer syntax clause of TS 36.413 v18.4.0, TS 36.423 v18.4.0, TS 38.413 v19.1.0. |
| ASN.1 PER, OER, XER (`[-]`) | [X.691](https://www.itu.int/rec/T-REC-X.691/en), [X.696](https://www.itu.int/rec/T-REC-X.696/en), [X.693](https://www.itu.int/rec/T-REC-X.693/en) | Encoding rules for the same X.680 types but not TLV: PER is bit-packed, OER is octet-oriented with schema-driven layout, XER is human-readable text. Only the X.690 rules (BER, CER, DER) are TLV. | Not verified: ITU-T recommendations not read. |
