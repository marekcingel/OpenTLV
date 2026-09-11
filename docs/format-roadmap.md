# Format expansion candidates

[Back to documentation](README.md)

This is a candidate catalogue, not a release schedule. The
[README checklist](../README.md#format-and-profile-support) records built-in support.
Unchecked entries are not implemented; application-defined callbacks may already
support particular encodings. Each implementation needs a separate scope, chosen
specification edition, limits, and conformance tests before its checkbox is enabled.

## Keep the core generic

Keep raw framing, nesting rules, structural schemas, value codecs, and protocol
semantics separate. Concrete adapters should remain selectable. Preserve
caller-owned storage, capacity checks, and zero-copy value reads in the C API.

The current callback contract reads a tag before resolving length/value bounds.
An adapter for packed headers, length-before-type framing, padding, or a length
that includes header bytes needs an explicit compatibility review. These formats
are candidates, not a claim that every one fits the existing callbacks unchanged.
Any contract extension should describe a reusable framing requirement rather than
introducing protocol-specific branches in the generic parser.

## Candidate encodings and profiles

| Area | Candidate | Intended boundary and reference |
| --- | --- | --- |
| Generic | Configurable fixed-width TLV | Reusable tag/length widths and byte order; distinguish payload length from total encoded length. Custom callbacks are already supported. |
| ASN.1 | CER | Dedicated canonical rules, including relevant value rules; BER indefinite support alone is insufficient. [ITU-T X.690](https://www.itu.int/rec/T-REC-X.690/en) |
| ASN.1 | Full DER validation | Extend beyond structural framing to canonical values and ordering. Schema-dependent semantics need an explicit scope. [Current limits](profiles/der/README.md#supported-scope) |
| Smart cards | GlobalPlatform DGI | DGI field encoding and length handling, separately from APDU transport and card management. [Card Specification 2.3, section 11.1.12](https://globalplatform.org/wp-content/uploads/2018/03/GPC_Specification_v2.3.pdf) |
| Payments | EMV contactless | Separate kernel-specific scope and specification selection; not implied by the existing Contact Book 3 dictionary. [Current profile](profiles/emv/README.md) |
| Networking | NDN | Packet TLV framing and explicit container rules; packet semantics belong in a separate profile. [NDN packet format](https://101.named-data.net/connectivity/packet-format/) |
| Networking | PEAP | Defined TLV structures, independently from TLS transport and authentication state machines. [Microsoft PEAP TLV](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-peap/fa418c4b-b11e-47a5-b86f-d74a9150b822) |
| Networking | RADIUS | Base attribute framing; the length includes Type and Length. Vendor-specific and extended attributes need separately defined coverage. [RFC 2865, section 5](https://www.rfc-editor.org/rfc/rfc2865.html#section-5) |
| IoT | OMA LwM2M TLV | Packed TLV headers and resource/container interpretation; separate from CoAP and device management. [LwM2M Core 1.2.2](https://www.openmobilealliance.org/release/LightweightM2M/V1_2_2-20240613-A/HTML-Version/OMA-TS-LightweightM2M_Core-V1_2_2-20240613-A.html) |
| Wireless | Bluetooth LE advertising data | Length-Type-Value (LTV) structures; an adjacent framing family with a different field order, not a Bluetooth stack. [Bluetooth SIG overview](https://www.bluetooth.com/wp-content/uploads/2023/02/2301_5.4_Tech_Overview_FINAL.pdf) |

## Generic processing extensions

- **Mixed-format child traversal:** select child formats and nesting rules explicitly
  using application context; current traversal uses the same format for descendants.
- **Incremental parsing:** resume across input chunks with clear incomplete-input
  status, buffer ownership, and resource limits. Zero-copy views require their
  backing bytes to remain available; fragmented values need an explicit policy.

The current tree walker already handles nested values without a schema, using
bounded iterative traversal. It does not allocate an object tree. See
[architecture](architecture.md#traversal-and-recovery).

## Proposed order

1. Add configurable fixed-width framing to cover more application protocols.
2. Assess DGI, NDN, and RADIUS as concrete adapters with different length rules.
3. Assess packed and reordered headers through LwM2M and Bluetooth advertising;
   derive any generic contract extension from those requirements.
4. Add mixed-format traversal and incremental parsing as separately scoped core work.
5. Expand semantic profiles and ASN.1 canonical validation with explicit standard
   coverage, independently of basic wire-format support.

These priorities are proposals. A format adapter can be useful without a full
protocol profile; enabling one must not imply the other is complete.
