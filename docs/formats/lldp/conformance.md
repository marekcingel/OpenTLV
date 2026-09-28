# LLDP reference tests and conformance boundary

[LLDP support](README.md) targets the base single-frame TLV representation of
IEEE 802.1AB-2016. The original architecture review is preserved in
[LLDP requirements review](../lldp-review.md).

## Evidence

- The [IEEE publication record](https://standards.ieee.org/ieee/802.1AB/6047/)
  identifies the selected edition. The complete published text was not available
  for this implementation review through IEEE GET.
- A published-text [ISO/IEC/IEEE 8802-1AB:2017 excerpt](https://www.normsplash.com/Samples/ISO/188141883/ISO-IEC-IEEE-8802-1AB-2017-en-2.pdf)
  reproduces IEEE 802.1AB-2016 clauses 9.2.10 and 10. Its 10.2.3/10.2.4 supports
  the mandatory three-TLV prefix and optional End. This is a partial excerpt,
  not evidence that all of clause 8 was inspected.
- The [IEEE LLDP overview, slide 9](https://www.ieee802.org/1/files/public/docs2025/new-bottorff-lldp-for-lsvr-0425-v02.pdf)
  supplies the packed header, mandatory prefix and generic organisational layout.
  It is an informative contribution, not the published specification.

## Reference vectors

These are hand-authored, independently specified byte examples for the documented
subset. They are not captures or an official IEEE conformance suite.

| Wire bytes | Expected interpretation |
| --- | --- |
| `02 02 07 63 04 02 07 70 06 02 00 78` | Local Chassis ID `c`, local Port ID `p`, TTL 120; complete region without End |
| Previous vector followed by `00 00` | Same LLDPDU with optional End |
| Previous vector followed by `00 00 0A 00` | Structural error: System Name after End |
| `06 02 00 00` | Framing/value example: TTL zero, without agent shutdown processing |
| `FE 06 00 80 C2 01 00 2A` | Organisational OUI/subtype prefix and opaque two-byte payload |
| `05 01 C0 00 02 01 02 01 02 03 04 00` | Management Address Value: IPv4 192.0.2.1, ifIndex 0x01020304, empty OID |

`tests/integration/builtins/lldp/lldp_test.cpp` covers every Type 0..127 and Length 0..511,
truncation, writer bounds, borrowed identity, source preservation, structural
errors, shared diagnostics, Reader/Writer, Document and Query. Its exhaustive
framing test intentionally includes semantically invalid LLDP elements.
`tests/unit/builtins/lldp/codec_test.cpp` tests each codec against expected bytes, both encoding
directions, size queries, capacities, invalid fields and boundary sizes.
The C and C++ examples are compiled targets and their documentation is checked
against source by `scripts/check_doc_examples.py`.

## Remaining normative audit

Implementation tests do not complete the previously deferred full-edition audit.
In particular, verify the selected edition's clause 8 and receive procedures
before claiming complete IEEE conformance: subtype/character restrictions,
reserved capability policy, OID semantics, duplicate management addresses,
vendor-specific multiplicity and receive/discard behavior remain outside the
implemented validation subset. Reference tests demonstrate the explicit API
contracts, not equivalence to an LLDP agent's acceptance policy.

The structural validator checks lengths, occurrences, prefix and End position.
Codecs perform the documented field checks separately. Neither API claims
complete protocol validation. Schema/Codec support for the base subset is
implemented; normative certification, vendor extensions, agents, Ethernet
parsing, MIB/YANG management and multiframe amendments are not.
