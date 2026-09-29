# Definition boundary audit (#381)

This Phase 1 audit examines the current implementation after the ASN.1 and EMV
format refactoring. It records architectural evidence, not a new normative
conformance assessment of the standards.

## Decision: minimal Definition, optional domain dictionaries

The generic Definition contract answers:

> What identifier is this, and what is its descriptive name in this registry?

`tlv_definition_t` remains an identifier/name entry. It must not acquire codec
pointers, schema references, ASN.1 type information, EMV value kinds, length
constraints or other standard-specific metadata. Its name is descriptive,
possibly absent, and neither unique nor a stable symbolic domain identity.
`tlv_definition_find()` compares key bytes in the explicitly selected registry;
it does not infer a namespace, context or protocol. Duplicate keys retain the
documented first-match behavior.

A standard-specific dictionary answers:

> In this standard and context, how should this identifier be interpreted?

Dictionaries may compose Definition, Schema, Codec and domain metadata. They
need not embed `tlv_definition_t` or route their lookup through a generic registry.
Dictionary is domain composition, not a new top-level OpenTLV layer. A factory
is only a possible implementation choice.

```text
Element + explicit context
            |
            v
Caller / standard-specific dictionary
            |
            +-- identifier/name metadata
            +-- schema and constraints
            `-- selected value codec
                        |
                        v
                   decoded Value
```

This is optional composition, not a mandatory parsing pipeline. Format and
Reader do not require a dictionary. A value codec converts Value bytes to/from
its documented typed representation without resolving the enclosing tag. The
caller selects it before invocation, checks that a codec exists and supplies
the correct representation and native byte size. Structure codecs can compose
Reader/Writer, schemas and codecs for nested elements; this does not make the
outer tag an input to value codec selection inside the codec.

## Evidence across standards

Public header paths below are relative to `tlv/include/`; source and test paths
are relative to the repository root.

| Family | Current implementation evidence | Boundary established |
| --- | --- | --- |
| ASN.1 BER/DER/CER | `tlv/builtins/asn1/identifier.h` shares identifier accessors; the formats retain identifier octets. `der_schema.h` separates a component's type from IMPLICIT/EXPLICIT tagging. `asn1_codec.h` explicitly assigns codec selection to the caller/schema/dictionary. | Identifier bytes do not identify a complete ASN.1 type or schema component. No generic Definition registry is needed for the implemented schema and codec operations. |
| EMV | `tlv/src/builtins/emv/dictionary.c` assigns `80` to `response_template1` in BASE and `biometric_header_version` in BHT. `tlv_emv_find(context, tag)` selects a context with no fallback. `tlv_emv_definition_t` composes schema, symbol, value kind, codec and length step. | Meaning is context-dependent. The rich EMV entry is a domain dictionary entry, not a proposed expansion of generic Definition. Its symbolic `name` differs from the generic descriptive-name contract; display labels are separate. |
| Bluetooth | `tlv_bluetooth_ad_types` names one-byte AD Types. `tlv_bluetooth_company_ids` names two-byte keys, least-significant octet first; `{4C, 00}` is a Company Identifier inside a Value. Codecs and AD schema are independent consumers. | A registry can name identifiers beyond an element's Tag. Explicit key representation is independent of CPU endianity; generic lookup does not decode integers or interpret vendor payloads. |
| LLDP | `tlv/src/builtins/lldp/lldp.c` extracts the packed seven-bit Type into an immutable one-byte key used by `tlv_lldp_types`. The raw header also contains Length bits. | Format performs wire extraction. Definition uses canonical keys, not the raw header or its byte envelope. Schema and value codecs remain separate. |
| DHCP | `tlv_dhcpv4_options` names option Codes, including Pad and End. DHCP framing and container policy are separate from the registry. | A definition's presence does not validate an option, interpret Value or cause generic Reader to stop at End. |

All five families can use this boundary without extending `tlv_definition_t`.
ASN.1 and EMV do not need to be rewritten to embed it to demonstrate compliance.
Unknown identifiers remain structurally parseable whenever their Format accepts
them; a dictionary miss is not a framing error.

## Separate decision: logical identity and identifier mapping

Two different relationships must be distinguished:

1. **Wire representation to canonical identifier.** Format already owns this
   relationship. LLDP proves that canonical keys need not be raw header bytes;
   source metadata retains wire locations. See the
   [Format contract](format-contract.md#decoded-identifier-consistency).
2. **Domain identity to identifiers in context.** ASN.1 component tagging and
   EMV context dictionaries demonstrate this relationship, but their existing
   Schema/domain composition handles it without a shared new mapping API.

For example, `{9F, 02}` plus "Amount, Authorised" is a valid descriptive entry
in an EMV registry. It is not a protocol-independent identity for an authorised
amount. The EMV dictionary also has `amount_authorised_binary` under `{81}`,
with a different Value representation. Neither name equality nor a numerical
conversion of tags establishes semantic equivalence.

**Audit outcome:** retain the existing generic Definition representation; do
not introduce a top-level Mapping/Binding abstraction. Multiple families show
context-dependent meaning, but the reviewed implementations do not demonstrate
a missing shared mechanism beyond Format, Schema and domain dictionaries.
This is an empirical decision for the current scope, not a prohibition on future
mapping support. Revisit it if independent standards require the same unresolved
mapping operation that existing composition cannot express. Generic lookup and
Writer must not silently remap identifiers in the meantime.

## Native and future runtime modules

Native tables, generated tables and a future `.otlv` loader must expose the same
borrowed registry contract. A runtime owner can hold entry arrays, immutable key
bytes and names; all must remain valid and unchanged while a registry or returned
entry is in use. The core lookup allocates nothing and does not own that storage.
Runtime symbols/references must be resolved separately from descriptive names.

A module may provide only definitions, only a format, or richer domain
composition. Dynamic loading does not require a new core dictionary API, codec
lookup callback or runtime-specific Definition type. No `.otlv` loader or syntax
is implemented by this audit.

## Regression evidence and limits

- `tests/unit/definition_test.cpp`: byte/size matching, first match, invalid
  inputs, independent registry scope and non-unique descriptive names. The
  registry-scope case uses caller-owned storage rather than builtin tables.
- `tests/integration/builtins/emv/emv_test.cpp`: parsed tags select domain codecs
  for two representations of an amount; codecs also work directly on Value.
  `tests/unit/builtins/emv/emv_test.cpp` covers context collisions and missing
  entries without fallback.
- `tests/unit/builtins/asn1/der_schema_test.cpp`: IMPLICIT/EXPLICIT tagging and
  schema type resolution. `tests/unit/builtins/asn1/asn1_codec_test.cpp` exercises
  codecs directly without tag lookup. BER/DER/CER framing tests cover their
  distinct format contracts.
- `tests/unit/builtins/bluetooth/company_ids_test.cpp`: independent Company ID
  lookup and byte identity. `tests/unit/builtins/bluetooth/ad_types_test.cpp`
  covers unknown types independently of registry coverage.
- `tests/integration/builtins/lldp/lldp_test.cpp`: canonical Type lookup after
  packed-header decoding, unknown Type handling and separate schema/codec use.
- `tests/unit/builtins/dhcp/options_test.cpp` and
  `tests/integration/architecture_test.cpp` cover independent naming, unknown
  Codes and generic Pad/End behavior.

These are architectural regressions, not exhaustive standards conformance or
validation of a future `.otlv` runtime. The generic Definition layout and encoded-byte behavior remain unchanged.
The EMV X-macro include is removed; public dictionary access and generic codec
configuration are additive APIs. See the [EMV migration notes](../standards/emv/README.md#migration-from-the-x-macro-dictionary-381).

## Runtime-model readiness and codec reuse

EMV now provides explicit typed tables and `tlv_emv_dictionary_t`, a borrowed
view that works equally with builtin or caller-owned entries. The existing
`tlv_emv_definition_t` names an EMV entry for source compatibility; it does not
expand generic Definition. `tlv_emv_dictionary_find()` has the same semantics
for static and dynamically owned storage. The context is selected before lookup.
Caller-owned dictionary tests configure a BCD codec and decode through the same
callbacks used by the builtin, without a parallel runtime object model.

The codec audit follows wire representation and C representation, not just
similar names:

| Family | Generic reuse implemented | Semantics retained in the domain |
| --- | --- | --- |
| EMV | Numeric/flag entries configure generic unsigned binary/BCD conversion. Digit strings reuse generic F-padded conversion. Amount is a six-byte BCD preset; date, time, account and number-list codecs reuse that numeric primitive internally. | Calendar checks, allowed account/biometric values, digit-count/length constraints, AFL, CVM and Track 2 structures. |
| ASN.1 | INTEGER and ENUMERATED delegate conversion to the generic minimal signed big-endian `int64_t` codec. | Universal-type selection, BOOLEAN content rules, BIT STRING padding, OID, character/time rules and structured representations. |
| Bluetooth | UUID16/32 delegate to generic LE integer codecs; Flags and Local Name reuse generic borrowed-byte conversion after validation. | UUID128 representation and UUID-list views, Flags minimality, UTF-8/length checks, Tx Power range and compound Service/Manufacturer Data views. |
| LLDP | TTL delegates to the generic BE uint16 codec; text reuses generic borrowed bytes after length validation. | Identifier subtypes, capabilities relationships, address families, management/organisation structures and length policy. |
| DHCP | Message Type already delegates to generic uint8; integer, IPv4 and byte-sequence consumers already use generic codecs. | Container/option constraints and interpretation of vendor payloads. |

These are different typed representations: for example a `uint16_t` UUID codec
cannot be substituted by a `uint64_t` number codec without an explicit adapter.
The unsigned number configuration exposes byte order/BCD, minimum/maximum byte
lengths, length step and decimal digit limit as data. It does not encode tags,
EMV value kinds, currency scaling or callbacks that choose a codec by tag.
The same descriptor can be initialized statically or created from caller-owned
configuration. The signed primitive encodes minimal two's-complement values;
it does not infer ASN.1 types.

Specialized codecs remain valid where generic conversion would lose domain
validation or change the public C representation. A new standard should first
compose existing codecs/configuration; repeated conversion mechanics should
be extracted as the smallest useful generic primitive. This does not require
all standards to adopt an EMV dictionary type or introduce a mandatory generic
dictionary layer. Future `.otlv` modules can select the same codec descriptors
and own their configurations without changing the core contracts.

## Additional domain-dictionary stress cases

A field catalog may contain symbolic aliases, identical identifiers with different
meanings in different contexts, and differently encoded identifiers for a similar
business concept. These are distinct cases:

- An alias can refer to the same domain entry. A descriptive name is not a
  unique symbol and must not become a global lookup key.
- A context chooses a dictionary before identifier lookup. A collision across
  dictionaries does not require a different generic Definition representation.
- A shared business meaning across identifiers needs an explicit domain mapping;
  equal names or compatible codecs alone do not establish logical identity.
  This does not yet demonstrate a cross-standard need for a generic binding API.

Length constraints belong to Schema. Exact length uses equal bounds, an interval
uses ordinary bounds, unrestricted length uses `0..SIZE_MAX`, and endpoint-only
length uses `TLV_SCHEMA_LENGTH_ENDPOINTS`. This flag composes with
`length_multiple`; diagnostics retain the flag in `length_flags`. EMV BIC and
public-key-exponent entries use the endpoint rule. The schema entry layout is
unchanged; the diagnostic layout gains a field and consumers must be rebuilt.

Encoding labels must resolve to explicit wire and C representations. Numeric
zero-left-padded BCD uses `uint64_t`; F-right-padded digit strings preserve
leading zeros in a character buffer. ASCII text uses a borrowed `tlv_value_t`,
with a chosen alphabet and optional trailing zero padding. Domain labels such
as AN/ANS do not automatically imply a character repertoire or padding policy.
See the [codec configurations](../guides/codecs.md#digit-strings-and-text).

A dictionary can describe identifiers that its selected Format does not accept.
Supporting private identifiers in a separate domain must not silently widen the
strict EMV wire grammar. Runtime owners can compose these existing primitives;
no universal descriptor, symbol resolver or `.otlv` loader is introduced here.
