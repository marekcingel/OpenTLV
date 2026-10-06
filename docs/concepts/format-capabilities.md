# Generic Format capability space

OpenTLV represents binary elements through combinations of wire properties.
Built-in protocols are representative points in that space, not its boundary.
For a proprietary format, start with its identifier, boundary and composition rules
rather than looking for its name in the [format inventory](../formats/support.md).

## From Element to Format

An Element contains an optional byte identifier and a contiguous Value. Its
logical length is `value.size`; it has no separate raw Length field. Tag identity
is byte identity, independent of host byte order or registry names.

```text
Element
|-- Tag:   optional identifier bytes
`-- Value: contiguous bytes (value.size is the logical length)

source bytes -- Format.decode --> Element + source Layout
Element      -- Format.encode --> destination bytes
```

Format determines how to recognize and encode those bytes. Decoded Layout
records where Header, optional Tag/Length, Value and Trailer occur in the source.
Header, Value and Trailer partition the complete encoded element; Tag and Length
are optional ranges inside Header and may overlap for packed fields.
Additional header bytes do not become new Element members.

The [Format and Element contract](format-contract.md) defines the exact range,
identifier binding, lifetime, error and encoding requirements. Parsed Values
borrow the input. A transformed Tag can borrow immutable Format-owned storage;
it must not point into scratch reused by subsequent decodes.

## TLV and LTV are configurations

```text
TLV: [ Tag ][ Length ][ Value ]
LTV: [ Length ][ Tag ][ Value ]
                 |
                 v
          the same Element
```

`tlv_element_order_t` selects TLV or LTV in the generic sequential field compositions.
`tlv_length_scope_t` separately selects whether the count covers Value alone or
Tag plus Value. Bluetooth uses LTV and Tag-plus-Value counts; these choices also
work for other configured widths. The enum does not describe arbitrary field
permutations or packed headers.

## Independent dimensions

```text
                         Generic Format Space
                                  |
              +-------------------+-------------------+
              |                   |                   |
          Identifier           Boundary           Composition
              |                   |                   |
           fixed               explicit              TLV
           variable            fixed                 LTV
           packed              derived               packed
           encoded             marker                custom
```

This is a design map, not a promise that every branch has a ready-made
configuration or that every combination is valid.

| Dimension | Choices and current constraints |
| --- | --- |
| Field ordering | Sequential TLV/LTV configurations; other header arrangements use a custom Format. |
| Identifier representation | Fixed byte widths, variable inline/escaped continuation bytes, or a transformed packed identifier. An absent identifier is valid under the contract. |
| Length representation | Fixed binary counts, short/long counts, escape-prefixed counts, or no explicit Length range under a custom Format. |
| Fixed and variable widths | Fixed tag widths and 1–8-byte binary counts; configurable variable identifier limits and variable count widths. These describe fields, not a fixed Value size. |
| Byte order | Explicit big/little endian for binary counts and packed storage; identifier bytes are never implicitly converted into host integers. |
| Packed fields | Unsigned fields within 1–8-byte backing integers; overlapping Tag/Length byte envelopes require complete Format callbacks. |
| Value boundaries | Explicit counts in supplied formats; custom callbacks can derive a fixed or type-selected byte extent, or resolve terminated framing. Value remains contiguous. |
| Padding | Extra Header/Trailer bytes can be represented by a custom Format. Stream padding and whether to skip a control element belong to the caller or protocol container. |
| Termination | A bounds resolver can recognize an element's terminated Value; message End policy is separate from decoding an individual element. |
| Trailers | Decode reports validated trailers; matching measure/encode callbacks generate them and include them in the total extent. |
| Constructed elements | The Format's optional constructed predicate classifies elements for generic traversal; Schema adds allowed-child and occurrence constraints. |

## Combining dimensions

A format matching a supplied configuration needs no new parser. For example,
a proprietary two-byte identifier with a three-byte little-endian count before
it can use the [Fixed format](../formats/fixed/configurable.md), configured as
LTV with Value-only length scope:

```text
02 00 00  A1 B2  CA FE
|-------| |---|  |---|
 Length    Tag   Value
    2     A1 B2  CA FE
```

For different field encodings, `tlv_field_composition_t` from
`tlv/formats/compose.h` composes read/write tag and length callbacks with ordering
and count scope. Reuse the standalone primitives under `tlv/field/` or binary
field adapters where they match the wire rules. Supplying a
field callback is implementation work, even though the composition is generic.

For a shared packed header, absent fields, extra header bytes, or generated
trailers, implement the complete `tlv_format_t` callback groups. Reader and Writer
continue to use the same contracts; see [custom Formats](../formats/custom/README.md).
A bounds resolver applies only to TLV/Value-scope framing in the field composer.
Its read-side trailer recognition does not change the default writer, which
emits definite counts without trailers. A bidirectional terminated format needs
matching canonical measurement and encoding.

```text
wire properties
      |
      +-- match supplied configuration --> configure existing Format
      +-- match sequential composition --> supply/reuse field callbacks
      `-- require other framing         --> custom Format callbacks
                                               |
                                               v
                                  same Reader / Writer / Element
```

These dimensions have constraints: tag-only tables require TLV/Value scope and
empty Values; generic sequential composition cannot combine tag-only selection
with a bounds resolver. A packed field helper alone is not a complete packed
Format. Counts must fit the logical length type and actual processing must fit
native buffer limits. Validate the complete combination, not just each field.

## Format Capability Matrix

**Configuration** means a supplied generic configuration or primitive works
today. **Custom Format** means the current contract supports the shape but the
application must supply callbacks; it does not claim a supplied protocol
implementation. **Planned/generalizable** identifies future model work or a
possible reusable mechanism, not an available API. **Outside core** identifies
policy handled above wire mechanics.

| Capability | Status | Current mechanism or boundary |
| --- | --- | --- |
| Standalone fixed-width Identifier and Length fields | Configuration | `tlv_fixed_identifier_t` and `tlv_fixed_length_t` in `tlv/field/fixed.h`; raw identifier bytes and unsigned counts with explicit byte order, independent of complete Format framing. |
| Fixed-width TLV/LTV, big/little-endian counts | Configuration | `tlv_binary_composition_t`, `tlv_fixed_format_t`; Value or Tag-plus-Value scope. |
| Inline/escaped continuation identifiers and short/long counts | Configuration | `tlv_variable_format_t`; concrete reserved encodings and canonicality remain separate. |
| Fixed identifiers with escape-prefixed counts | Configuration | `tlv_escaped_format_t`, including optional tag-only identifiers. |
| Identifier-selected tag-only elements | Configuration | `tlv_tagged_binary_composition_t` / `tlv_tagged_fields_composition_t`; omits Length, requires empty Value, implies no skip/stop policy. |
| Extract/insert packed unsigned fields | Configuration | `tlv_packed_field_t` helpers preserve unrelated bits on write. |
| Complete packed Tag/Length header | Custom Format | Compose packed helpers in decode/measure/encode; LLDP is an existing example, not a generic packed-format initializer. |
| Different sequential field encodings | Custom Format | Supply callbacks to `tlv_field_composition_t`; retain TLV/LTV and supported count scopes. |
| Absent Tag or Length; fixed/type-derived Value extent | Custom Format | Publish valid optional ranges and a contiguous Value; no supplied general boundary selector. |
| Terminated Value or container | Custom Format | Optional bounds resolver for TLV/Value scope, or complete decode; paired measure/encode for trailers. BER indefinite framing is implemented. |
| Additional Header bytes, alignment padding, checksums/trailers | Custom Format | Complete callbacks validate framing and measure/encode it; no general padding/checksum configuration is supplied. |
| Constructed classification | Custom Format | Optional `is_constructed` predicate; generic Tree processing handles traversal. Fixed/Variable configurations alone keep Values opaque. |
| Stream PAD/END handling and required termination | Outside core | Protocol container/caller decides skipping, stopping and tail validity; tag-only framing alone makes no such decision. |
| Allowed children, order, occurrence counts | Outside core | Schema uses the shared elements without redefining framing. |
| Value meaning, dictionaries, transactions, transport/device mapping | Outside core | Codec, domain composition or application responsibilities. |
| Declarative runtime configuration and generated implementations | Planned/generalizable | Future `.otlv` frontend/model/compiler reuse these contracts; no runtime interpreter is delivered by these configuration APIs. |
| General boundary selectors and arbitrary Format composition | Planned/generalizable | Possible generalizations of custom callbacks, not committed features or supplied configuration knobs today. |
| Mixed-format traversal | Planned/generalizable | Not implemented in generic Tree processing; tracked in the [format roadmap](../formats/format-roadmap.md#generic-processing-extensions). A caller can parse separate regions with separate Formats today. |

Read-only and write-only Formats are possible. A decode demonstration does not
establish Writer support; bidirectional encoding must preserve semantic Tag and
Value on decode. Ordinary encoding can regenerate framing; exact preservation
of unchanged source bytes uses `tlv_source_preserve()` explicitly.

## Existing protocols as representative points

```text
Generic mechanisms + concrete rules --> protocol Format
             |
             +-- EMV:       TLV; BER-style identifier/count; definite boundary
             +-- Bluetooth: LTV; fixed fields; count includes Type
             +-- LLDP:      packed 7-bit Type / 9-bit Length; explicit boundary
             +-- DHCPv4:    fixed fields; tag-only Pad/End controls
             `-- NFC Type 2: fixed Tag; escaped Length; tag-only controls
```

| Representative point | Composition and protocol boundary |
| --- | --- |
| [EMV](../standards/emv/README.md) | BER-style wire fields with independent EMV validity rules; indefinite lengths/EOC are unsupported. Dictionary and value codecs add meaning separately. |
| [Bluetooth](../formats/bluetooth/README.md) | Fixed 1-byte Length and Type, LTV, Tag-plus-Value scope; advertising-container zero padding is separate. |
| [LLDP](../formats/lldp/README.md) | Big-endian two-byte packed header; semantic Tag is an immutable one-byte Type. End and LLDPDU structure are protocol concerns. |
| [DHCPv4](../formats/dhcp/README.md) | Fixed 1-byte Code/Length with tag-only Pad/End; container validation adds termination and trailing-byte rules. |
| [NFC Type 2](../formats/nfc/README.md) | Fixed Tag plus short/escape-prefixed Length and tag-only NULL/Terminator; physical memory mapping and NDEF interpretation are separate. |
| [BER](../formats/asn1/ber.md) | Variable identifier and short/long Length plus ASN.1-specific rules, constructed classification and indefinite/EOC boundary resolution. |

The number of builtins measures packaged protocol coverage, not the extent of
generic Format capability.

## Architecture boundaries and stress tests

```text
Definition: optional identifier names
                  |
                  | lookup is not required to parse
                  v
Format --------> Layout + Element
                              |
                         +----+----+
                         |         |
                       Schema    Codec
                     structure   meaning

built-in protocol support != generic format capability != custom implementation
```

Format does not require Definition, Schema or Codec. Schema and Codec consume
the same Element model; they do not provide a second parser or redefine Value
boundaries. Protocol policy stays above generic mechanics. The future
[runtime model and canonical IR](runtime-model.md) must describe combinations
of these capabilities and lower them to the existing execution contracts,
rather than select from a closed list of protocol names.

Protobuf and CBOR are architectural stress-test examples only: neither is a
supported OpenTLV format. Implicit or type-derived lengths, value-derived
boundaries and marker-terminated containers raise questions about complete
framing, identifier identity, contiguous Values, nesting and matching encoding.
A plausible mapping to callbacks is not evidence of implemented support or
conformance. General-purpose serialization semantics or a full ASN.1 language
compiler remain outside the binary TLV scope; see the
[architectural rules](architectural-rules.md).

For a proprietary format, identify each wire dimension, select existing
configuration where possible, and isolate the remaining rules in callbacks or
protocol containers. Verify truncation, malformed framing, borrowed lifetimes
and semantic round trips against the shared contract before claiming support.
