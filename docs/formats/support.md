# Implemented format and standard capabilities

This inventory describes the current native implementation. A built-in Format
means supported wire framing, not a complete protocol stack. Definitions name
identifiers; Schema constrains composition; Codec interprets Values. Independent
standards exercise shared Field Encoding and Format composition primitives rather
than add protocol branches to the generic core. See the
[format comparison](README.md#compare-formats) for wire limits and the
[binding matrix](../concepts/bindings.md) for operation-level coverage.

## Native and tool inventory

Optional entries require their named CMake component and its parents. Fixed and
Variable are always-built generic formats. The CLI column records registered
`--format` identifiers; a native preset without an entry is not available in
the CLI today. EMV's dictionary/validation is separately selected by `--module emv`.

| Format / scope | C descriptor or initializer | Component | C++ framing header | CLI identifier |
| --- | --- | --- | --- | --- |
| [Fixed](fixed/configurable.md) | `tlv_fixed_format_init` | Always built | [fixed_format.hpp](../../tlv++/include/tlv++/formats/fixed_format.hpp) | `fixed` |
| [Variable](variable.md) | `tlv_variable_format_init` | Always built | Native interop/custom Format | Unavailable |
| [BER](asn1/ber.md) | `tlv_format_ber`, `tlv_format_ber_indefinite` | `OPENTLV_FORMAT_BER` | [ber.hpp](../../tlv++/include/tlv++/builtins/asn1/ber.hpp) | `ber` |
| [DER](../standards/der/README.md) | `tlv_format_der` | `OPENTLV_FORMAT_DER` | [der.hpp](../../tlv++/include/tlv++/builtins/asn1/der.hpp) | `der` |
| [CER](../standards/cer/README.md) | `tlv_format_cer` | `OPENTLV_FORMAT_CER` | [cer.hpp](../../tlv++/include/tlv++/builtins/asn1/cer.hpp) | Unavailable |
| [EMV](../standards/emv/README.md) | `tlv_format_emv` | `OPENTLV_EMV` | [format.hpp](../../tlv++/include/tlv++/builtins/emv/format.hpp) | `emv` |
| [Bluetooth](bluetooth/README.md) | `tlv_format_bluetooth_ltv` | `OPENTLV_BLUETOOTH` | [ltv.hpp](../../tlv++/include/tlv++/builtins/bluetooth/ltv.hpp) | `bluetooth-ltv` |
| [LLDP](lldp/README.md) | `tlv_format_lldp` | `OPENTLV_LLDP` | [lldp.hpp](../../tlv++/include/tlv++/builtins/lldp/lldp.hpp) | Unavailable |
| [DHCPv4](dhcp/README.md) | `tlv_format_dhcpv4` | `OPENTLV_DHCP` | [dhcpv4.hpp](../../tlv++/include/tlv++/builtins/dhcp/dhcpv4.hpp) | Unavailable |
| [NFC Type 2](nfc/README.md) | `tlv_format_nfc_type2` | `OPENTLV_NFC` | [type2.hpp](../../tlv++/include/tlv++/builtins/nfc/type2.hpp) | `nfc-type2` |

ASN.1 Value codecs and shared construction/tag rules are selected by
`OPENTLV_FORMAT_ASN1`; BER depends on ASN1, and DER/CER/EMV depend on BER.
Other protocol packages are independent. The
[component configuration](../concepts/architecture.md#build-configuration)
is the authoritative description of dependency and disabled-component behavior.

## Semantics beyond framing

| Package | Definition / dictionary | Schema / structural validation | Value codecs / conformance | Explicit limits |
| --- | --- | --- | --- | --- |
| Fixed / Variable | Application supplied | Application supplied | Generic codecs selected explicitly | Generic wire mechanics do not infer semantics |
| BER / ASN.1 | ASN.1 tag/type helpers | Generic traversal and application Schema | Shared ASN.1 Value codecs; framing reader accepts BER representation | No complete ASN.1 notation/compiler or protocol |
| DER | ASN.1 helpers | Recursive validation and schema-aware supported type subset | `_strict` universal Values; schema-aware SET/SET OF ordering and tagging | Full type/time/schema conformance remains limited to the linked scope |
| CER | ASN.1 helpers | Recursive framing, EOC and segmentation checks | `_strict` universal Values and canonical string segmentation | Canonical SET/SET OF ordering not implemented |
| EMV | Contextual dictionaries | Supported FCI/Application/GPO structural rules and length policies | Explicit dictionary-selected codecs | No payment kernel or transaction state machine |
| Bluetooth | AD type registry | AD/container structure and documented constraints | Flags, names, power, UUIDs, service/manufacturer data | No radio stack or arbitrary GATT application model |
| LLDP | Base Type definitions | LLDPDU structural validation | Base Value codecs; normative verification limits documented | No Ethernet agent/MIB; full-edition verification pending |
| DHCPv4 | Selected option registry | Caller-supplied option/packet constraints | Generic bytes, numbers, IPv4 and Message Type alias | No fragment joining, overload, nested suboptions, DHCP client/server or DHCPv6 |
| NFC Type 2 | Framing identifiers | Caller handles NULL/Terminator policy | No NDEF interpretation | Contiguous data area only; no physical memory mapping |

Each linked package page states the supported subset and validation contracts.
Structural checks, strict Value checks and complete protocol conformance are
different claims. Candidates remain in the
[catalogue](format-catalogue.md) and [format roadmap](format-roadmap.md).

## Language framing presets

This table records preset selection, not all protocol semantics or binding
parity. `Yes` requires the corresponding native component; Rust LLDP/NFC also
require their Cargo features. `Missing` means no public preset.

| Preset | C++ | Rust | Python | Lua | Go |
| --- | --- | --- | --- | --- | --- |
| Fixed | Yes | Yes | Yes | Yes | Yes |
| Variable configuration | Native interop/custom Format | Missing | Missing | Missing | Missing |
| BER / DER / CER / EMV | Yes | Yes | Yes | Yes | Yes |
| Bluetooth LTV | Yes | Missing | Missing | Yes | Yes |
| LLDP | Yes | Yes | Yes | Yes | Yes |
| DHCPv4 | Yes | Missing | Missing | Missing | Yes |
| NFC Type 2 | Yes | Yes | Yes | Yes | Yes |

WebAssembly is a parse-to-JSON consumer, with its own supported options in the
[WebAssembly guide](../development/webassembly.md), rather than a complete
language facade. CLI/WASM support is narrower than native Format availability.

The [documentation drift check](../development/documentation-layout.md#documentation-inventory-checks)
compares native descriptors, C++ built-in directories and CLI identifiers with
this inventory. Prose limitations and semantic parity still require review.
