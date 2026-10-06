# Build only the components you need

OpenTLV builds only the components you ask for. This guide gives ready-made CMake
recipes for the common selections. For the principle and the option reference, see
[include only what you need](../concepts/architecture.md#include-only-what-you-need) and
[build configuration](../concepts/architecture.md#build-configuration).

Core primitives and generic formats are always built. Reader, Writer, Document,
Query, Schema and Codec default to ON and can be disabled independently. Operations
combining capabilities require each participant. Protocol family flags select
framing and the integrations permitted by the selected core capabilities.

## Capability profiles

Start with all six capability switches OFF, then enable the selected columns:

| Profile | Reader | Writer | Document | Query | Schema | Codec |
| --- | --- | --- | --- | --- | --- | --- |
| Minimal read | ON | OFF | OFF | OFF | OFF | OFF |
| Minimal write | OFF | ON | OFF | OFF | OFF | OFF |
| Read/write | ON | ON | OFF | OFF | OFF | OFF |
| Standalone Document | OFF | OFF | ON | OFF | OFF | OFF |
| Parse Document | ON | OFF | ON | OFF | OFF | OFF |
| Serialize Document | OFF | ON | ON | OFF | OFF | OFF |
| Full | ON | ON | ON | ON | ON | ON |

For example, this builds a C library for reading generic formats only:

```sh
cmake -S . -B build/read \
  -DOPENTLV_BUILD_CXX=OFF -DOPENTLV_BUILD_EXAMPLES=OFF \
  -DOPENTLV_READER=ON -DOPENTLV_WRITER=OFF -DOPENTLV_DOCUMENT=OFF \
  -DOPENTLV_QUERY=OFF -DOPENTLV_SCHEMA=OFF -DOPENTLV_CODEC=OFF \
  -DOPENTLV_FORMAT_ASN1=OFF -DOPENTLV_BLUETOOTH=OFF \
  -DOPENTLV_NFC=OFF -DOPENTLV_DHCP=OFF -DOPENTLV_LLDP=OFF
cmake --build build/read --target tlv
```

`OPENTLV_QUERY=OFF` also disables its frontend and set operations in the effective
configuration. `tlv/config.h` and `tlv_config_*()` report that configuration.
Disabling a capability does not enable another one. Generated headers must match
the linked library; using declarations from a disabled capability is unsupported.

Reader + Document provides parse/build and constructed-wire mutation. Writer +
Document provides encoding. Query + Document provides path matching; the current
compiled Document Query adapter additionally requires Reader and Writer. Schema
wire validation requires Reader; Schema/Query assertions require both. Structure
codecs require Reader and Schema. EMV dictionaries compose Schema and Codec;
EMV framing remains available independently. ASN.1 Query adapters require Codec;
DER Schema operations currently require Codec and Writer.

### Bindings and tools

The C dependency graph is authoritative. Binding conveniences may require more:

| Consumer | Current requirements |
| --- | --- |
| C++ Reader/Writer headers | Matching C capability; the umbrella selects enabled components |
| C++ Schema facade | Schema and Reader |
| C++ Query facade | Query and Reader |
| C++ Document facade | Document, Reader, Writer, Query and Codec |
| Python, Lua, WASM, CLI, examples, benchmarks and fuzz suites | Reader, Writer, Query, Schema, Codec and Query frontend; CMake skips these in reduced builds |
| Rust | Native build explicitly enables Reader, Writer, Query, Schema and Codec; Document remains a Cargo feature |
| Go | Prebuilt library must enable Reader, Writer, Query, Schema and Codec; the bridge checks generated configuration |

Broad unit/integration suites are skipped in reduced builds. The dependency-free
`capability-contract` test remains available with `OPENTLV_BUILD_TESTS=ON`.
`python scripts/check_capabilities.py` configures, links and executes the profiles
above plus core-only, Query-only, Document/Query, Schema-only and Codec-only builds. CI runs both
shared and static variants and checks that disabled source groups are absent.

## Generic core formats

| Format | Availability |
| --- | --- |
| [Configurable fixed-width TLV](../formats/fixed/configurable.md) | Always built; shared C implementation and C++ wrapper |

## Built-in standards

| Option | Component |
| --- | --- |
| `OPENTLV_NFC` | [NFC Type 2 Tag framing](../formats/nfc/README.md) for contiguous TLV streams |
| `OPENTLV_DHCP` | [DHCPv4 option framing](../formats/dhcp/README.md), including Pad and End |
| `OPENTLV_BLUETOOTH` | [Bluetooth](../formats/bluetooth/README.md): LTV format, containers, definitions, schemas and codecs |
| `OPENTLV_LLDP` | [LLDP](../formats/lldp/README.md): packed framing and base Type definitions; no schemas or value codecs |
| `OPENTLV_FORMAT_ASN1` | The ASN.1 group; must be ON for BER, DER, CER and EMV |
| `OPENTLV_FORMAT_BER` | [BER-TLV](../formats/asn1/ber.md); must be ON for DER, CER and EMV |
| `OPENTLV_FORMAT_DER` | [DER-TLV](../formats/asn1/der.md); independent of EMV |
| `OPENTLV_FORMAT_CER` | [CER-TLV](../formats/asn1/cer.md); independent of DER |
| `OPENTLV_EMV` | [EMV module](../standards/emv/README.md) |

The [mutable document](document.md) is a separate optional generic component,
controlled by `OPENTLV_DOCUMENT`; it is not a format or a standard package.

Turning an option OFF also turns OFF everything below it in the chain
`ASN1 -> BER`, with DER, CER and EMV as siblings under BER.
EMV framing uses generic primitives; only the unchanged DOL implementation
retains a BER dependency. EMV does not require DER or CER.
The C++ [configurable fixed-width format](../formats/fixed/configurable.md)
template delegates to the always-built C implementation.

## Recipes

Each recipe starts from a clean build directory; replace `build` with your own. Every
option defaults to ON, so a recipe lists exactly the options it turns OFF.

### Generic formats without protocol extensions

Use this when you supply your own [format callbacks](../formats/custom/README.md).

```sh
cmake -S . -B build \
  -DOPENTLV_BLUETOOTH=OFF -DOPENTLV_LLDP=OFF -DOPENTLV_DHCP=OFF -DOPENTLV_NFC=OFF -DOPENTLV_FORMAT_ASN1=OFF
cmake --build build --parallel --target tlv
```

### Core and BER

```sh
cmake -S . -B build \
  -DOPENTLV_BLUETOOTH=OFF -DOPENTLV_LLDP=OFF -DOPENTLV_DHCP=OFF -DOPENTLV_NFC=OFF \
  -DOPENTLV_FORMAT_DER=OFF -DOPENTLV_FORMAT_CER=OFF -DOPENTLV_EMV=OFF
cmake --build build --parallel --target tlv
```

### Core, BER, DER and EMV

This recipe enables DER alongside EMV. EMV itself does not need DER;
add `-DOPENTLV_FORMAT_DER=OFF` for BER and EMV only. CER is off.

```sh
cmake -S . -B build \
  -DOPENTLV_BLUETOOTH=OFF -DOPENTLV_LLDP=OFF -DOPENTLV_DHCP=OFF -DOPENTLV_NFC=OFF -DOPENTLV_FORMAT_CER=OFF
cmake --build build --parallel --target tlv
```

### Core and Bluetooth LTV only

Bluetooth uses the generic binary layout primitives. Fixed is always available.

```sh
cmake -S . -B build \
  -DOPENTLV_FORMAT_ASN1=OFF -DOPENTLV_LLDP=OFF -DOPENTLV_DHCP=OFF -DOPENTLV_NFC=OFF
cmake --build build --parallel --target tlv
```

### Everything

The default. No options are needed.

```sh
cmake -S . -B build
cmake --build build --parallel
```

## What you get

Fixed remains available in every configuration, including core-only builds.
Disabled protocol extensions contribute no implementation symbols.

Confirm your own selection from the generated `tlv/config.h`, which defines each option
as `1` or `0`:

```c
#include "tlv/config.h"

#if OPENTLV_FORMAT_BER
#include "tlv/builtins/asn1/ber.h"
/* use tlv_format_ber */
#endif
```

Use these macros when your code has to compile against a reduced build. Including the
header of a disabled component does not provide its symbols.

## Notes

- Tests, examples and the CLI that need a disabled component are omitted from that build.
- The C++ wrapper adds cost only for the headers you include.
- Rust exposes LLDP through the default `lldp` feature; `--no-default-features`
  disables that package in source builds. Other C components retain their defaults. See
  [include only what you need](../concepts/architecture.md#include-only-what-you-need).
- Protocol extensions remain optional; generic formats belong to the core. See the
  [format expansion candidates](../formats/format-roadmap.md).
