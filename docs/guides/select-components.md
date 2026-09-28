# Build only the components you need

OpenTLV builds only the components you ask for. This guide gives ready-made CMake
recipes for the common selections. For the principle and the option reference, see
[include only what you need](../concepts/architecture.md#include-only-what-you-need) and
[build configuration](../concepts/architecture.md#build-configuration).

The generic core (reader, writer, walker, schemas, value codecs and the format
callbacks), including the configurable Fixed format, is always built.
Protocol extensions are options that default to ON.
Turn off what you do not use.

## Generic core formats

| Format | Availability |
| --- | --- |
| [Configurable fixed-width TLV](../formats/fixed/configurable.md) | Always built; shared C implementation and C++ wrapper |

## Built-in standards

| Option | Component |
| --- | --- |
| `OPENTLV_BLUETOOTH` | [Bluetooth](../formats/bluetooth/README.md): LTV format, containers, definitions, schemas and codecs |
| `OPENTLV_FORMAT_ASN1` | The ASN.1 group; must be ON for BER, DER, CER and EMV |
| `OPENTLV_FORMAT_BER` | [BER-TLV](../formats/asn1/ber.md); must be ON for DER, CER and EMV |
| `OPENTLV_FORMAT_DER` | [DER-TLV](../formats/asn1/der.md); must be ON for EMV |
| `OPENTLV_FORMAT_CER` | [CER-TLV](../formats/asn1/cer.md); independent of DER |
| `OPENTLV_PROFILE_EMV` | [EMV profile](../profiles/emv/README.md) |

The [mutable document](document.md) is a separate optional generic component,
controlled by `OPENTLV_DOCUMENT`; it is not a format or a standard package.

Turning an option OFF also turns OFF everything below it in the chain
`ASN1 -> BER -> DER -> EMV`, with CER a sibling of DER under BER.
The C++ [configurable fixed-width format](../formats/fixed/configurable.md)
template delegates to the always-built C implementation.

## Recipes

Each recipe starts from a clean build directory; replace `build` with your own. Every
option defaults to ON, so a recipe lists exactly the options it turns OFF.

### Core only

Use this when you supply your own [format callbacks](../formats/custom/README.md).

```sh
cmake -S . -B build \
  -DOPENTLV_BLUETOOTH=OFF -DOPENTLV_FORMAT_ASN1=OFF
cmake --build build --parallel --target tlv
```

### Core and BER

```sh
cmake -S . -B build \
  -DOPENTLV_BLUETOOTH=OFF \
  -DOPENTLV_FORMAT_DER=OFF -DOPENTLV_FORMAT_CER=OFF -DOPENTLV_PROFILE_EMV=OFF
cmake --build build --parallel --target tlv
```

### Core, BER, DER and EMV

EMV needs DER and DER needs BER, so all three are on. CER is off.

```sh
cmake -S . -B build \
  -DOPENTLV_BLUETOOTH=OFF -DOPENTLV_FORMAT_CER=OFF
cmake --build build --parallel --target tlv
```

### Core and Bluetooth LTV only

Bluetooth uses the generic binary layout primitives. Fixed is always available.

```sh
cmake -S . -B build \
  -DOPENTLV_FORMAT_ASN1=OFF
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
- The Rust bindings do not choose components yet: they build the C library with its
  default options. See
  [include only what you need](../concepts/architecture.md#include-only-what-you-need).
- Protocol extensions remain optional; generic formats belong to the core. See the
  [format expansion candidates](../formats/format-roadmap.md).
