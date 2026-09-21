# Build only the components you need

OpenTLV builds only the components you ask for. This guide gives ready-made CMake
recipes for the common selections. For the principle and the option reference, see
[include only what you need](../concepts/architecture.md#include-only-what-you-need) and
[build configuration](../concepts/architecture.md#build-configuration).

The generic core (reader, writer, walker, schemas, value codecs and the format
callbacks) is always built. Each format and profile is an option that defaults to ON.
Turn off what you do not use.

| Option | Component |
| --- | --- |
| `OPENTLV_FORMAT_DEFAULT` | [Default TLV](../formats/default/README.md) |
| `OPENTLV_FORMAT_FIXED_1BYTE` | [Fixed 1-byte TLV](../formats/fixed/README.md) |
| `OPENTLV_FORMAT_BLUETOOTH_LTV` | [Bluetooth LTV](../formats/bluetooth/README.md) |
| `OPENTLV_FORMAT_ASN1` | The ASN.1 group; must be ON for BER, DER, CER and EMV |
| `OPENTLV_FORMAT_BER` | [BER-TLV](../formats/asn1/ber.md); must be ON for DER, CER and EMV |
| `OPENTLV_FORMAT_DER` | [DER-TLV](../formats/asn1/der.md); must be ON for EMV |
| `OPENTLV_FORMAT_CER` | [CER-TLV](../formats/asn1/cer.md); independent of DER |
| `OPENTLV_PROFILE_EMV` | [EMV profile](../profiles/emv/README.md) |
| `OPENTLV_DOCUMENT` | [Mutable document](document.md); allocates memory, so turn it OFF for allocation-free builds. Independent of every format |

Turning an option OFF also turns OFF everything below it in the chain
`ASN1 -> BER -> DER -> EMV`, with CER a sibling of DER under BER. The
[configurable fixed-width format](../formats/fixed/configurable.md) is a C++ header and
has no CMake option.

## Recipes

Each recipe starts from a clean build directory; replace `build` with your own. Every
option defaults to ON, so a recipe lists exactly the options it turns OFF.

### Core only

Use this when you supply your own [format callbacks](../formats/custom/README.md).

```sh
cmake -S . -B build \
  -DOPENTLV_FORMAT_DEFAULT=OFF -DOPENTLV_FORMAT_FIXED_1BYTE=OFF \
  -DOPENTLV_FORMAT_BLUETOOTH_LTV=OFF -DOPENTLV_FORMAT_ASN1=OFF
cmake --build build --parallel --target tlv
```

### Core and BER

```sh
cmake -S . -B build \
  -DOPENTLV_FORMAT_DEFAULT=OFF -DOPENTLV_FORMAT_FIXED_1BYTE=OFF \
  -DOPENTLV_FORMAT_BLUETOOTH_LTV=OFF \
  -DOPENTLV_FORMAT_DER=OFF -DOPENTLV_FORMAT_CER=OFF -DOPENTLV_PROFILE_EMV=OFF
cmake --build build --parallel --target tlv
```

### Core, BER, DER and EMV

EMV needs DER and DER needs BER, so all three are on. CER is off.

```sh
cmake -S . -B build \
  -DOPENTLV_FORMAT_DEFAULT=OFF -DOPENTLV_FORMAT_FIXED_1BYTE=OFF \
  -DOPENTLV_FORMAT_BLUETOOTH_LTV=OFF -DOPENTLV_FORMAT_CER=OFF
cmake --build build --parallel --target tlv
```

### Core and Bluetooth LTV only

```sh
cmake -S . -B build \
  -DOPENTLV_FORMAT_DEFAULT=OFF -DOPENTLV_FORMAT_FIXED_1BYTE=OFF \
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

These recipes were checked by configuring each one and building the `tlv` library target
with MSVC in Release as a shared library. The generated `tlv/config.h` matched each recipe,
and the symbols of the disabled formats were absent from the built library. As an
illustration only (the sizes depend on the compiler, settings and platform), the shared
library was about 26 KB for the core only and about 107 KB with everything.

Confirm your own selection from the generated `tlv/config.h`, which defines each option
as `1` or `0`:

```c
#include "tlv/config.h"

#if OPENTLV_FORMAT_BER
#include "tlv/formats/asn1/ber.h"
/* use tlv_reader_format_ber */
#endif
```

Use these macros when your code has to compile against a reduced build. Including the
header of a disabled component does not provide its symbols.

## Notes

- Tests, examples and the CLI that need a disabled component are omitted from that build.
  The recipes above were checked by building the `tlv` library target.
- The C++ wrapper adds cost only for the headers you include.
- The Rust bindings do not choose components yet: they build the C library with its
  default options. See
  [include only what you need](../concepts/architecture.md#include-only-what-you-need).
- A future format follows the same rule, with its own option; see the
  [format expansion candidates](../formats/format-roadmap.md).
