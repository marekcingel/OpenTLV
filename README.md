![OpenTLV - Tag, Length, Value](docs/assets/opentlv.svg)

[![GCC build and tests](https://github.com/marekcingel/OpenTLV/actions/workflows/build-gcc.yml/badge.svg?branch=main)](https://github.com/marekcingel/OpenTLV/actions/workflows/build-gcc.yml?query=branch%3Amain)
[![Clang build and tests](https://github.com/marekcingel/OpenTLV/actions/workflows/build-clang.yml/badge.svg?branch=main)](https://github.com/marekcingel/OpenTLV/actions/workflows/build-clang.yml?query=branch%3Amain)
[![MSVC build and tests](https://github.com/marekcingel/OpenTLV/actions/workflows/build-msvc.yml/badge.svg?branch=main)](https://github.com/marekcingel/OpenTLV/actions/workflows/build-msvc.yml?query=branch%3Amain)
[![Rust bindings](https://github.com/marekcingel/OpenTLV/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/marekcingel/OpenTLV/actions/workflows/rust.yml?query=branch%3Amain)
[![WebAssembly build](https://github.com/marekcingel/OpenTLV/actions/workflows/wasm.yml/badge.svg?branch=main)](https://github.com/marekcingel/OpenTLV/actions/workflows/wasm.yml?query=branch%3Amain)
[![Static analysis](https://github.com/marekcingel/OpenTLV/actions/workflows/static-analysis.yml/badge.svg?branch=main)](https://github.com/marekcingel/OpenTLV/actions/workflows/static-analysis.yml?query=branch%3Amain)
[![CodeQL](https://github.com/marekcingel/OpenTLV/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/marekcingel/OpenTLV/actions/workflows/codeql.yml?query=branch%3Amain)
[![C API fuzzing](https://github.com/marekcingel/OpenTLV/actions/workflows/fuzz.yml/badge.svg?branch=main)](https://github.com/marekcingel/OpenTLV/actions/workflows/fuzz.yml?query=branch%3Amain)
[![Documentation](https://github.com/marekcingel/OpenTLV/actions/workflows/docs.yml/badge.svg?branch=main)](https://github.com/marekcingel/OpenTLV/actions/workflows/docs.yml?query=branch%3Amain)

**Read, write, and inspect Tag-Length-Value data in C and C++.**
OpenTLV provides a dependency-free C99 core and a header-only C++11+ wrapper.
Each TLV element identifies a value with a tag and records its length, making
it useful for structured binary messages, files, and device protocols.

The badges show workflow status on `main`.

## Who is it for?

OpenTLV is for C/C++ developers building embedded software, protocol handlers,
smart-card tooling, and binary-data inspection utilities. It is especially useful
when the application needs to own its buffers and control memory use.

- **Allocation-free C core:** write into caller-owned storage with capacity checks.
- **Zero-copy value reads:** parsed values borrow the input buffer.
- **Selectable formats and profiles:** use built-in encodings or supply custom callbacks.
- **Composable processing:** add traversal, schemas, value codecs, or recovery scanning as needed.
- **Include only what you need:** build just the core, or add a single format such as BER; components you leave out are not compiled. Bindings should follow the same rule, but the Rust bindings do not select components yet. See [architecture](docs/concepts/architecture.md#include-only-what-you-need).

The C++ layer offers convenience wrappers; error strings and dynamic containers
can allocate. Applications requiring strictly allocation-free behavior should use
the C API. Raw TLV reading does not interpret values or validate an entire protocol.

See [choosing a format](docs/formats/README.md#choose-a-format) and
[memory ownership](docs/guides/memory.md) for practical guidance.

## Format and profile support

Checked items are implemented; the linked documentation defines their scope.
Unchecked items have no built-in implementation today. This is a support overview,
not a commitment to implement every listed format; scheduled work belongs in issues.
Built-in components are enabled by default and can be selected with
[CMake options](docs/concepts/architecture.md#build-configuration).

- **TLV processing**
  - [x] Primitive values
  - [x] Constructed / nested values
    - [x] BER/DER/CER constructed-tag recognition and custom nesting predicates
    - [x] Bounded tree traversal without a schema
    - [x] Depth and element-count limits
  - [x] Sequential traversal
  - [x] Structural schema validation
  - [ ] Mixed-format child traversal with automatic format selection
  - [ ] Incremental parsing across input chunks
- **Wire formats**
  - **Default and fixed-width**
    - [x] **Default TLV** - one-byte tags, definite BER-style lengths up to 65,535 bytes. [Details](docs/formats/README.md#generic-interface) [Tree and bytes](docs/formats/default/README.md#byte-example)
    - [x] **Fixed 1-byte TLV** - one-byte tags and lengths, values up to 255 bytes. [Details](docs/formats/fixed/README.md) [Tree and bytes](docs/formats/fixed/README.md#byte-example)
    - [x] **Bluetooth LTV** - length-before-type framing used by Bluetooth advertising data, values up to 254 bytes. [Details](docs/formats/bluetooth/README.md) [Tree and bytes](docs/formats/bluetooth/README.md#byte-example)
    - [x] **Configurable fixed-width TLV (C++)** - compile-time tag width, length width (1-8 bytes) and length byte order. [Details](docs/formats/fixed/configurable.md)
  - **ASN.1-related encodings**
    - [x] **BER-TLV** - multi-byte tags. [Scope](docs/formats/asn1/ber.md) [Tree and bytes](docs/formats/asn1/ber.md#byte-example)
      - [x] Definite-length reading and writing
      - [x] Constructed indefinite-length reading and explicit writing
    - [x] **DER-TLV** - canonical identifier and length framing. [Scope](docs/profiles/der/README.md) [Tree and bytes](docs/formats/asn1/der.md#byte-example)
      - [x] Structural validation
      - [x] Universal primitive value canonical validation (`_strict` functions, documented type coverage). [Scope](docs/profiles/der/README.md#strict-universal-value-validation)
      - [x] Schema-aware SEQUENCE/SET/SET OF/CHOICE validation and encoding, including canonical SET/SET OF ordering, IMPLICIT/EXPLICIT tagging and DEFAULT omission (requires an explicit schema; the generic reader above does not infer SET/SET OF semantics on its own). [Scope](docs/profiles/der/README.md#schema-aware-validation-and-encoding)
    - [x] **CER-TLV** - indefinite-length constructed framing, canonical string segmentation. [Scope](docs/profiles/cer/README.md) [Tree and bytes](docs/formats/asn1/cer.md#byte-example-nested-indefinite-length-containers)
      - [x] Structural validation (framing, EOC placement, canonical segmentation)
      - [x] Universal primitive value canonical validation (`_strict` functions, documented type coverage). [Scope](docs/profiles/cer/README.md#strict-universal-value-validation)
      - [ ] Canonical SET/SET OF ordering
  - [x] **Application-defined format callbacks** - independent reader and writer descriptors. [Contracts](docs/formats/README.md#generic-interface) [Tree and bytes](docs/formats/custom/README.md#byte-example)
- **Protocol formats and profiles**
  - **Smart cards / payments**
    - [x] **EMV Contact Book 3 v4.4** - dictionary, contextual length schemas, and value codecs over BER-TLV; not a payment kernel. [Scope](docs/profiles/emv/README.md) [Tree and bytes](docs/profiles/emv/README.md#byte-example)
      - [x] Structural validation (mandatory/forbidden/duplicate tags and nesting for the FCI, Application, and GPO response templates). [Scope](docs/profiles/emv/README.md#structural-validation)
    - [ ] **EMV contactless kernels**
    - [ ] **GlobalPlatform DGI encoding**
  - **Networking**
    - [ ] **NDN packet TLV format**
    - [ ] **PEAP TLV structures**
    - [ ] **RADIUS attribute encoding**
  - **IoT / wireless**
    - [ ] **OMA LwM2M TLV format**

OpenTLV keeps framing, traversal, schemas, and value codecs separate. Broader
format coverage should come through selectable adapters and profiles around the
generic core. Protocol entries above refer to their data encodings and explicitly
named profile functionality, not complete networking or device stacks.

Tree traversal visits borrowed values without building an allocated object tree.
Applications that must change a message can opt into the separate, allocating
[mutable document](docs/guides/document.md), which parses TLV into an owned tree
and encodes it again.
For definite-length containers, the value length covers the complete child
encodings; indefinite BER containers use EOC termination. See
[nested traversal](docs/formats/README.md#nested-traversal),
[value codecs](docs/guides/codecs.md), and [architecture](docs/concepts/architecture.md).

### Candidate formats (not implemented)

OpenTLV covers binary formats encoded as TLV; only a different field order or
packing is accepted as a variation. The catalogue lists possible future built-in
formats. **Listing is not a commitment and not a claim of support**, and TLV framing
support never means full protocol support.

| Area | Candidates | Relationship to existing support |
| --- | --- | --- |
| Protocols using BER | LDAP, SNMP | Profiles over [BER-TLV](docs/formats/asn1/ber.md) |
| ASN.1 notation (X.680) | Wider type coverage, BER/CER schema variants, open types, optional schema generator | Extends the [DER schema subset](docs/profiles/der/README.md#schema-aware-validation-and-encoding) |
| ASN.1 profiles | X.509, PKCS#1, PKCS#7, PKCS#8, PKCS#10, CMS/S-MIME, Kerberos, OCSP | Schemas over [DER/BER](docs/profiles/der/README.md) |
| Smart cards and SIM | ISO 7816 (BER-TLV and SIMPLE-TLV), GlobalPlatform beyond DGI, eSIM, SIM Toolkit, NFC tag TLV container | BER reuse plus new adapters |
| Networking | LLDP, IS-IS, DHCPv4/DHCPv6, LDP, RFC 5444 TLV blocks, Diameter | New adapters |
| Telecommunications | PFCP, GTPv2-C, GTPv1-C, NAS | New adapters and profiles |
| Excluded (not TLV) | CBOR, CWT, COSE, QUIC frames, NDEF records, ASN.1 PER/OER/XER (S1AP, X2AP, NGAP) | Different encodings; out of scope |

See [format expansion candidates](docs/formats/format-roadmap.md) for the catalogue
tree, scope rules, framing requirements, and proposed priorities, and the
[candidate catalogue](docs/formats/format-catalogue.md) for specifications, required
components, variants, limitations, and what was checked against the primary text. Scheduled work is tracked
in [issues](https://github.com/marekcingel/OpenTLV/issues).

See [format trees and byte examples](docs/formats/format-examples.md) for a field-by-field
view of every implemented format, including nested BER/DER and the EMV profile.

## Quick start

This complete C example ([source](examples/tlv/src/quick_start.c), built and run in CI) writes
`01 03 AA BB CC` and reads the value back:

<!-- example: examples/tlv/src/quick_start.c -->
```c
#include <string.h>
#include "tlv/builtins/fixed/fixed_1byte.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"

int main(void) {
    const tlv_tag_t tag = TLV_TAG(0x01);
    const uint8_t   value[] = {0xAA, 0xBB, 0xCC};
    uint8_t         buffer[5];
    size_t          written = 0, consumed = 0;
    tlv_view_t      view;

    if (tlv_write(buffer, sizeof(buffer), &tlv_writer_format_fixed_1byte, tag, value, sizeof(value),
                  &written) != TLV_OK)
        return 1;
    if (tlv_read(buffer, written, &tlv_reader_format_fixed_1byte, &view, &consumed) != TLV_OK)
        return 1;

    /* view.value borrows buffer; keep it alive while using the view. */
    if (consumed != written || view.tag.size != 1 || view.tag.data[0] != 0x01) return 1;
    if (view.value.length != sizeof(value) || memcmp(view.value.data, value, sizeof(value)) != 0)
        return 1;
    return 0;
}
```

Requires CMake 3.16+ and a supported compiler: GCC, MSVC, or upstream Clang 18+.
The C API requires C99; the optional C++ wrapper requires C++11 or newer.
C++23 builds require CMake 3.20+. Tests use GoogleTest and require C++17 or newer.

Build the library and bundled examples without fetching test dependencies:

```sh
cmake -S . -B build -DOPENTLV_BUILD_TESTS=OFF
cmake --build build --config Release --parallel
```

See [getting started](docs/getting-started/README.md) for linking this example, CMake
integration, C-only builds, and running tests. The [C](examples/tlv/src/) examples
cover more of the API, one topic per file, and the [C++](examples/tlv++/src/basic_usage.cpp)
example covers the default format; [examples/tlv/src/builtins/emv/tag_decoding.c](examples/tlv/src/builtins/emv/tag_decoding.c)
walks a full EMV TLV record through tag lookup, length validation, and value decoding.

## Documentation

An optional command-line tool (built on the `tlv++` wrapper, so it requires a
C++11+ compiler) supports TLV inspection and structural validation from
files, stdin, or hexadecimal input. Builds by default (`OPENTLV_BUILD_CLI`);
see the [CLI guide](docs/cli/README.md) for commands, build instructions, limits,
and exit codes.

Start with the [documentation index](docs/README.md), or choose a topic:

| Topic | Guide |
| --- | --- |
| Build and integrate | [Getting started](docs/getting-started/README.md), [distribution archives](docs/getting-started/README.md#install-and-generate-distribution-archives), [compiler support](docs/reference/compilers.md) |
| Architecture and API migration | [Layers, component options, and migration](docs/concepts/architecture.md) |
| Read, write, and traverse | [Formats and I/O contracts](docs/formats/README.md), [core types](docs/concepts/core-types.md) |
| Validate and decode | [Schemas](docs/guides/schemas.md), [value codecs](docs/guides/codecs.md), [DER](docs/profiles/der/README.md), [CER](docs/profiles/cer/README.md), [EMV](docs/profiles/emv/README.md) |
| Copy and recover data | [Copy helpers](docs/guides/copy.md), [recovery scanner](docs/guides/scanner.md), [byte order](docs/concepts/endian.md) |

## Long-term direction

OpenTLV 1.x is the stable, compile-time foundation described above: a
portable C core and C++ wrapper with built-in formats, schemas, and codecs
defined at compile time. Beyond 1.x, the project's planned direction moves
toward runtime-defined TLV formats (an OpenTLV Definition Language, or OTDL),
a runtime semantic model for interpreting decoded values, and an
`opentlv-gen` compiler that generates native C/C++ code from OTDL
definitions. See [ROADMAP.md](ROADMAP.md) for the full stage-by-stage plan;
future major-version functionality described there is direction, not a
committed API or implementation design.

## Releases and contributing

See [releases](https://github.com/marekcingel/OpenTLV/releases) and the
[changelog](CHANGELOG.md) for version history and migration-relevant changes.
Bug reports and feature proposals are welcome through
[GitHub issues](https://github.com/marekcingel/OpenTLV/issues).
See [contributing](CONTRIBUTING.md) before opening a pull request.

OpenTLV is distributed under the [MIT license](LICENSE).
