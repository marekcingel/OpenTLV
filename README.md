![OpenTLV - Tag, Length, Value](docs/assets/opentlv.svg)

[![GCC build and tests](https://github.com/marekcingel/OpenTLV/actions/workflows/build-gcc.yml/badge.svg?branch=main)](https://github.com/marekcingel/OpenTLV/actions/workflows/build-gcc.yml?query=branch%3Amain)
[![Clang build and tests](https://github.com/marekcingel/OpenTLV/actions/workflows/build-clang.yml/badge.svg?branch=main)](https://github.com/marekcingel/OpenTLV/actions/workflows/build-clang.yml?query=branch%3Amain)
[![MSVC build and tests](https://github.com/marekcingel/OpenTLV/actions/workflows/build-msvc.yml/badge.svg?branch=main)](https://github.com/marekcingel/OpenTLV/actions/workflows/build-msvc.yml?query=branch%3Amain)

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

The C++ layer offers convenience wrappers; error strings and dynamic containers
can allocate. Applications requiring strictly allocation-free behavior should use
the C API. Raw TLV reading does not interpret values or validate an entire protocol.

See [choosing a format](docs/formats/README.md#choose-a-format) and
[memory ownership](docs/memory.md) for practical guidance.

## Format and profile support

Checked items are implemented; the linked documentation defines their scope.
Unchecked items have no built-in implementation today. This is a support overview,
not a commitment to implement every listed format; scheduled work belongs in issues.
Built-in components are enabled by default and can be selected with
[CMake options](docs/architecture.md#build-configuration).

- **TLV processing**
  - [x] Primitive values
  - [x] Constructed / nested values
    - [x] BER/DER constructed-tag recognition and custom nesting predicates
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
    - [ ] **Configurable fixed-width TLV** - built-in configurable tag/length widths and byte order
  - **ASN.1-related encodings**
    - [x] **BER-TLV** - multi-byte tags. [Scope](docs/formats/asn1/ber.md) [Tree and bytes](docs/formats/asn1/ber.md#byte-example)
      - [x] Definite-length reading and writing
      - [x] Constructed indefinite-length reading and explicit writing
    - [x] **DER-TLV** - canonical identifier and length framing. [Scope](docs/profiles/der/README.md) [Tree and bytes](docs/formats/asn1/der.md#byte-example)
      - [x] Structural validation
      - [ ] Full ASN.1 value validation and canonical SET/SET OF ordering
    - [ ] **CER** - dedicated canonical encoding and validation
  - [x] **Application-defined format callbacks** - independent reader and writer descriptors. [Contracts](docs/formats/README.md#generic-interface) [Tree and bytes](docs/formats/custom/README.md#byte-example)
- **Protocol formats and profiles**
  - **Smart cards / payments**
    - [x] **EMV Contact Book 3 v4.4** - dictionary, contextual length schemas, and value codecs over BER-TLV; not a payment kernel. [Scope](docs/profiles/emv/README.md) [Tree and bytes](docs/profiles/emv/README.md#byte-example)
    - [ ] **EMV contactless kernels**
    - [ ] **GlobalPlatform DGI encoding**
  - **Networking**
    - [ ] **NDN packet TLV format**
    - [ ] **PEAP TLV structures**
    - [ ] **RADIUS attribute encoding**
  - **IoT / wireless**
    - [ ] **OMA LwM2M TLV format**
    - [ ] **Bluetooth LE advertising data (LTV)**

OpenTLV keeps framing, traversal, schemas, and value codecs separate. Broader
format coverage should come through selectable adapters and profiles around the
generic core. Protocol entries above refer to their data encodings and explicitly
named profile functionality, not complete networking or device stacks.

Tree traversal visits borrowed values without building an allocated object tree.
For definite-length containers, the value length covers the complete child
encodings; indefinite BER containers use EOC termination. See
[nested traversal](docs/formats/README.md#nested-traversal),
[value codecs](docs/codecs.md), and [architecture](docs/architecture.md).

See [format expansion candidates](docs/format-roadmap.md) for references,
implementation boundaries, and proposed priorities. Scheduled work is tracked
in [issues](https://github.com/marekcingel/OpenTLV/issues).

See [format trees and byte examples](docs/format-examples.md) for a field-by-field
view of every implemented format, including nested BER/DER and the EMV profile.

## Quick start

This complete C example writes `01 03 AA BB CC` and reads the value back:

```c
#include <string.h>
#include "tlv/formats/fixed/fixed_1byte.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"

int main(void) {
    const tlv_tag_t tag = {{0x01}, 1};
    const uint8_t value[] = {0xAA, 0xBB, 0xCC};
    uint8_t buffer[5];
    size_t written = 0, consumed = 0;
    tlv_view_t view;

    if (tlv_write(buffer, sizeof(buffer), &tlv_writer_format_fixed_1byte,
                  tag, value, sizeof(value), &written) != TLV_OK)
        return 1;
    if (tlv_read(buffer, written, &tlv_reader_format_fixed_1byte,
                 &view, &consumed) != TLV_OK)
        return 1;

    /* view.value borrows buffer; keep it alive while using the view. */
    return consumed == written && view.tag.size == 1 &&
           view.tag.data[0] == 0x01 && view.value.length == sizeof(value) &&
           memcmp(view.value.data, value, sizeof(value)) == 0 ? 0 : 1;
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

See [getting started](docs/getting-started.md) for linking this example, CMake
integration, C-only builds, and running tests. The [C](examples/tlv/src/basic_usage.c)
and [C++](examples/tlv++/src/basic_usage.cpp) examples cover more of the API.

## Documentation

Start with the [documentation index](docs/README.md), or choose a topic:

| Topic | Guide |
| --- | --- |
| Build and integrate | [Getting started](docs/getting-started.md), [distribution archives](docs/getting-started.md#install-and-generate-distribution-archives), [compiler support](docs/compilers.md) |
| Architecture and API migration | [Layers, component options, and migration](docs/architecture.md) |
| Read, write, and traverse | [Formats and I/O contracts](docs/formats/README.md), [core types](docs/core-types.md) |
| Validate and decode | [Schemas](docs/schemas.md), [value codecs](docs/codecs.md), [DER](docs/profiles/der/README.md), [EMV](docs/profiles/emv/README.md) |
| Copy and recover data | [Copy helpers](docs/copy.md), [recovery scanner](docs/scanner.md), [byte order](docs/endian.md) |

## Releases and contributing

See [releases](https://github.com/marekcingel/OpenTLV/releases) and the
[changelog](CHANGELOG.md) for version history and migration-relevant changes.
Bug reports and feature proposals are welcome through
[GitHub issues](https://github.com/marekcingel/OpenTLV/issues).
See [contributing](CONTRIBUTING.md) before opening a pull request.

OpenTLV is distributed under the [MIT license](LICENSE).
