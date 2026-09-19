# OpenTLV

OpenTLV is a portable C99 library with a C++ wrapper for reading, writing,
traversing and validating TLV (Tag-Length-Value) data. It covers default and
fixed one-byte formats, BER, DER and CER, application-defined formats, and an
EMV Contact Book 3 profile.

## Where to start

| I want to... | Go to |
| --- | --- |
| Build the library and link it into a project | [Getting started](getting-started/README.md) |
| Understand the layers and components | [Architecture](concepts/architecture.md) |
| Pick a TLV format | [Formats](formats/README.md#choose-a-format) |
| Understand who owns parsed data | [Memory ownership](guides/memory.md) |
| Validate or decode values | [Schemas](guides/schemas.md), [value codecs](guides/codecs.md) |
| Work with DER, CER or EMV data | [DER](profiles/der/README.md), [CER](profiles/cer/README.md), [EMV](profiles/emv/README.md) |
| Look up an exact function, type or contract | [C API](reference/c-api.md), [C++ API](reference/cxx-api.md) |
| Inspect TLV data from a terminal | [The `otlv` CLI](cli/README.md) |
| Contribute or run the fuzzers | [Fuzzing](development/fuzzing.md), [Contributing](../CONTRIBUTING.md) |

## Sections

- **Getting Started** - builds, CMake integration and tests.
- **Concepts** - architecture, core types, borrowed values, lengths and byte order.
- **Guides** - memory ownership, schemas, value codecs, copy helpers and recovery scanning.
- **Formats** - reading, writing and traversal for each TLV format, with byte examples.
- **Profiles** - DER, CER and EMV semantics layered on the formats.
- **CLI** - the `otlv` command-line tool.
- **Reference** - the generated [C API](reference/c-api.md) and [C++ API](reference/cxx-api.md) references and supported compilers.
- **Development** - fuzzing and [where documentation belongs](development/documentation-layout.md).

Exact API contracts live in the generated [C API](reference/c-api.md) and
[C++ API](reference/cxx-api.md) references; the guides here explain how to use them.

## Project

[Roadmap](../ROADMAP.md) ·
[Changelog](../CHANGELOG.md) ·
[Security policy](../SECURITY.md) ·
[License](../LICENSE) ·
[Source on GitHub](https://github.com/marekcingel/OpenTLV)
