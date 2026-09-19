# OpenTLV

OpenTLV is a portable C99 library with a C++ wrapper for reading, writing,
traversing and validating TLV (Tag-Length-Value) data. It covers default and
fixed one-byte formats, BER, DER and CER, application-defined formats, and an
EMV Contact Book 3 profile.

## Where to start

| I want to... | Go to |
| --- | --- |
| Build the library and link it into a project | [Getting started](getting-started.md) |
| Understand the layers and components | [Architecture](architecture.md) |
| Pick a TLV format | [Formats](formats/README.md#choose-a-format) |
| Understand who owns parsed data | [Memory ownership](memory.md) |
| Validate or decode values | [Schemas](schemas.md), [value codecs](codecs.md) |
| Work with DER, CER or EMV data | [Profiles](profiles/der/README.md) |
| Inspect TLV data from a terminal | [The `otlv` CLI](cli.md) |
| Contribute or run the fuzzers | [Fuzzing](fuzzing.md), [Contributing](../CONTRIBUTING.md) |

## Sections

- **Getting Started** - builds, CMake integration and supported compilers.
- **Concepts** - architecture, core types, borrowed values, lengths and byte order.
- **Formats** - reading, writing and traversal for each TLV format, with byte examples.
- **Profiles** - DER, CER and EMV semantics layered on the formats.
- **Guides** - memory ownership, schemas, value codecs, copy helpers and recovery scanning.
- **CLI** - the `otlv` command-line tool.
- **Development** - fuzzing and project assets.

Dedicated C and C++ API reference manuals are not yet available. Use the guides
here and the public headers in [tlv](../tlv/include/tlv) and
[tlv++](../tlv++/include/tlv++) for the current API.

## Project

[Roadmap](../ROADMAP.md) ·
[Changelog](../CHANGELOG.md) ·
[Security policy](../SECURITY.md) ·
[License](../LICENSE) ·
[Source on GitHub](https://github.com/marekcingel/OpenTLV)
