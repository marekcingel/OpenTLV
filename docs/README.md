# OpenTLV documentation

[Project overview](../README.md)

Documentation is grouped by purpose. See
[where documentation belongs](development/documentation-layout.md) before adding a page.

## Getting started

- [Getting started: builds, CMake integration, and tests](getting-started/README.md)
- Usage examples: [C](../examples/tlv/src/basic_usage.c) and [C++](../examples/tlv++/src/basic_usage.cpp)
- [EMV tag decoding walkthrough](../examples/emv/src/tag_decoding.c)

## Concepts

- [Layered architecture, component selection, and API migration](concepts/architecture.md)
- [Core types: tags, values, lengths, and ownership](concepts/core-types.md)
- [Borrowed TLV values](concepts/value.md)
- [Logical TLV value lengths](concepts/length.md)
- [Integer byte-order conversions](concepts/endian.md)

## Guides

- [Memory ownership and lifetime](guides/memory.md)
- [Schemas and length validation](guides/schemas.md)
- [Value codecs](guides/codecs.md)
- [Copy helpers](guides/copy.md)
- [TLV scanning and recovery](guides/scanner.md)

## Formats

- [Choosing a format](formats/README.md#choose-a-format)
- [Formats, reading, writing, traversal, and custom callbacks](formats/README.md)
- [Format trees and byte examples](formats/format-examples.md)
- [Format expansion candidates and proposed priorities](formats/format-roadmap.md)

## Profiles

- [EMV Contact Book 3 v4.4](profiles/emv/README.md)
- [ASN.1 DER-TLV and validation limits](profiles/der/README.md)
- [ASN.1 CER-TLV and validation limits](profiles/cer/README.md)

## CLI

- [Command-line inspection and validation](cli/README.md)

## Reference

- [Reference overview](reference/README.md)
- [Generated C API reference](reference/c-api.md)
- [Generated C++ API reference](reference/cxx-api.md)
- [Supported compilers and build settings](reference/compilers.md)

## Development

- [Where documentation belongs](development/documentation-layout.md)
- [C API fuzzing with ASan and UBSan](development/fuzzing.md)
- [Logo assets](assets/README.md)

## Project

- [Long-term roadmap](../ROADMAP.md)
- [Changelog](../CHANGELOG.md)
- [Contributing](../CONTRIBUTING.md)
- [Public API documentation conventions](../CONTRIBUTING.md#public-api-documentation)
- [Security policy](../SECURITY.md)
- [License](../LICENSE)
