# OpenTLV documentation

[Project overview](../README.md)

## Start here

- [Getting started: builds, CMake integration, and tests](getting-started.md)
- [Supported compilers and build settings](compilers.md)
- [Layered architecture, component selection, and API migration](architecture.md)
- Usage examples: [C](../examples/tlv/src/basic_usage.c) and [C++](../examples/tlv++/src/basic_usage.cpp)

- [Choosing a format](formats/README.md#choose-a-format)
- [Memory ownership and lifetime](memory.md)

## Core API and formats

- [Format trees and byte examples](format-examples.md)

- [Format expansion candidates and proposed priorities](format-roadmap.md)
- [Core types and buffer ownership](core-types.md)
- [Formats, reading, writing, traversal, and custom callbacks](formats/README.md)
- [Schemas and length validation](schemas.md)
- [Value codecs](codecs.md)
- [Copy helpers](copy.md)
- [TLV scanning and recovery](scanner.md)
- [Integer byte-order conversions](endian.md)

## Profiles

- [EMV Contact Book 3 v4.4](profiles/emv/README.md)
- [ASN.1 DER-TLV and validation limits](profiles/der/README.md)

## Project

- [Logo assets](assets/README.md)
- [Changelog](../CHANGELOG.md)
- [Contributing](../CONTRIBUTING.md)
- [License](../LICENSE)

Dedicated C and C++ API reference manuals are not yet available. Use the guides
above and the public headers in [tlv](../tlv/include/tlv) and
[tlv++](../tlv++/include/tlv++) for the current API.
