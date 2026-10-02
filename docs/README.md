# OpenTLV documentation

[Project overview](../README.md)

OpenTLV uses a canonical C execution engine and interoperability boundary,
with an idiomatic `tlv++` C++ API and official Rust, Python, Lua and Go bindings.
The `otlv` CLI and WebAssembly support use the same architecture. Reader, Writer,
Tree Reader, Tree Writer and Visitor support borrowed and streaming processing;
mutable Document owns data for editing. Query, Schema, Codec and diagnostics
compose with generic formats and protocol-specific built-ins.

The shared Format, Layout, Element, Schema and Codec contracts are described in
the [conceptual model](concepts/architecture.md#conceptual-model) and
[binding model](concepts/bindings.md). See [memory ownership](guides/memory.md)
for borrowed lifetimes and the allocating Document representation.

Documentation is grouped by purpose. See
[where documentation belongs](development/documentation-layout.md) before adding a page.

## Getting started

- [Getting started: builds, CMake integration, and tests](getting-started/README.md)
- Usage examples: [C](../examples/tlv/src/) and [C++](../examples/tlv++/src/basic_usage.cpp)
- [EMV tag decoding walkthrough](../examples/tlv/src/builtins/emv/tag_decoding.c)

## Language APIs

- [Binding capability reference](concepts/bindings.md)
- [C++ examples and API usage](guides/cxx-examples.md)
- [Using OpenTLV from Rust](guides/rust.md)
- [Using OpenTLV from Python](guides/python.md)
- [Using OpenTLV from Lua](guides/lua.md)
- [Using OpenTLV from Go](guides/go.md)
- [WebAssembly tooling](development/webassembly.md)

## Concepts

- [Layered architecture, component selection, and API migration](concepts/architecture.md)
- [Core types: tags, values, lengths, and ownership](concepts/core-types.md)
- [Borrowed TLV values](concepts/value.md)
- [Logical TLV value lengths](concepts/length.md)
- [Integer byte-order conversions](concepts/endian.md)

## Guides

- [Choose a processing API](guides/processing.md)
- [Executable examples and workflow coverage](guides/examples.md)
- [Path queries](guides/queries.md)
- [Memory ownership and lifetime](guides/memory.md)
- [Diagnostics](guides/diagnostics.md)
- [Schemas and length validation](guides/schemas.md)
- [Value codecs](guides/codecs.md)
- [Copy helpers](guides/copy.md)
- [Pull-based Reader](guides/reader.md)
- [Writer and scoped construction](guides/writer.md)
- [Mutable documents](guides/document.md)
- [Building only the components you need](guides/select-components.md)

## Formats

- [Implemented format and standard capabilities](formats/support.md)
- [Choosing a format](formats/README.md#choose-a-format)
- [Formats, reading, writing, traversal, and custom callbacks](formats/README.md)
- [Format trees and byte examples](formats/format-examples.md)
- [Format expansion candidates and proposed priorities](formats/format-roadmap.md)
- [Format candidate catalogue: specifications, components and limits](formats/format-catalogue.md)

## Builtins

- [EMV Contact Book 3 v4.4](standards/emv/README.md)
- [ASN.1 DER-TLV and validation limits](standards/der/README.md)
- [ASN.1 CER-TLV and validation limits](standards/cer/README.md)

## CLI

- [Command-line inspection and validation](cli/README.md)

## Playground

- [Interactive TLV playground](playground/index.md)

## Reference

- [Reference overview](reference/README.md)
- [Generated C API reference](reference/c-api.md)
- [Generated C++ API reference](reference/cxx-api.md)
- [Supported compilers and build settings](reference/compilers.md)
- [Error codes](reference/errors.md)

## Development

- [Core architectural rules](concepts/architectural-rules.md)
- [Processing pipeline contract](concepts/processing-pipeline.md)
- [Planned runtime model and canonical IR](concepts/runtime-model.md)
- [Go binding development](development/go.md)

- [Where documentation belongs](development/documentation-layout.md)
- [C API fuzzing with ASan and UBSan](development/fuzzing.md)
- [Experimental WebAssembly build](development/webassembly.md)
- [Logo assets](assets/README.md)

## Project

- [Long-term roadmap](../ROADMAP.md)
- [Changelog](../CHANGELOG.md)
- [Contributing](../CONTRIBUTING.md)
- [Public API documentation conventions](../CONTRIBUTING.md#public-api-documentation)
- [Security policy](../SECURITY.md)
- [License](../LICENSE)
