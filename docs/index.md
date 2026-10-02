# OpenTLV

OpenTLV is a portable foundation for reading, writing, traversing, editing and
validating TLV (Tag-Length-Value) data. The C99 library is its canonical execution
engine and interoperability boundary. The idiomatic `tlv++` C++ API and official
Rust, Python, Lua and Go bindings expose the same conceptual model through
language-native APIs; the `otlv` CLI and WebAssembly support use the same engine.

Reader and Writer support borrowed and streaming processing, with Tree Reader,
Tree Writer and Visitor for nested data. Mutable Document provides an owned
representation for editing; Query selects elements, Schema validates structure,
Codec interprets values, and diagnostics report failures. Generic formats and
protocol-specific built-ins share these mechanisms.

Format, Layout, Element, Schema and Codec keep wire encoding, source locations,
semantic content, structure and value interpretation separate. Reader, Writer,
Query and Document reuse these contracts. See the
[conceptual model](concepts/architecture.md#conceptual-model),
[binding model](concepts/bindings.md) and [memory ownership](guides/memory.md)
for their responsibilities and lifetimes.

## Where to start

| I want to... | Go to |
| --- | --- |
| Build the library and link it into a project | [Getting started](getting-started/README.md) |
| Choose borrowed traversal or owned editing | [Processing choices](guides/processing.md) |
| Use a language API | [C++](guides/cxx-examples.md), [Rust](guides/rust.md), [Python](guides/python.md), [Lua](guides/lua.md), [Go](guides/go.md), [WebAssembly](development/webassembly.md) |
| Write or modify a message | [Writer](guides/writer.md), [Document](guides/document.md) |
| Query nested data | [Path queries](guides/queries.md) |
| Run a complete example | [Executable examples](guides/examples.md) |
| Check current support versus planned work | [Implemented capabilities](formats/support.md), [Roadmap](../ROADMAP.md) |
| Understand the layers and components | [Architecture](concepts/architecture.md) |
| Pick a TLV format | [Formats](formats/README.md#choose-a-format) |
| Understand who owns parsed data | [Memory ownership](guides/memory.md) |
| Validate or decode values | [Schemas](guides/schemas.md), [value codecs](guides/codecs.md) |
| Work with DER, CER or EMV data | [DER](standards/der/README.md), [CER](standards/cer/README.md), [EMV](standards/emv/README.md) |
| Look up an exact function, type or contract | [C API](reference/c-api.md), [C++ API](reference/cxx-api.md) |
| Inspect TLV data from a terminal | [The `otlv` CLI](cli/README.md) |
| Contribute or run the fuzzers | [Fuzzing](development/fuzzing.md), [Contributing](../CONTRIBUTING.md) |

## Sections

- **Getting Started** - builds, CMake integration and tests.
- **Architecture and Concepts** - shared model, core types, borrowed values, lengths and byte order.
- **Language APIs** - C++, Rust, Python, Lua, Go and WebAssembly entry points.
- **Guides** - processing choices, Reader, Writer, Document, Query, schemas, codecs and executable examples.
- **Formats** - reading, writing and traversal for each TLV format, with byte examples.
- **Standards** - DER, CER and EMV validation, definitions, schemas and codecs.
- **CLI** - the `otlv` command-line tool.
- **Reference** - the generated [C API](reference/c-api.md) and [C++ API](reference/cxx-api.md) references and supported compilers.
- **Development** - technical contracts, runtime-model design, binding workflows, fuzzing and [where documentation belongs](development/documentation-layout.md).

Exact API contracts live in the generated [C API](reference/c-api.md) and
[C++ API](reference/cxx-api.md) references; the guides here explain how to use them.

## Project

[Roadmap](../ROADMAP.md) ·
[Changelog](../CHANGELOG.md) ·
[Security policy](../SECURITY.md) ·
[License](../LICENSE) ·
[Source on GitHub](https://github.com/marekcingel/OpenTLV)
