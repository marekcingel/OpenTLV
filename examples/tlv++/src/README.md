# C++ examples

Start with [`quick_start.cpp`](quick_start.cpp): scoped encoding, iterable parsing
and typed string decoding for a Fixed-format `Hello, world!` round trip,
with explicit error handling and input lifetime. All examples compile and run
through CTest with the `examples` label when their components are enabled.
See the [C++ guide](../../../docs/guides/cxx-examples.md) for ownership,
workspace limits, API ceremony comparisons and equivalent CLI commands.

## Common operations

- [`basic_usage.cpp`](basic_usage.cpp): write two primitive elements and iterate
  over the sequence; uses the built-in BER Format.
- [`write.cpp`](write.cpp): build the same nested document with scoped writes.
- [`document.cpp`](document.cpp): parse an owning Document and traverse roots
  and children (requires Document and BER).
- [`query.cpp`](query.cpp): select a path from a streaming Tree Reader and,
  when enabled, an owning Document.
- [`typed_fields.cpp`](typed_fields.cpp): write and decode an application field,
  including `document.get<Counter>()` when Document is enabled. Typed writing
  owns temporary codec storage. No optional protocol component is required.
- [`formats/fixed_format.cpp`](formats/fixed_format.cpp): configure generic
  fixed-width framing, then use typed Reader and Writer.

The nested BER examples use the same wire data as the
[C](../../tlv/src/), [Rust](../../../bindings/rust/opentlv/examples/) and
[WASM](../../../bindings/wasm/examples/) examples. The CLI acceptance script is
[`tools/cli/examples.cmake`](../../../tools/cli/examples.cmake).

## Advanced control

- [`parse.cpp`](parse.cpp): nested borrowed Visitor traversal with bounded frames.

- [`advanced_control.cpp`](advanced_control.cpp): explicit codec scratch,
  incremental Reader outcomes and native C interoperability.
- [`document_edit.cpp`](document_edit.cpp): edit nodes, check erased handles,
  and encode an owning Document.
- [`formats/custom_format.cpp`](formats/custom_format.cpp): implement the
  complete C++ Format contract, including source metadata and bounded encoding.
- [`formats/fixed_format_runtime.cpp`](formats/fixed_format_runtime.cpp): choose
  framing at runtime through the native C API.
- [`validate.cpp`](validate.cpp): explicit native structure-schema validation.
- [`lldp.cpp`](lldp.cpp): protocol validation with the LLDP facade.

Examples use C++11-compatible lambdas. Format ordering and some advanced
contracts still use native enums; the guide identifies those remaining API
requirements rather than hiding them behind example-only helpers.
