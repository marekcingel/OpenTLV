# C++ examples

- **Start here:** [`quick_start.cpp`](quick_start.cpp) -- the smallest possible
  round trip: write one element, read it back.

## Use cases

The same document is parsed, built, addressed and checked here as in
[`examples/tlv`](../../tlv/src/), [`bindings/rust/opentlv/examples`](../../../bindings/rust/opentlv/examples/)
and [`bindings/wasm/examples`](../../../bindings/wasm/examples/), so the same
operation can be compared across languages.

- [`parse.cpp`](parse.cpp) -- read a nested BER-TLV document.
- [`document.cpp`](document.cpp) -- own, iterate and edit a Document with checked
  Node handles (requires Document and BER).
- [`write.cpp`](write.cpp) -- build that same document from its parts.
- [`query.cpp`](query.cpp) -- address one field directly by path.
- [`validate.cpp`](validate.cpp) -- check the document's structure without decoding it.

## API tour

- [`typed_fields.cpp`](typed_fields.cpp) -- associate byte tags with semantic types,
  write using caller-owned scratch, and decode through Element or optional Document.
  Requires C++11 and no optional protocol component.

- [`basic_usage.cpp`](basic_usage.cpp) -- a sequential `tlv::writer<>`/`tlv::reader<>`
  round trip over BER.

## Formats

Generic, protocol-agnostic format mechanisms.

- [`formats/custom_format.cpp`](formats/custom_format.cpp) -- an application-defined
  C++ Format used by the generic Reader and Writer, with no C descriptor construction.
- [`formats/fixed_format.cpp`](formats/fixed_format.cpp) --
  `tlv::fixed_format<>`, a compile-time configurable fixed-width format.
