# C++ examples

- **Start here:** [`quick_start.cpp`](quick_start.cpp) -- the smallest possible
  round trip: write one element, read it back.

## Use cases

The same document is parsed, built, addressed and checked here as in
[`examples/tlv`](../../tlv/src/), [`bindings/rust/opentlv/examples`](../../../bindings/rust/opentlv/examples/)
and [`bindings/wasm/examples`](../../../bindings/wasm/examples/), so the same
operation can be compared across languages.

- [`parse.cpp`](parse.cpp) -- read a nested BER-TLV document.
- [`write.cpp`](write.cpp) -- build that same document from its parts.
- [`query.cpp`](query.cpp) -- address one field directly by path.
- [`validate.cpp`](validate.cpp) -- check the document's structure without decoding it.

## API tour

- [`basic_usage.cpp`](basic_usage.cpp) -- a sequential `tlv::writer`/`tlv::reader`
  round trip over the default format.

## Builtins

Examples specific to one wire format.

- [`builtins/fixed/fixed_format.cpp`](builtins/fixed/fixed_format.cpp) --
  `tlv::fixed_format<>`, a compile-time configurable fixed-width format.
