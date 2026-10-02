# Executable examples and workflow coverage

Examples are part of the public documentation surface: they demonstrate the
same concepts through each language's intended API. Native C interoperability
is explicit in the C++ runtime Fixed, advanced-control and Schema examples;
it is not the default application path. Go examples import only the public
package. Rust uses `opentlv`, Python uses `opentlv`, Lua uses `require("opentlv")`
and WebAssembly uses the supported JavaScript loader.

## Workflow coverage

Links below name existing programs, not promised parity. A dash means there is
no dedicated example for that workflow; the binding may still implement it.
See the [binding matrix](../concepts/bindings.md) for actual capability coverage.

| Workflow | C | C++ | Rust | Python | Lua | Go | WASM |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Quick start | quick_start.c | quick_start.cpp | quick_start.rs | quick_start.py | quick_start.lua | quick_start/main.go | — |
| Reader | sequential_io.c, incremental_reader.c | quick_start.cpp, advanced_control.cpp | reader.rs | parse.py | quick_start.lua | reader/main.go | parse.mjs |
| Writer | sequential_io.c | quick_start.cpp | writer.rs | writer.py | quick_start.lua | writer/main.go | — |
| Nested/tree traversal | tree_reader.c, visitor.c, parse.c | parse.cpp | parse.rs | parse.py | parse.lua | — | parse.mjs |
| Nested construction | tree_writer.c, write.c | write.cpp | write.rs | write.py | — | writer/main.go | — |
| Owned Document | — | document.cpp, document_edit.cpp | — | document.py | — | document/main.go | — |
| Query | query.c | query.cpp | — | query.py | — | query/main.go | — |
| Schema / validation | schema_visitor.c, validate.c | validate.cpp | validate.rs | validate.py | schema.lua | — | — |
| Codec / typed Values | codecs_and_endian.c | typed_fields.cpp | — | codec.py | codec.lua | codec/main.go | — |
| Built-in standards | BER, CER, EMV, DHCP, LLDP, NFC programs | BER use cases, lldp.cpp | BER use cases | BER use cases | BER use cases / EMV codec | optional BER nested writing | BER parsing |

## Running and CI coverage

The [quick start](../getting-started/README.md#quick-start) supplies setup and
run commands. Use the [C++ guide](cxx-examples.md) and the language guides for
[Rust](rust.md), [Python](python.md), [Lua](lua.md) and [Go](go.md).
C/C++ sources are registered by their example CMake files and run as CTest
examples when their components are enabled. Component prerequisites can omit
individual programs; compiling a minimal build does not exercise disabled formats.

Rust CI builds all targets and runs the quick start; that is not a claim that
every example is runtime-tested. Python and Lua CI run their example programs.
Go CI runs applicable examples in default/minimal builds, excluding Document
and Query where Document is disabled. WASM's Node example is runnable after an
Emscripten build; a WASM build alone does not prove that example was run.
The CLI's [acceptance script](../../tools/cli/examples.cmake) exercises the
shared Fixed round trip and nested BER decode/encode/query workflows.

Embedded complete programs use `<!-- example: PATH -->`; run
`python scripts/check_doc_examples.py` to keep the copies identical. Small
illustrative fragments link to runnable programs. Changes to public APIs must
update their examples and documentation together.

## Source inventory

The [documentation inventory check](../development/documentation-layout.md#documentation-inventory-checks)
compares every source below with the example directories, detecting additions,
removals and stale links. This is an inventory, not evidence of a CI runtime pass.

<!-- example-inventory:start -->

| Language | Executable source | Demonstrates |
| --- | --- | --- |
| C | [builtins/asn1/ber.c](../../examples/tlv/src/builtins/asn1/ber.c) | BER framing / construction |
| C | [builtins/asn1/cer.c](../../examples/tlv/src/builtins/asn1/cer.c) | CER framing |
| C | [builtins/emv/tag_decoding.c](../../examples/tlv/src/builtins/emv/tag_decoding.c) | EMV definitions / codecs |
| C | [codecs_and_endian.c](../../examples/tlv/src/codecs_and_endian.c) | Value codecs and byte order |
| C | [copies.c](../../examples/tlv/src/copies.c) | Explicit copy / preservation |
| C | [custom_format.c](../../examples/tlv/src/custom_format.c) | Application Format |
| C | [dhcpv4.c](../../examples/tlv/src/dhcpv4.c) | DHCPv4 framing / End policy |
| C | [formats/fixed_format.c](../../examples/tlv/src/formats/fixed_format.c) | Generic Fixed Format |
| C | [incremental_reader.c](../../examples/tlv/src/incremental_reader.c) | Resumable input |
| C | [lldp.c](../../examples/tlv/src/lldp.c) | LLDP validation / codecs |
| C | [nfc_type2.c](../../examples/tlv/src/nfc_type2.c) | NFC Type 2 framing |
| C | [parse.c](../../examples/tlv/src/parse.c) | Nested parsing / traversal |
| C | [query.c](../../examples/tlv/src/query.c) | Path Query |
| C | [quick_start.c](../../examples/tlv/src/quick_start.c) | Quick start / round trip |
| C | [schema_visitor.c](../../examples/tlv/src/schema_visitor.c) | Schema and Visitor |
| C | [sequential_io.c](../../examples/tlv/src/sequential_io.c) | Sequential Reader / Writer |
| C | [tree_reader.c](../../examples/tlv/src/tree_reader.c) | Pull Tree Reader |
| C | [tree_writer.c](../../examples/tlv/src/tree_writer.c) | Tree Writer |
| C | [validate.c](../../examples/tlv/src/validate.c) | Schema / validation |
| C | [visitor.c](../../examples/tlv/src/visitor.c) | Visitor traversal |
| C | [write.c](../../examples/tlv/src/write.c) | Nested construction |
| C++ | [advanced_control.cpp](../../examples/tlv++/src/advanced_control.cpp) | Input control, scratch and explicit native interop |
| C++ | [basic_usage.cpp](../../examples/tlv++/src/basic_usage.cpp) | Reader / Writer / codecs |
| C++ | [document.cpp](../../examples/tlv++/src/document.cpp) | Owned Document / traversal |
| C++ | [document_edit.cpp](../../examples/tlv++/src/document_edit.cpp) | Document mutation |
| C++ | [formats/custom_format.cpp](../../examples/tlv++/src/formats/custom_format.cpp) | Application Format |
| C++ | [formats/fixed_format.cpp](../../examples/tlv++/src/formats/fixed_format.cpp) | Generic Fixed Format |
| C++ | [formats/fixed_format_runtime.cpp](../../examples/tlv++/src/formats/fixed_format_runtime.cpp) | Runtime Fixed / explicit native interop |
| C++ | [generate.cpp](../../examples/tlv++/src/generate.cpp) | Deterministic wire generation / owned cases |
| C++ | [lldp.cpp](../../examples/tlv++/src/lldp.cpp) | LLDP validation / codecs |
| C++ | [parse.cpp](../../examples/tlv++/src/parse.cpp) | Nested parsing / traversal |
| C++ | [query.cpp](../../examples/tlv++/src/query.cpp) | Path Query |
| C++ | [quick_start.cpp](../../examples/tlv++/src/quick_start.cpp) | Quick start / round trip |
| C++ | [typed_fields.cpp](../../examples/tlv++/src/typed_fields.cpp) | Typed fields / Values |
| C++ | [validate.cpp](../../examples/tlv++/src/validate.cpp) | Schema / validation |
| C++ | [write.cpp](../../examples/tlv++/src/write.cpp) | Nested construction |
| Rust | [parse.rs](../../bindings/rust/opentlv/examples/parse.rs) | Nested parsing / traversal |
| Rust | [quick_start.rs](../../bindings/rust/opentlv/examples/quick_start.rs) | Quick start / round trip |
| Rust | [reader.rs](../../bindings/rust/opentlv/examples/reader.rs) | Sequential Reader and input control |
| Rust | [validate.rs](../../bindings/rust/opentlv/examples/validate.rs) | Schema / validation |
| Rust | [write.rs](../../bindings/rust/opentlv/examples/write.rs) | Nested construction |
| Rust | [writer.rs](../../bindings/rust/opentlv/examples/writer.rs) | Sequential Writer |
| Python | [codec.py](../../bindings/python/opentlv/examples/codec.py) | Typed Value codecs |
| Python | [document.py](../../bindings/python/opentlv/examples/document.py) | Owned Document / traversal |
| Python | [parse.py](../../bindings/python/opentlv/examples/parse.py) | Nested parsing / traversal |
| Python | [query.py](../../bindings/python/opentlv/examples/query.py) | Path Query |
| Python | [quick_start.py](../../bindings/python/opentlv/examples/quick_start.py) | Quick start / round trip |
| Python | [validate.py](../../bindings/python/opentlv/examples/validate.py) | Schema / validation |
| Python | [write.py](../../bindings/python/opentlv/examples/write.py) | Nested construction |
| Python | [writer.py](../../bindings/python/opentlv/examples/writer.py) | Sequential Writer |
| Lua | [codec.lua](../../bindings/lua/examples/codec.lua) | Typed Value codecs |
| Lua | [parse.lua](../../bindings/lua/examples/parse.lua) | Nested parsing / traversal |
| Lua | [quick_start.lua](../../bindings/lua/examples/quick_start.lua) | Quick start / round trip |
| Lua | [schema.lua](../../bindings/lua/examples/schema.lua) | Structural Schema |
| Go | [codec/main.go](../../bindings/go/examples/codec/main.go) | Typed Value codecs |
| Go | [document/main.go](../../bindings/go/examples/document/main.go) | Owned Document / traversal |
| Go | [errors/main.go](../../bindings/go/examples/errors/main.go) | Owned diagnostics / error matching |
| Go | [query/main.go](../../bindings/go/examples/query/main.go) | Path Query |
| Go | [quick_start/main.go](../../bindings/go/examples/quick_start/main.go) | Quick start / round trip |
| Go | [reader/main.go](../../bindings/go/examples/reader/main.go) | Sequential Reader and input control |
| Go | [version/main.go](../../bindings/go/examples/version/main.go) | Version / native integration |
| Go | [writer/main.go](../../bindings/go/examples/writer/main.go) | Sequential Writer |
| WebAssembly | [parse.mjs](../../bindings/wasm/examples/parse.mjs) | Nested parsing / traversal |

<!-- example-inventory:end -->
