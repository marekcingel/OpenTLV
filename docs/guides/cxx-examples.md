# C++ examples

The C++ facade delegates parsing, traversal, Query and encoding to the canonical
C engine. The common examples below use C++11; no generic lambdas are required.
The [source index](../../examples/tlv++/src/README.md) lists all runnable examples.

## Borrowed parsing and sequential iteration

The [quick-start](../getting-started/README.md#quick-start) uses
`tlv::ber::parse({input, sizeof(input)})`. This returns an allocation-free,
single-pass range of Elements at one level, including constructed Elements
whose Values are still encoded child bytes. It does not recursively flatten
the tree. Input must remain immutable and alive for the range and retained
Elements. Iteration throws `tlv::parse_error` on malformed final input.

The same rule applies to [`basic_usage.cpp`](../../examples/tlv++/src/basic_usage.cpp),
which writes two primitive elements and reads only the written output prefix.
Writing returns a result; check it before reading output. A failed scoped write
may leave a prefix in the output buffer; do not publish that output as a success.

<!-- example: examples/tlv++/src/basic_usage.cpp -->
```cpp
// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

// Write two primitive BER elements, then iterate over that sequence.
#include <tlv++/tlv.hpp>
#include <array>
#include <iostream>

int main() {
    std::array<tlv::byte, 14> output{};
    auto                      written = tlv::ber::encode(output, [](tlv::writer_builder& writer) {
        writer.write<0x04>("hello");
        writer.write<0x04>("world");
    });
    if (!written) {
        std::cerr << written.error().message() << '\n';
        return 1;
    }

    // Only the written prefix is input; borrowed Values cannot outlive output.
    size_t count = 0;
    try {
        for (auto element : tlv::ber::parse({output.data(), *written})) {
            std::cout << "Value bytes: " << element.value().size() << '\n';
            if (element.tag() != tlv::tag_bytes<0x04>() || element.value().size() != 5) return 2;
            ++count;
        }
    } catch (const tlv::parse_error& failure) {
        std::cerr << failure.what() << '\n';
        return 1;
    }
    return count == 2 && *written == output.size() ? 0 : 2;
}
```

## Nested writing and traversal

[`write.cpp`](../../examples/tlv++/src/write.cpp) expresses nesting with
`writer.constructed<Tag>(callback)` and writes Values directly from text or byte
arrays. Its `encode<12, 2>` uses bounded local storage: 12 scratch bytes and two
frames. No storage grows or allocates; insufficient output, scratch or depth
returns an error. The default overload uses 1024 scratch bytes and the default
tree depth. Select capacities for your data, or pass caller-owned
`writer_storage<Scratch, Depth>::view()` as described in the [Writer guide](writer.md).
Scoped callbacks collect the first failure; check the outer result.

[`parse.cpp`](../../examples/tlv++/src/parse.cpp) visits all four Elements in the
same nested document through the canonical Tree Reader Visitor. It supplies two
caller-owned frames, a depth limit of two and an element limit of 16. Those
frames and input must outlive traversal. The callback supplies a C++ Element,
depth and source offset; the native continue enum is explicit advanced control.
Tree Reader currently has no general range interface, so this remains an advanced
example. Use Document children for common owning traversal. See the [Reader guide](reader.md) for incremental input.

## Owning Document and Query

Document parsing returns a checked result and owns the parsed data. Iteration
visits roots; `node.children()` visits immediate children. Nodes borrow their
Document and become invalid when the Document dies or their node is erased.
See [`document_edit.cpp`](../../examples/tlv++/src/document_edit.cpp) for mutation.

<!-- example: examples/tlv++/src/document.cpp -->
```cpp
// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

// Parse an owning Document and traverse roots and their children.
#include <tlv++/tlv.hpp>
#include <iostream>

int main() {
    const tlv::byte input[] = {tlv::byte(0x30), tlv::byte(0x03), tlv::byte(0x04), tlv::byte(0x01),
                               tlv::byte('A'),  tlv::byte(0x04), tlv::byte(0x01), tlv::byte('B')};
    auto            document =
        tlv::document::parse({input, sizeof(input)}, tlv::document_format(tlv::ber::format{}));
    if (!document) {
        std::cerr << document.error().message << '\n';
        return 1;
    }
    // Document owns its data; Nodes borrow this Document and cannot outlive it.
    size_t roots = 0, children = 0;
    for (auto node : *document) {
        std::cout << "Root Value bytes: " << node.value().size() << '\n';
        ++roots;
        for (auto child : node.children()) {
            std::cout << "  Child Value bytes: " << child.value().size() << '\n';
            ++children;
        }
    }
    return roots == 2 && children == 1 ? 0 : 2;
}
```

For an owning Document, `document.select("6F/A5/50")` returns matching Node
handles. For borrowed streaming traversal, `reader.select("6F/A5/50")` returns
a lazy range. [`query.cpp`](../../examples/tlv++/src/query.cpp) executes both
forms when Document is enabled. Invalid Query text throws `query_error`;
streaming parse failures throw `parse_error`. Document parsing itself uses a
result that must be checked before selection. Document and its selection
snapshot may allocate; streaming selection does not allocate on success.

## Typed Values and custom Formats

[`typed_fields.cpp`](../../examples/tlv++/src/typed_fields.cpp) defines an
application `Counter` field with byte Tag `9F36`, `uint16_t` and an explicit
big-endian codec. It uses `writer.write<Counter>(value)`,
`element.decode<Counter>()` and optional `document.get<Counter>()`.
Typed results preserve codec and framing failures. The short Writer overload
allocates temporary Value storage; [`advanced_control.cpp`](../../examples/tlv++/src/advanced_control.cpp)
instead supplies two caller-owned scratch bytes.

[`formats/fixed_format.cpp`](../../examples/tlv++/src/formats/fixed_format.cpp)
uses a compile-time Format with typed Reader and Writer; it needs no native
descriptor access. Its byte-order template argument still uses
`TLV_BYTE_ORDER_LITTLE_ENDIAN`: that is an existing public API requirement.
A completely application-defined Format is shown separately in
[`formats/custom_format.cpp`](../../examples/tlv++/src/formats/custom_format.cpp).
It implements decode, measure and encode contracts and source ranges, while
generic Reader and Writer still execute the canonical engine.

## Measuring ceremony

These are nonblank, noncomment physical source-line counts from the previous
examples and this rewrite. Include braces, calls and error reporting; exclude
input/output fixtures, printing of successful results and acceptance checks.
Count the complete writing block up to the first success message or parsing,
and the Document parse/check/move block up to traversal. Fixed-format counting
also excludes its one-line Value fixture. This measures the visible code users
need, with the committed formatting, rather than just API calls.

| Operation | Previous lines | Current lines | What changed |
| --- | ---: | ---: | --- |
| Write two primitive BER Values (`basic_usage.cpp`) | 14 | 8 | Scoped encode replaces explicit Writer setup, a byte conversion helper and two individual result checks. |
| Write a custom fixed-format Value (`formats/fixed_format.cpp`) | 7 | 6 | Typed Writer and direct array input replace descriptor selection and explicit Tag/Value adaptation. |
| Parse/check an owning Document (`document.cpp`) | 4 | 6 | Iteration uses the checked result directly, removing the move; explicit error reporting adds lines. |

Streaming Query now uses `reader.select(path)` instead of a callback and native
continue enum. Its bounded frame setup and two possible exception types remain
visible. Borrowed nested Visitor traversal retains four setup/result operations:
frames, cursor, Visitor call and result check. Neither example hides limits or
failure handling to lower its line count.

The quick-start now isolates parsing; its total length is not compared with the
old round-trip program because they perform different operations. Document
parsing retains explicit Format selection, and borrowed input still requires a
byte span. These remaining setup requirements are visible rather than hidden in
example-only adapters. Allocation-free native control and explicit C structure
access belong in the [advanced examples](../../examples/tlv++/src/README.md#advanced-control).

## Equivalent CLI operations

With BER enabled, these commands use the same primitive and nested bytes as the
C++ examples. `otlv` allocates its input/output storage; C++ callers can select
borrowed ranges or an owning Document explicitly.

```sh
otlv encode --format ber --tag 04 --value 414243
otlv dump --format ber --hex 0403414243 --no-color
otlv decode --format ber --hex 6F0A8403414243A503500101
otlv query 6F/A5/50 --format ber --hex 6F0A8403414243A503500101 --value
```

The first command produces `0403414243`; Query produces `01`. Decode produces
the versioned JSON model, which `otlv encode --format ber --input model.json`
encodes back to the original bytes. The following executable acceptance example
checks those exact outputs. CTest runs it as `Integration_cli_cpp_examples` when
`OPENTLV_BUILD_CLI_TESTS` and BER are enabled; temporary JSON is written in the
build directory. Run it there with `cmake -DCLI=/path/to/otlv -P
/path/to/tools/cli/examples.cmake`.

<!-- example: tools/cli/examples.cmake -->
```cmake
# Run from a build directory: cmake -DCLI=/path/to/otlv -P /path/to/tools/cli/examples.cmake
cmake_minimum_required(VERSION 3.16)

function(run_cli expected)
    execute_process(COMMAND "${CLI}" ${ARGN} RESULT_VARIABLE result
        OUTPUT_VARIABLE output ERROR_VARIABLE error)
    string(STRIP "${output}" output)
    if(NOT result EQUAL 0 OR NOT error STREQUAL "" OR NOT output STREQUAL expected)
        message(FATAL_ERROR "${ARGN}: ${result}\n${output}\n${error}\nExpected: ${expected}")
    endif()
endfunction()

# Same primitive Value as the C++ quick-start.
run_cli("0403414243" encode --format ber --tag 04 --value 414243)
run_cli("offset=0 tag=04 length=3 value=414243" dump --format ber --hex 0403414243 --no-color)

# Same nested bytes as C++ parse.cpp, write.cpp and query.cpp.
set(wire "6F0A8403414243A503500101")
set(model [=[{"schema":"opentlv.tlv","version":1,"format":"ber","elements":[{"tag":"6F","length_mode":"definite","children":[{"tag":"84","value":"414243"},{"tag":"A5","length_mode":"definite","children":[{"tag":"50","value":"01"}]}]}]}]=])
run_cli("${model}" decode --format ber --hex "${wire}")
run_cli("01" query 6F/A5/50 --format ber --hex "${wire}" --value)

# Write the decoded model in the build directory, then regenerate the exact wire bytes.
set(json "${CMAKE_CURRENT_BINARY_DIR}/cpp-example.json")
file(WRITE "${json}" "${model}\n")
run_cli("${wire}" encode --format ber --input "${json}")
```

See the [CLI guide](../cli/README.md) for installation, binary output and limits.

The CLI implementation also consumes the C++ facade: built-in Format views,
Tree Reader traversal, borrowed Element access, Writer sizing/encoding and an
owning Query matcher. Runtime Fixed configuration belongs to each command.
Query feeds every visited ancestor to the matcher so failure diagnostics retain
the enclosing path. Recovery uses checked single-element reads. Strict DER,
PDOL identifiers and existing protocol annotation/diagnostic adapters retain
explicit native interoperability where their specialized contracts require it.
CLI JSON encoding validates output with the same Fixed widths and byte order
selected for writing.

## Build and run

```sh
cmake -S . -B build -DCMAKE_CXX_STANDARD=11
cmake --build build --config Debug --parallel
ctest --test-dir build -C Debug -L examples --output-on-failure --no-tests=error
python scripts/check_doc_examples.py
```

BER examples require `OPENTLV_FORMAT_BER`; Document examples additionally require
`OPENTLV_DOCUMENT`. Generic Format, typed field and advanced control examples
remain available when optional protocols are disabled. The CI compiler jobs run
registered examples through the integration label. Documentation blocks above
are synchronized with their compiled or executed sources by the example checker.
