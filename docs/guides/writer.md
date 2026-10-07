# Writer and scoped construction

Prerequisite: Understand Element and Format in the [basic model](../concepts/learning-model.md).

```text
Element --Writer + Format--> caller-provided output
```

See [Choose a processing API](processing.md) for ownership, nesting, resumable
input, construction and editing choices.

## Typed C++ writing

Include `<tlv++/writer/builder.hpp>` for generic construction or
`<tlv++/builtins/asn1/ber.hpp>` for the BER helper. Both use the canonical C
Writer and Tree Writer. Output remains caller-owned and is never resized.

```cpp
std::array<tlv::byte, 128> output{};
auto result = tlv::ber::encode(output, [](tlv::writer_builder& writer) {
    const uint8_t pan[] = {0x12, 0x34};
    writer.write<0x5A>(pan);
    writer.constructed<0x6F>([](tlv::writer_builder& fci) {
        fci.write<0x84>("AID");
        fci.write<0x50>("VISA");
    });
});
// Check result once; success contains the exact number of output bytes.
```

`write(tag, value)` accepts a `tlv::tag`. `write<0x9F, 0x02>(value)` uses
individual identifier bytes with static lifetime, preserving leading zero bytes
and platform-independent byte identity. `<0x9F02>` is not a supported shorthand.
`write(element)` accepts a semantic Element, including an already encoded
constructed Value; it does not traverse or validate that Value's children.

Supported Values are `tlv::bytes`, `tlv::value_view`, arrays and contiguous
containers of `tlv::byte` or `uint8_t`, `std::string`, character arrays, and
`std::string_view` from C++17. Byte inputs preserve every byte. Character arrays
omit one trailing NUL and preserve embedded NULs; strings and string views use
their explicit lengths. Raw text pointers are not accepted: use a string view
or a byte span with a known length. No conversion copies or allocates storage.

Numbers and enums require an explicit Value representation. Select a typed
C++ Value codec or field with the desired width and byte order, encode into
caller-owned scratch or use the typed Writer overloads below, and check the
codec result before publishing bytes. The Writer does not infer a codec from a tag or serialize a
host object's memory. The existing `write_value()` convenience for application
codecs uses a temporary vector and is outside this allocation-free interface.

For reusable associations between tags and semantic types, sequential Writers
also support `write<Field>(value)` and `write<Field>(value, scratch)` using
[typed fields and Value codecs](codecs.md#c11-typed-fields-and-value-codecs).
The first form stages Value in an owned vector; the second uses caller-owned
scratch. Both delegate framing to the same Writer and preserve codec errors
separately from Writer errors. Scoped builders retain their byte-input API.

The same typed inputs and byte-tag templates are available on the sequential
`tlv::writer<F>`:

```cpp
tlv::writer<tlv::ber::format> writer(
    tlv::span<tlv::byte>(output.data(), output.size()));
auto first = writer.write<0x50>("VISA");
// Check each result before continuing; writer.size() reports the written prefix.
```

This cursor preserves its existing per-operation results, diagnostics,
`copy_encoded()` and `preserve()` operations. Its `tlv::error` may allocate a
message on failure. The builder and `encode()` instead return
`expected<size_t, writer_failure>`: the error contains the canonical `code` and
`message()` borrows a static description, so failures do not allocate either.
User callbacks and custom containers/Formats remain responsible for their own
allocation behavior.

### Workspace and scoped errors

The short helper uses 1024 scratch bytes and `TLV_TREE_DEFAULT_DEPTH` frames on
the stack. `tlv::ber::encode<512, 8>(output, callback)` selects different fixed
capacities. Insufficient storage returns an error and never grows implicitly.
For explicit caller storage, use:

```cpp
tlv::writer_storage<128, 4> storage;
auto result = tlv::ber::encode(output, storage.view(), callback);
```

`writer_workspace` also accepts separate frame and scratch spans, plus runtime
depth and element-count limits. Each open parent requires one frame; scratch
must fit the largest closed parent Value. Output, workspace and input must be
disjoint. Generic calls use `tlv::encode<F>(output, workspace, callback, format)`
or `tlv::encode(output, format_view, workspace, callback)`; the typed overload
owns a stable Format adapter for the call.

For persistent sequential construction, initialize `tlv::writer_builder` with
an output span, a C++ Format view and workspace, perform `write()` and
`constructed()` operations, then inspect `finish()`. Keep the borrowed Format
descriptor/context and workspace alive and stationary throughout use.

Builder callbacks take `tlv::writer_builder&` and return `void`. The first
failure is retained, later writes are skipped, and later nested callbacks are
not invoked. A failed parent opening skips its callback; a failed child skips
parent closing. Application code can stop writing with `writer.fail(code)`.
Statements in an already running user callback still execute after a write
fails; `status()` can be inspected when application control flow needs it.

`constructed()` explicitly closes a parent after its callback succeeds. An
exception propagates to the caller, marks the builder failed and leaves that
root unpublished. Destruction does not attempt encoding. `size()` exposes only
completed roots; failed output may contain provisional bytes and there is no
whole-buffer rollback. Optional `writer_diagnostic` preserves the C operation's
detail and current output offsets; initialization errors and application
`fail()` do not populate it. Runtime Tag storage must outlive diagnostic
inspection as well as its operation.

All APIs support C++11 with explicitly typed callbacks as above. With C++14
generic lambdas, dependent calls need `writer.template write<0x50>("VISA")`
and `writer.template constructed<0x6F>(callback)`.

### Exact size measurement

The existing `encoded_size(element, format)` measures a complete semantic
Element. For callback construction, use
`tlv::encoded_size<F>(staging, workspace, callback, format)` or the runtime
overload `tlv::encoded_size(staging, format_view, workspace, callback)`.
These operations encode into caller-owned staging storage and return the exact
size on success. Content-dependent Formats receive actual encoded children.
The callback runs once and the staged bytes can be used directly or passed to
`copy_encoded()`. A failed capacity check does not predict the complete final
size; retrying requires a fresh callback invocation and suitable storage.

### Complete C++ example

This example produces the same document as the parsing example, checks its
bytes independently, and is compiled and run by the example test suite:

<!-- example: examples/tlv++/src/write.cpp -->
```cpp
// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

// Builds the same BER document as parse.cpp using scoped, allocation-free writes.
#include "tlv++/builtins/asn1/ber.hpp"
#include <array>
#include <algorithm>
#include <iostream>

// Same bytes as parse.cpp's document.
static const std::array<tlv::byte, 12> expected = {
    tlv::byte(0x6F), tlv::byte(0x0A), tlv::byte(0x84), tlv::byte(0x03),
    tlv::byte(0x41), tlv::byte(0x42), tlv::byte(0x43), tlv::byte(0xA5),
    tlv::byte(0x03), tlv::byte(0x50), tlv::byte(0x01), tlv::byte(0x01)};

int main() {
    std::array<tlv::byte, 12> output{};
    auto result = tlv::ber::encode<12, 2>(output, [](tlv::writer_builder& writer) {
        writer.constructed<0x6F>([](tlv::writer_builder& fci) {
            fci.write<0x84>("ABC");
            fci.constructed<0xA5>([](tlv::writer_builder& proprietary) {
                const uint8_t label[] = {0x01};
                proprietary.write<0x50>(label);
            });
        });
    });
    if (!result) {
        std::cerr << "write error: " << result.error().message() << "\n";
        return 1;
    }

    std::cout << "Wrote " << *result << " bytes\n";
    return *result == expected.size() && std::equal(output.begin(), output.end(), expected.begin())
               ? 0
               : 1;
}
```

## Bounded Tree Writer

`tlv_tree_writer_t` builds nested output through explicit `begin()`,
`write_element()` and `end()` operations. It is iterative and allocation-free,
using a destination buffer, a frame array and a separate scratch buffer supplied
by the caller. Include `tlv/writer/tree.h`; C++ exposes `tlv::tree_writer` in
`tlv++/writer/tree.hpp` with the same storage and operation contracts.

`begin()` requires a Tag classified as constructed by the destination Format.
It retains that borrowed Tag until the matching successful `end()`. Keep Tag
bytes immutable and outside all writable writer storage. `write_element()`
accepts primitive Elements and already-complete constructed Elements; it does
not retain their content or traverse complete subtrees. Schema validation is a
separate operation. `finish()` checks for unmatched `begin()` calls and does not
close them automatically or seal the cursor.

## Storage and unknown parent lengths

Children accumulate in the destination buffer. Closing a parent copies its
complete Value to scratch, then delegates measurement and encoding of the whole
parent to the existing Writer and Format. The input Value never overlaps the
encoder's output. Variable-width length transitions need no patching, reserved
maximum header, or format-specific code in Tree Writer. Formats whose measurement
depends on Value content receive the actual bytes, including for empty Values.

- Destination capacity must accommodate the final encoding.
- Scratch capacity must accommodate the largest Value closed by `end()`.
  A zero-sized workspace supports empty parents and complete-element writes.
- Each open parent needs one frame, including an empty parent. Frame capacity
  and runtime `max_depth` are independent limits.
- Item depths start at zero. `max_depth == 0` permits root Elements and empty
  root parents, but no children. `TLV_TREE_DEFAULT_DEPTH` is a suggested limit,
  not a hard maximum. An empty parent at depth N still requires N+1 frames.
- `max_elements` counts successful `begin()` and `write_element()` calls.
  Writing a complete subtree counts once; `end()` does not increment the count.

All writable storage must be disjoint. Values passed to `write_element()` must
not overlap output. No storage is allocated internally. Nested ancestors can
copy their descendants repeatedly, giving O(bytes * depth) worst-case work
and O(depth) frame storage, in addition to destination and scratch buffers.

## Publication, errors and offsets

`tlv_tree_writer_size()` returns only the completed root prefix. Bytes in an
open root are provisional and can move when ancestors acquire their headers.
Do not treat them as a final wire representation or retain pointers into them.

`begin()` failures leave all state and output unchanged. Failed writes do not
advance or count an Element; encoder errors can change unused output bytes.
Failed `end()` calls preserve the active frames, cursor and all accumulated
output bytes. This includes restoring Value bytes after an encoder has partially
overwritten them. Scratch and unused output bytes may change. A failed parent
remains open; there is no implicit close, discard or allocation. Repeating an
operation under the same conditions yields the same result for deterministic
Format callbacks. This API does not resize or replace storage mid-construction;
insufficient capacity requires restarting with suitably sized caller storage.

The `_diag` operations preserve Format error codes, regions and field offsets.
Offsets are absolute in the **current destination buffer**. For an open subtree
they are not predictions of final positions after ancestor headers are inserted.
A workspace shortage reports `TLV_WRITER_OP_END` with scratch `available` and
`required` byte counts. Successful operations leave diagnostics unchanged.

## Bounded output versus streaming

The current Format contract encodes a complete contiguous Element. Every
writable Format therefore uses bounded construction here, including BER
indefinite and CER; Tree Writer does not expose a streaming sink.

| Wire requirements | What true one-pass output would additionally need |
| --- | --- |
| Definite parent length, unknown at begin | Prior measurement of transformed children and a Format operation that can emit framing separately, or bounded staging as implemented here |
| Header depends on Value content | Sufficient prior content/measurement; a byte count alone may not suffice |
| Terminated/indefinite parent | Header independent of future content, an appendable Value and a separately emit-able trailer; any trailer state must also be bounded |

Indefinite framing alone is not a streaming API capability. The present
descriptor has no separate header/trailer operations, and Tree Writer neither
infers capabilities from Format identity nor bypasses `measure/encode`.
Format policy still applies to complete-element writes: the BER indefinite
preset only encodes constructed elements, while CER selects definite framing
for primitive elements and indefinite framing for constructed elements.

## Reader → transform → Writer

Pull `tlv_tree_reader_next_event()` and pass each successful event directly to
`tlv_tree_writer_write_event()`, optionally modifying node content between them.
BEGIN opens the destination Tag and ignores the original parent Value; ELEMENT
writes primitive content; END encodes the accumulated parent. No depth reconstruction
or final implicit closure is required. `finish()` rejects missing END events.

Writer checks event depth and destination classification. It rejects skipped END
because omitted descendants are not an empty container. Code choosing to copy a
complete subtree with `write_element()` must suppress that subtree's BEGIN and
skipped END rather than write it twice. Query matches alone are not a balanced
structural stream.

Input and output remain separate. In default mode BEGIN borrows its Tag until END.
Use `tlv_tree_writer_set_tag_storage()` with disjoint caller-owned bytes to retain
open Tags independently of a replaceable Reader buffer; exhaustion returns LIMIT.
On Writer failure retain the current event for retry before pulling another one.
NEED_MORE_DATA publishes nothing and does not close scopes. No Document is required;
Tree Reader still requires a complete parent before BEGIN. Format conversion may
reject destination identifiers or content. See the [event contract](../concepts/processing-pipeline.md#canonical-structural-events-402).

## Example

This self-checking example works without optional builtins:

<!-- example: examples/tlv/src/tree_writer.c -->
```c
// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

/* Nested output with caller-owned frames, destination and scratch storage. */
#include "tlv/writer/tree.h"
#include "tlv/formats/fixed.h"
#include <string.h>

static int constructed(const void* context, const tlv_tag_t* tag) {
    (void)context;
    return tag->size == 1 && tag->data[0] >= 0x80;
}

int main(void) {
    const tlv_fixed_format_t config = {.identifier = {1}, .length = {1, TLV_BYTE_ORDER_BIG_ENDIAN}};
    tlv_format_t             format;
    uint8_t                  output[64], scratch[64];
    tlv_tree_writer_frame_t  frames[2];
    tlv_tree_writer_t        writer;
    const uint8_t            value_a[] = {0xAA}, value_b[] = {0xBB};
    /* Borrowed container tags must remain alive until their matching end(). */
    const uint8_t       outer[] = {0xE1}, inner[] = {0xE2};
    const tlv_element_t a = {TLV_TAG(0x01), {value_a, sizeof(value_a)}};
    const tlv_element_t b = {TLV_TAG(0x02), {value_b, sizeof(value_b)}};
    const uint8_t       expected[] = {0xE1, 8, 1, 1, 0xAA, 0xE2, 3, 2, 1, 0xBB};
    if (tlv_fixed_format_init(&format, &config) != TLV_OK) return 1;
    format.is_constructed = constructed;
    if (tlv_tree_writer_init(&writer, output, sizeof(output), &format, frames, 2, scratch,
                             sizeof(scratch), TLV_TREE_DEFAULT_DEPTH, SIZE_MAX) != TLV_OK)
        return 1;
    if (tlv_tree_writer_begin(&writer, tlv_tag(outer, sizeof(outer))) != TLV_OK) return 1;
    if (tlv_tree_writer_write_element(&writer, &a) != TLV_OK) return 1;
    if (tlv_tree_writer_begin(&writer, tlv_tag(inner, sizeof(inner))) != TLV_OK) return 1;
    if (tlv_tree_writer_write_element(&writer, &b) != TLV_OK) return 1;
    if (tlv_tree_writer_end(&writer) != TLV_OK) return 1;
    if (tlv_tree_writer_size(&writer) != 0) return 1; /* Outer root is still open. */
    if (tlv_tree_writer_end(&writer) != TLV_OK) return 1;
    if (tlv_tree_writer_finish(&writer) != TLV_OK) return 1;
    return tlv_tree_writer_size(&writer) == sizeof(expected) &&
                   memcmp(output, expected, sizeof(expected)) == 0
               ? 0
               : 1;
}
```

## Measuring an owned tree

`tlv_tree_writer_measure_events()` consumes a balanced structural event callback.
Document and other tree producers supply the same BEGIN/ELEMENT/END contract.
The node-only `tlv_tree_writer_measure()` callback remains an adapter that supplies
missing closures to the same event consumer. Tree Writer has no Document dependency.
The event helper requires explicit final ENDs; NEED_MORE_DATA aborts this one-shot
operation, so use a persistent Writer for resumable transformations.

The caller supplies `tlv_tree_writer_workspace_t`: frames, staging output and a
separate shared scratch buffer. Measurement stages the encoding so that every
Format receives readable child bytes, including Formats whose header or trailer
depends on Value content. On success, `size` is exact and `workspace.data` contains
the complete encoding; `tlv_writer_copy_encoded()` can reuse it.

If storage is too small, `required_data` and/or `required_scratch` identify the
next required capacities. The caller may grow storage and restart from a fresh
source. These fields are reset for every call; a callback returning
`TLV_ERR_BUFFER_TOO_SHORT` does not set them and must not trigger a storage retry.
Frame exhaustion and configured traversal limits return `TLV_ERR_LIMIT`.

This operation never allocates or recurses. It can call both Format measure and
encode callbacks, and failures may modify workspace bytes. Source Tags remain
borrowed through completion. Formats and sources must be deterministic when
replayed; staging requires space for the complete output, plus shared scratch
and the structural stack.

## Next step

Next: [Document](document.md) for editing, or [memory contracts](memory.md) for buffer lifetimes.
