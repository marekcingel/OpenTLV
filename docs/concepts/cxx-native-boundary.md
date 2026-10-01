# C++ public and native boundary

The tlv++ redesign ([#440](https://github.com/marekcingel/OpenTLV/issues/440))
builds an idiomatic C++ API on the canonical C engine. Generic concepts stay
public under `tlv`; C representation access and callback adaptation belong in
`tlv::detail`. Detail headers and symbols are implementation details without
a source-compatibility guarantee.

## Namespace direction

Standards use namespaces such as `tlv::ber`, following the style of protocol
types in Boost.Asio. The intended Reader spelling is `tlv::ber::reader`,
backed by the same generic `tlv::reader<tlv::ber::format>` that accepts an
application Format. These **Reader spellings are planned**, not implemented
by the initial boundary change. A namespace cannot also be the callable
`tlv::ber(data)` used in early issue sketches.

The initial implementation provides `tlv::ber::format`, usable with the
existing generic cursor:

```cpp
tlv::reader reader(data, tlv::ber::format{});
auto element = reader.next();
```

`data` is a borrowed `tlv::bytes` view. Keep its storage alive while using the
reader and returned elements. BER still uses the generic C Reader and Format
operations. Other built-in namespaces, iterable readers, typed fields and
builders follow in their respective issues. C++11 remains the baseline;
examples using generic lambdas need a separate C++14-or-newer spelling.

## Format execution view

`tlv::format` is a small, copyable, non-owning execution view. It exposes
capability queries and can be passed to Format operations, Reader, Writer,
Tree Reader/Writer, tree measurement, Query, Schema and Document operations.
`tlv::fixed_format<...>::view()` supplies a C++ view of its program-lifetime
descriptor. The existing `format()` accessor remains available during migration.

Copying a view performs no allocation and retains the original descriptor
identity. There is no implicit conversion to or from `tlv_format_t`.
Readability and writability describe available callbacks, not input validity;
the engine still validates operations and reports its original errors.

This view is the execution boundary, not a replacement for the C++ Format
customization contract in [#432](https://github.com/marekcingel/OpenTLV/issues/432).
That contract must allow user-defined Formats without manually constructing
C descriptors. Built-ins must use the same generic contract.

## Explicit interoperability and lifetime

Include `<tlv++/native.hpp>` explicitly to mix C and C++ APIs:

```cpp
auto format = tlv::native::borrow_format(native_descriptor);
tlv::reader reader(data, format);
const auto& descriptor = tlv::native::descriptor(format);
```

`native_descriptor` must be a named, live `tlv_format_t`. Import rejects both
mutable and const temporary descriptors. Export returns an immutable reference
to the original descriptor. It does not copy configuration or transfer ownership.

The C++ view may be temporary: cursors and decoded source metadata reference
the original descriptor, not the view object. The descriptor, its context and
format-owned identifier storage must remain alive and unchanged for all
dependent operations and retained views. The compiler cannot prevent a caller
from destroying a named descriptor too early.

`document_format` copies the descriptor when constructed from a view, just as
it does for its existing native constructor. Document parsing/creation copies
that descriptor into stable owned storage; the context remains borrowed.
Documents produced by `document_builder` retain their existing dependency on
the source Reader's descriptor. No additional allocation is introduced into
Reader/Writer success paths; existing error strings may allocate.

The compiled [runtime Fixed example](../../examples/tlv++/src/formats/fixed_format_runtime.cpp)
demonstrates explicit import with caller-owned configuration and buffers.
The C/C++ descriptor semantics are described in the
[Format contract](format-contract.md) and [memory guide](../guides/memory.md).

## Public-header audit and migration order

The initial [#430](https://github.com/marekcingel/OpenTLV/issues/430) boundary
is additive. Existing native overloads and representations remain transitional
building blocks; they are not the final idiomatic surface. The new path uses
`detail::format_access` for descriptors, while Reader, Tree Reader and Query
buffer visitors use shared `detail` trampolines. Other bridges migrate with
their owning abstractions rather than moving processing semantics out of C.

| Current public representation | Next migration owner |
| --- | --- |
| `tag`, `value_view`, `element_view`, decoded/tree semantic payloads | #431 implemented; `source`/`encoding` aliases migrate with #432 Format operations |
| Native Format overloads, `fixed_format` byte-order parameter and `format()`, built-in descriptor getters | #432 customization and #438 standard namespaces |
| `reader_diagnostic`, `input_mode` cursor operations, native visitor return codes, Tree Reader frames/items/events | #433 Reader and iteration |
| `writer_diagnostic`, `tlv_source_t` preservation, Tree Writer frames/workspace/events and source callbacks | #434 Writer and builders |
| `document_format.format`, `node::c_node()`, `document::c_document()`, builder options and C deleters/state | #435 Document ownership and traversal |
| Native structure-codec descriptors, `is_tlv_codec` tag requirements, callback registration and `any` values | #436 typed fields/codecs |
| `query::c_query()`, native matching diagnostics and visitor adapters | #437 Query integration |
| Schema rules/diagnostics, diagnostic paths and protocol container/validation options | Follow-up facade migration alongside their owning generic/domain APIs |
| Examples using native macros, field access and byte conversions | #439 compiled ergonomics examples |

Existing `c_node()`, `c_document()` and `c_query()` accessors already make
interop explicit, but their final placement will be reviewed during migration.
`error::code` and `error::from_c()` also remain native-facing until the error
surface migrates with semantic and cursor APIs. Source compatibility is retained
in this first step; subsequent changes must state their migration requirements.

New facade code should use public C++ types at call sites and `tlv::detail`
for implementation bridging. Public interoperability belongs in `tlv::native`,
not in an implicit conversion. Protocol policy remains in the standard, and
all wire processing, traversal, validation and Query semantics stay in C.

## Semantic interoperability

[#431](https://github.com/marekcingel/OpenTLV/issues/431) replaces C Tag and Element
aliases with `tlv::tag`, `tlv::value_view` and `tlv::element_view`. Ordinary code
uses `element.tag()`, `element.value()` and explicit `as_bytes()` spans. Definition
entries, Query steps, Document accessors and codec tag requirements also use the
strong Tag type. Definition registries still borrow their tables and names and
allocate nothing; registered codec identifiers continue to be copied by the registry.

Native semantic imports are explicit and checked:

```cpp
auto result = tlv::native::borrow_element(native_element);
if (!result) return; // Invalid pointer or non-native-addressable Value size.
auto descriptor = tlv::native::descriptor(*result);
```

The native descriptor itself is copied; its Tag and Value bytes remain borrowed.
Unlike a Format descriptor, a temporary semantic descriptor can be imported safely
when its underlying byte storage remains alive. See [semantic views](core-types.md#c-semantic-views)
for the borrowed lifetime and absent/empty Tag rules.
