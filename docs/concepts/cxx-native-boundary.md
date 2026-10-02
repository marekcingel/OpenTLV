# C++ public and native boundary

`tlv++` is an idiomatic C++11 API over the canonical C engine. It is
header-only and links to `tlv`; all wire processing, traversal, Query and
Document operations delegate to C. The
[architecture overview](architecture.md#conceptual-model) owns the shared model;
exact declarations belong in the [C++ reference](../reference/cxx-api.md).

## Public facade

| Responsibility | Public C++ API | Contract |
| --- | --- | --- |
| Identifier and content | `tag`, `value_view`, `element_view`, `decoded` | Borrowed bytes; Tag is byte identity |
| Format | `format`, `format_traits<F>`, `format_adapter<F>` | Non-owning execution view or owned immutable configuration adapted to C |
| Sequential reading | `reader<F>`, `parse<F>`, built-in `parse` | Explicit pulls or ranges over complete borrowed Elements |
| Nested reading | `tree_reader`, items, events and `visit` | Caller frames, limits, subtree skip and resumable windows |
| Writing | `writer<F>`, `tree_writer`, `writer_builder`, built-in `encode` | Caller output and explicit scratch; staged constructed parents |
| Owned data | `document`, `node`, `document_builder` | RAII ownership, checked handles, edits and regenerated encoding |
| Selection | `query`, `query_matcher`, Document Query | C grammar and matching over borrowed or owned traversal |
| Typed Values | `field`, Value codecs, typed decode/find/write | Explicit Tag/codec association; separate codec and framing errors |
| Standards | `ber`, `der`, `cer`, `asn1`, `emv`, `bluetooth`, `lldp`, `dhcp`, `nfc` | Domain conveniences under enabled native components |

Generic concepts stay public under `tlv`. `tlv::detail` contains descriptor
access, callback trampolines and adaptation; it has no source-compatibility
guarantee and is not an application API. Advanced APIs may still accept C
descriptions such as Schema rules or native Structure Codec descriptors.

Built-in framing types work with `tlv::reader<tlv::ber::format>` and
`tlv::writer<tlv::ber::format>`; `tlv::ber::parse(data)` supplies a range.
Protocol-specific Reader aliases remain unimplemented; the typed cursor and
parse helper are the current API. See [Format customization](cxx-formats.md),
[built-in standards](cxx-builtins.md), [compiled examples](../guides/cxx-examples.md)
and [typed fields](../guides/codecs.md#c11-typed-fields-and-value-codecs).

## Ownership, allocation and errors

Semantic views borrow Tag/Value storage; source metadata can also depend on the
Format descriptor and context. Keep them alive and unchanged while retained
results are used. Copying a `format` execution view allocates nothing and does
not extend those lifetimes. Typed cursors own their Format configuration;
higher-level consumers can share a named `format_adapter`. Views must not
outlive the cursor/adapter that supplies their descriptor.

Sequential Writer uses caller output. Tree Writer and scoped Builder stage
constructed content in bounded scratch without implicit growth. Document owns
copied data and allocates, and C++ handle tracking can allocate. Owning codec
results, vector conveniences, error strings and application callbacks may also
allocate. Successful borrowed/fixed-size codec operations retain their C
allocation behavior.

Cursor operations return `expected` with `tlv::error`; a failure message may
allocate. Format customization uses `format_failure` and scoped construction
uses `writer_failure`, preserving codes/detail without allocating error strings.
Typed field failures distinguish invalid handles, Tag mismatch, constructed
Values, codec errors and Writer errors. Ranges use their documented failure
channel; explicit pulls give control over resumable statuses.
`TLV_NEED_MORE_DATA` is a pause and `TLV_ERR_END_OF_BUFFER` is final exhaustion.
C++11 remains the baseline; generic lambdas require C++14.

## Explicit interoperability and lifetime

Include `<tlv++/native.hpp>` explicitly to mix C and C++ APIs:

```cpp
auto format = tlv::native::borrow_format(native_descriptor);
tlv::reader<> reader(data, format);
const auto& descriptor = tlv::native::descriptor(format);
```

Import requires a named, live `tlv_format_t`, rejecting mutable and const
temporaries. Export returns an immutable reference to the original descriptor.
It neither copies configuration nor transfers ownership. The descriptor,
context and Format-owned identifier storage must outlive dependent operations
and retained views, even when the C++ view itself was temporary.

`document_format` and Document creation copy the descriptor into stable storage;
the context remains borrowed. Builder-produced Documents retain the source
Reader's descriptor dependency. Copying a descriptor does not copy its context.

Semantic imports use checked `tlv::native::borrow_element`; the descriptor is
copied but its bytes stay borrowed. Export is explicit through
`tlv::native::descriptor`. Existing `c_node()`, `c_document()` and `c_query()`
accessors are native escape hatches. Native Document mutation bypasses C++
handle tracking; follow their warnings and prefer public mutation APIs.

The [runtime Fixed example](../../examples/tlv++/src/formats/fixed_format_runtime.cpp)
demonstrates native import with caller-owned configuration. See the
[Format contract](format-contract.md), [semantic views](core-types.md#c-semantic-views)
and [memory guide](../guides/memory.md) for borrowing and preservation.
