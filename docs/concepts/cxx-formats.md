# C++ Format customization

A C++ Format defines wire framing through `tlv::format_traits<F>`. It uses
the same C Reader, Writer and higher-level engines as the built-in Formats.
An application implements operations in C++, without constructing a
`tlv_format_t`, inheriting a base class, or using virtual dispatch.

Include `<tlv++/format.hpp>` for the contract, or `<tlv++/tlv.hpp>` for the
complete configured facade. C++11 remains supported.

## Operations

The default traits recognize these `const noexcept` members:

```cpp
struct my_format {
    tlv::expected<tlv::decoded, tlv::format_failure>
    decode(tlv::bytes input) const noexcept;

    tlv::expected<tlv::encoding, tlv::format_failure>
    measure(const tlv::measure_request& input) const noexcept;

    tlv::expected<size_t, tlv::format_failure>
    encode(const tlv::element_view& input, tlv::span<tlv::byte> output) const noexcept;

    bool is_constructed(tlv::tag identifier) const noexcept;
};
```

These declarations illustrate the signatures; an application supplies their
implementations. A complete compiled example is
[custom_format.cpp](../../examples/tlv++/src/formats/custom_format.cpp).

| Operation | Requirement and result |
|---|---|
| `decode` | Required for reading. Returns canonical Element and complete source ranges. |
| `measure` | Required together with `encode` for writing. Returns exact logical Header/Value/Trailer/total sizes. |
| `encode` | Writes a complete element, returning the native byte count. |
| `is_constructed` | Optional. Identifies Values containing elements of this same Format. Without it, Values are opaque. |

At least one capability group must exist. `format_capabilities<F>` exposes
`readable`, `writable`, `classified`, and `valid`. Invalid operation return types,
non-const or throwing operations, and incomplete write capability groups produce
compile-time diagnostics when adapted. Reader and Writer additionally reject
Formats lacking their required capability.

To adapt an existing type, specialize `tlv::format_traits<F>`. Provide the same
operation names as static functions, taking `const F&` as the first argument
followed by the arguments above. Omit unsupported capability groups. The trait
operations themselves must be `noexcept` and return the exact result types.

## Generic consumers and built-ins

```cpp
tlv::reader<my_format> reader(data);
tlv::writer<my_format> writer(output.data(), output.size());

tlv::reader<tlv::ber::format> ber_reader(data);
```

These cursors own default-constructed immutable Format configuration. Supply an
explicit configuration as the next argument to copy or move it into the cursor.
Move-only Formats are supported; construction is separate from allocation-free
processing. Format operations must not allocate, retain operation buffers, or
throw exceptions.

The configured built-in types are `tlv::ber::format`, `tlv::der::format`,
`tlv::cer::format`, `tlv::emv::format`, `tlv::bluetooth::format`,
`tlv::lldp::format`, `tlv::dhcp::format`, and `tlv::nfc::format`.
`tlv::fixed_format<TagWidth, LengthWidth, Order>` also satisfies the contract.
Built-ins delegate wire operations to their existing C implementations.
Optional built-ins remain governed by their existing CMake component options.

For consumers accepting a runtime execution view, own one shared adapter:

```cpp
tlv::format_adapter<my_format> format;
tlv::reader<> reader(data, format.view());
tlv::tree_reader tree(data, format.view(), frames, max_depth, max_elements);
tlv::document_format options(format.view());
auto document = tlv::document::parse(data, options);
```

The same view works with Tree Writer, tree measurement, Query, and destination
Format selection when encoding a Document. These consumers retain their existing
storage, allocation and traversal contracts. They do not implement another parser.

## Measurement and diagnostics

`measure_request` separates a logical `value_size` (`tlv_size_t`, always 64-bit)
from optional readable `content`. Its `identifier` retains byte identity.
When content is available it contains exactly `value_size` bytes. A null/empty
content span with nonzero `value_size` requests measurement without Value storage.
Such requests can exceed `SIZE_MAX`; use checked logical arithmetic and defer
native-size conversion until actual buffer access. Content-dependent Formats
must reject a request lacking the bytes they need.

```cpp
auto sizes = tlv::measure(format.view(), tlv::measure_request{
    tlv::tag_bytes<0x01>(), UINT64_C(4294967296), tlv::bytes{}});
```

Failures use allocation-free `format_failure`, containing the original result
code and optional `tlv_format_error_t` wire detail. Return
`tlv::unexpected<tlv::format_failure>(...)`; partial offsets and ranges are
relative to the current element. Incomplete input uses
`TLV_ERR_BUFFER_TOO_SHORT`; malformed input uses its specific error. The Reader
engine translates truncation into `TLV_NEED_MORE_DATA` for incremental input and
preserves its cursor. Generic C++ operation errors retain their existing message
allocation behavior.

## Shared invariants and lifetime

The [canonical Format contract](format-contract.md) applies unchanged. Decode
must publish bounded Header/Value/Trailer ranges that partition the complete
element. Value borrows its declared input range. Tag normally borrows its source
range; transformed identifiers may use immutable Format storage with the existing
`TLV_TAG_BINDING_FORMAT` binding. Never return callback-local or mutable scratch
identifier bytes. The C engine validates these results before publication.

Measurement must preserve the logical Value size and checked framing sum.
Successful encoding must write exactly the measured size; for bidirectional
Formats it must decode to the same Tag and Value. Encoding regenerates framing;
`tlv::preserve` remains the separate explicit byte-preservation operation.
Classification describes nesting, without introducing Schema or Value semantics.

An adapter owns F but borrows any external storage referenced by F. It cannot be
copied or moved: the C engine and decoded sources retain its descriptor/context
addresses. Typed cursors have the same restriction. Keep the adapter or typed
cursor, input, and Format-supplied identifier storage alive while retained results
are used. A `view()` may be temporary; destroying it does not destroy the adapter.
Documents retain their documented descriptor/context dependencies even when
their input bytes are owned.

## Source migration

Reader and Writer are now templates. Existing runtime-Format code uses
`tlv::reader<>` and `tlv::writer<>`, including in function parameter types.
Their existing C++ view and transitional native-descriptor constructors remain
available. `write_value` accepts a Writer with any Format parameter. The public
C API, ABI and serialized behavior of existing Formats are unchanged.
