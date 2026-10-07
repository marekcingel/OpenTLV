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
| Owned data | `document`, `node`, `const_node`, `document_builder` | RAII ownership, checked mutable/read-only handles, edits and regenerated encoding |
| Runtime configuration | `runtime_fixed_format`, `byte_order`, `element_order`, `length_scope` | Stable immutable owner; views borrow it and cannot be obtained from temporaries |
| Schema | `schema_storage<N>`, `schema`, `validation_report<N>` | Caller-owned bounded tables and reports; validation delegates to C without allocation |
| Runtime Values | `dynamic_codec`, `emv::dictionary` | Explicit representation contracts and immutable metadata; no tag lookup in Value conversion |
| Selection | `query`, `query_matcher`, Document Query | C grammar and matching over borrowed or owned traversal |
| Typed Values | `field`, Value codecs, typed decode/find/write | Explicit Tag/codec association; separate codec and framing errors |
| Standards | `ber`, `der`, `cer`, `asn1`, `emv`, `bluetooth`, `lldp`, `dhcp`, `nfc` | Domain conveniences under enabled native components |

Generic concepts stay public under `tlv`. `tlv::detail` contains descriptor
access, callback trampolines and adaptation; it has no source-compatibility
guarantee and is not an application API. Native callback tables, ABI parity fixtures and externally supplied C descriptors
are intentional interoperability. Schema rules, runtime Format configuration,
Codec selection and Query configuration have public C++ representations.

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
copied data and allocates one shared lifetime record. Observing or copying Node
handles does not allocate. Owning codec
results, vector conveniences and application callbacks may also
allocate. Successful borrowed/fixed-size codec operations retain their C
allocation behavior.

Cursor operations return `expected` with `tlv::error`; copying the error and its
borrowed static message does not allocate. `status()` exposes `tlv::errc`, with
distinct `end_of_input` and `need_more_data` outcomes. Located errors expose
`has_offset()`, `offset()` and `stage()`. Custom error descriptions are borrowed
and must outlive the errors. Format customization uses `format_failure` and scoped construction
uses `writer_failure`, preserving codes/detail without allocating error strings.
Typed field failures distinguish invalid handles, Tag mismatch, constructed
Values, codec errors and Writer errors. Ranges use their documented failure
channel; explicit pulls give control over resumable statuses.
`errc::need_more_data` is a pause and `errc::end_of_input` is final exhaustion.
C++11 remains the baseline; generic lambdas require C++14.

### Exception policy

The C++ facade requires compiler exception support. Operational failures from
explicit cursor, validation and conversion operations use `expected`. Reader
and Query range iteration throw on failure, including incomplete non-final input;
malformed input never silently becomes a successful end iterator. Use explicit
pulls when an application needs to resume input or handle errors without throwing.
Checked access/precondition violations use the documented standard exceptions;
allocations in owning operations can propagate `std::bad_alloc`. Callbacks retain
their documented exception contracts. No second exception-disabled implementation
of the C++ facade is provided. The canonical C engine remains available in builds
that disable C++ exceptions.

### Node validity and allocation costs

Each Node handle stores a pointer, identity and cached Document revision and
borrows the owner's lifetime record. Unchanged-document access is constant-time.
After a mutation, the first access through each retained handle checks membership
without dereferencing a possibly freed pointer; it also compares identity to
reject allocator address reuse. This check scans the current Document in O(nodes).
Subsequent accesses at the same revision are constant-time. Copies validate
independently; moving the owning Document preserves handles, and owner destruction
invalidates them. A `const document` returns `const_node`, including through Query
selection, so child traversal cannot recover mutation.

The `test-document-handle-smoke` C++11 target checks zero C++ allocations during
seven traversals of 10,000 nodes, handle invalidation, short typed writes and
Reader failure reporting. Pass an extra argument to print raw repetitions as
`repeat,observed_nodes,allocations,microseconds`. Local measurements before replacing
the map/token tracker observed 20,007 allocations on the first traversal and 10,000
on subsequent traversals; the identity/revision handles observed zero in all seven.
This is an allocation result for that workload, not a general timing guarantee.
The owning C Document still allocates its tree. Typed Writer convenience operations
use 64 bytes of stack scratch for short encoded values, then a vector for larger
values; caller-supplied scratch avoids this fallback.

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
`tlv::native::descriptor`. Document and Node interoperability uses
`tlv::native::handle()`, preserving constness for const Documents and `const_node`.
Native Document edits participate in revision/identity checks when retained
C++ handles are accessed. Never free the borrowed owner or retain raw pointers
after its destruction. Query path descriptors use `native::descriptor(query)`; compiled programs and
mutable continuations use `native::handle()`. Temporary owning objects cannot
export retained pointers.

The [runtime Fixed example](../../examples/tlv++/src/formats/fixed_format_runtime.cpp)
demonstrates `runtime_fixed_format` with caller-owned configuration. A copied
owner rebinds its descriptor to its own configuration; existing views continue
to borrow the original owner. Reader/Writer construction from a C descriptor now
requires explicit `native::borrow_format()`. See the
[Format contract](format-contract.md), [semantic views](core-types.md#c-semantic-views)
and [memory guide](../guides/memory.md) for borrowing and preservation.

## Error and traversal contract

`tlv::to_error(result.error())` projects ordinary and specialized errors into
one allocation-free diagnostic: `status()`, `message()`, `severity()`, `stage()`,
optional `offset()`/`tag()`, enclosing `ancestor(i)` identifiers, and optional
`expected()`/`actual()` descriptions. Check `has_offset()` and `has_tag()` before
using location metadata. Ancestor descriptors are copied into bounded inline
storage; their identifier bytes and diagnostic strings remain borrowed.
Unavailable context stays absent rather than inventing an offset or constraint.
Keep the original `typed_error`, `writer_failure`, `format_failure`,
`validation_issue` or `query_failure` for subsystem-specific numeric details.
Schema reports expose bounds, occurrence counts, form and alternative-group
information through C++ accessors. Legacy diagnostic aliases remain useful for
advanced diagnostic collection; common consumers need no native constants.

| Operation | Completion | Failure and continuation |
| --- | --- | --- |
| Reader / Tree Reader `next()` | Element or event | `end_of_input` is final exhaustion; `need_more_data` preserves resumable state |
| Reader / Query range | End iterator after final exhaustion | Throws its documented parse/query exception, never silently drops malformed input |
| Visitor | `visit_control::next` continues; `stop` succeeds | `error` reports a visitor failure; callback exceptions follow the documented callback contract |
| Writer | Successful result advances committed cursor | Failed writes preserve cursor; a callback may have modified uncommitted destination bytes |
| Schema report | Total violation count, including omitted entries | Wire/argument failure is an error; `truncated()` distinguishes bounded report storage |
| Document parse | Owning tree | Operational status and available absolute offset; allocation exceptions can propagate |
| Query pull | Match or scalar | Original limit, conversion, source or execution detail; reset requirements remain canonical |

## Customization and ownership

| Object | Owns | Borrows and invalidation |
| --- | --- | --- |
| `runtime_fixed_format` | Configuration and descriptor | Views borrow the named owner; copies rebind to independent configuration |
| `format_adapter<F>` / typed cursor | C++ Format state | Input and retained source views depend on its stable lifetime |
| `schema_storage<N,G>` | Bounded rule/group tables | Identifier bytes, names and child schemas; no copy/move or temporary views |
| `codec_owner<C>` | Stateful codec and callback descriptor | Runtime views borrow the stationary owner; decoded borrowed Values depend on input |
| `query_options` | Declaration table | Names and optional environment during compilation; finish mutation before borrowing |
| `query_environment` | Provider table | Format and provider contexts through all dependent programs/executions |
| `validation_report<N>` / copied issue | Diagnostic records and ancestor descriptors | Identifier bytes and field names from input, Format or Schema |
| `document` / `node` | Tree / checked non-owning handle | Mutation changes revision; destruction invalidates handles; const traversal stays read-only |

Custom Format methods use exact C++ return types and `const noexcept` callbacks;
the existing positive and negative compile checks enforce this contract. Typed
codecs return `expected<T, codec_errc>` and may propagate their own allocation
exceptions. `codec_owner<C>` additionally requires const, nonthrowing decode and
encode methods and a nothrow move-assignable representation because it invokes
those methods through the canonical C callback ABI. Non-default-constructible
codec state can be constructed in place. Codec encode with `nullptr, 0` measures
and validates; runtime decoding must use the exact documented representation.

## Coverage audit and enforcement (#440)

The closure boundary is complete supported consumer workflows, not a one-to-one
copy of every C helper. All ordinary examples and CLI sources pass
`scripts/check_cxx_boundary.py`; the CI job also runs the scanner's regression
tests. The scanner rejects native headers, C identifiers/constants and
`tlv::detail`/`tlv::native` usage. The generated `tlv/config.h` capability switches
are allowed. Native parity and malformed-native-input fixtures are excluded by
exact path with a reason in the script; mixed historical parity files are not
claimed as pure public examples. New public acceptance tests belong in
`tests/unit/public_api_test.cpp` and are checked. The explicit interoperability
example remains excluded. Run `--report build/cxx-boundary.json` for the audit.

| Issue | Implemented contract and evidence |
| --- | --- |
| #451 | Public coverage table, CLI migration, public acceptance tests and explicit native exclusions |
| #452 | Common error projection, borrowed messages, located Reader/Writer/Document errors and Schema reports |
| #453 | Bounded declarative Schema rules/groups, child schemas and validation/report APIs |
| #454 | Runtime Fixed owner, configuration validation, independent copying and CLI selection |
| #455 | Scoped status, codec, visitor, byte/order, Schema and Query enums plus domain constants |
| #456 | Runtime Codec view, stateful owner and exact representation/error contracts |
| #457 | Builtin metadata audit below and runtime EMV dictionary/Bluetooth metadata APIs |
| #458 | Lifetime table, rejected temporary borrows and copied-owner/invalidated-handle tests |
| #459 | Identity/revision Node validation and reproducible zero-allocation traversal checks |
| #460 | Allocation-free returned errors and short typed writes; explicit scratch alternatives |
| #461 | Completion/pause/failure table and failed-initialization/range regression tests |
| #462 | C++ Format overloads and explicit native imports, descriptors and handles |
| #463 | Exact Format/Codec contracts, positive/negative compile checks and stateful Codec test |
| #464 | Read-only Document traversal, selection and semantic diff handles |
| #465 | One exception-enabled C++ contract with a negative exception-disabled compile check |
| #466 | Public runtime-format, validation, typed-field and traversal examples |
| #467 | Public C++ CLI parsing, writing, metadata, validation, decoding, Query and diagnostics |
| #468 | Architectural scanner, explicit exclusions, scanner tests and CI integration |

### Builtin metadata audit

| Domain | Legitimate public C++ metadata and composition |
| --- | --- |
| EMV | With Codec and Schema enabled, `emv::dictionary` entries expose context-dependent name/symbol, kind, Codec, length bounds/step and validation; child contexts and structural Schema stay in the domain |
| ASN.1 | Typed representations, identifier limits, BER identifier reading, DER limits/validation and explicit ASN.1 Query providers; no duplicate generic registry |
| Bluetooth | AD type/company names, structural Schema, container validation and typed UUID access; registry data remains canonical |
| LLDP | Framing, typed chassis/port/capability representations and separate container validation; no additional runtime dictionary is required by supported consumers |
| DHCP | Framing, typed Values and options-container validation; `dhcp::options_rules` selects End and tail policy without native tables |
| NFC | Framing and semantic element representation; no separate runtime dictionary/Schema surface is required by current supported use cases |
| Future domains | Add reusable Schema/Codec/definition concepts when real consumer workflows require them; protocol policy stays outside generic core |

### Source migration

Use `error.message()` instead of the previous owning string field, and scoped
`errc`/`codec_errc` values instead of C constants in C++ callbacks. Custom typed
codecs must update their `expected` error type to `codec_errc`. Use
`fixed_format<...>::view()` or a preset object, and `runtime_fixed_format` for
runtime policies. Raw Format overloads become `native::borrow_format(raw)`.
Native typed codec adapters move to `native::codec_adapter`; raw Schema
validation lives under `native::validate`. Query compiler settings and runtime
capabilities are obtained from named C++ owners; existing C tables can be imported
with `native::borrow_query_settings` and `native::borrow_query_capabilities`.
These are C++ source changes; the canonical C ABI is unchanged by this work.
