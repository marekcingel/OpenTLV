# Common conceptual model for language bindings

OpenTLV ships a canonical C execution engine, the header-only idiomatic
`tlv++` C++ API, and official experimental Rust, Python, Lua and Go bindings.
All use the public C API as their interoperability boundary. WebAssembly is a
narrow tooling embedding over the same engine. The
[architecture overview](architecture.md#conceptual-model) defines the concepts;
this page is the canonical cross-language capability reference.

This page is the design contract every official binding follows: the primary
concepts below stay recognizable in every binding's public API, even where
syntax and idiom differ.

> Bindings should preserve the OpenTLV conceptual model while adapting its
> ergonomics to the target language.

## The C API is the binding boundary

```text
                    OpenTLV C API
                         |
    +----------+---------+---------+----------+----------+
    |          |         |         |          |          |
   C++       Rust        Go      Python      Lua        ...
    |          |         |         |          |          |
idiomatic  idiomatic  idiomatic  idiomatic  idiomatic  idiomatic
   C++       Rust        Go       Python      Lua    <language>
```

All five language APIs expose Format, Element, Reader, Writer and owned
Document processing. Their higher-level coverage differs as recorded below;
Go includes Document Query and generic Value codecs, and Lua includes borrowed
Query and checked Document Nodes. The trailing `...` stands for future bindings.

The public OpenTLV C API (see the [C API reference](../reference/c-api.md)) is
the single language boundary every binding wraps. A binding calls into the C
library directly for parsing, encoding, validation and codec work instead of
reimplementing it, and it does not depend on another language's binding: the
Rust crate does not sit on top of the C++ wrapper, and a future binding would
not sit on top of Rust either. This keeps behavior identical across languages,
since one C implementation backs every one of them, and lets each binding be
built and shipped independently of the others. `tlv++` differs only in build
shape, not in boundary: its facade is header-only, compiles against the public C
headers and links the C library, without a separately compiled C++ facade library.
It still wraps only the public C API. See [relationship to the C
API](../guides/rust.md#relationship-to-the-c-api) for how the Rust crate holds
to this in practice.

## Capability parity through the public facade

The [pipeline audit](processing-pipeline.md) describes selection of an already
published subtree: C++ `document_builder::current_subtree(reader)`, Rust
`DocumentBuilder::current_subtree` and Python `current_subtree=True` avoid pulling
the selected root a second time.

Every supported language binding must expose the complete capability set of
the public C API through its public, idiomatic language facade. Access through
raw FFI alone does not satisfy capability parity. Users must not need to bypass
the facade to access advanced capabilities. Raw FFI may remain an internal
implementation detail; exposing it publicly is not required.

The call boundary is:

```text
Application
    |
Public idiomatic language facade
    |
Internal binding / FFI
    |
Public C API and canonical C engine
```

These are responsibilities, not a requirement for separate packages. A native
extension can implement the facade directly, and C++ can call C directly from
its headers.

The facade adapts calling conventions, ownership, lifetimes, iteration and
error handling. Parsing, tree traversal, Query semantics, validation, value
codecs and wire encoding must delegate to the canonical C engine. Bindings
must not implement independent versions of those processing semantics.

Parity covers single-element and sequential Readers and Writers, Tree Reader,
incremental/resumable input, Reader and Writer diagnostics, source offsets and
source information, Reader resource limits, subtree control, Visitor processing,
Tree Writer, measurement, exact encoded copy and preservation, Query, Schema,
Codec, Definition, Format, Layout and Document. It includes configuration and
extension capabilities exposed by C, not just access to builtin presets.
Compare bindings against the same enabled C components; a disabled optional
component is distinct from an unimplemented binding capability.

Convenience defaults and iterators may simplify ordinary use, but advanced
operations must remain available through the facade. In particular, resumable
reading must preserve the distinction between an element, a request for more
input, final end of input and an error. An iterator must not make a resumable
reader permanently exhausted merely because it needs more input.

Preserve zero-copy access and borrowed lifetimes where the language supports
them directly. Managed representations must keep backing storage alive or use
documented copies, and must prevent access through invalidated native handles.
Document intentional language-specific ownership and error-handling differences
without treating missing functionality as an ergonomic difference.

Capability tracking must identify the corresponding C operations, the public
facade API and parity tests where practical. An FFI declaration without a public
facade remains a gap. Tests should compare observable C semantics, including
results, diagnostics, offsets, limits, incremental continuation and encoded
bytes. The current coverage below is an implementation snapshot, not a claim
that full parity has already been achieved. This contract is the long-term
target; the matrix records current implemented workflows and remaining gaps.

## Capability implementation matrix

This is a current public-facade inventory, not the historical acceptance scope
of a particular issue. **Implemented** means the named workflow has a public
API, not complete coverage of every C overload. **Partial** names a restricted
subset or a missing advanced operation. **Missing** means there is no public
facade. Intentional copying, cleanup and error conventions are documented
separately and do not close missing-operation gaps.

Availability is another dimension: optional native components must be enabled.
Python and Lua omit disabled presets; Go returns an unsupported error. Rust's
native build does not yet offer the same per-protocol component selection and
its `document` feature must match the linked C library. C++ headers follow the
generated C configuration. Missing facade support is distinct from disabled
native functionality; see [component selection](../guides/select-components.md).

| Capability / canonical C family | C++ | Rust | Python | Lua | Go |
| --- | --- | --- | --- | --- | --- |
| Format (`tlv_format_t`) | Implemented: traits, adapters and execution views | Partial: presets and Fixed; no public custom callback adapter | Partial: presets and Fixed | Partial: presets and Fixed | Partial: presets and Fixed; no custom callbacks |
| Element / instance Layout (`tlv_element_t`, `tlv_source_t`) | Implemented: borrowed semantic/source views | Implemented: borrowed Element and Decoded | Implemented: Element and Decoded; retained immutable backing | Partial: copied Element tables and source detail | Implemented: borrowed slices and Source; Clone owns bytes |
| Single-element read (`tlv_read*`) | Implemented: `read` | Implemented: `read`, `read_fixed` | Implemented: `read` | Missing standalone facade | Missing standalone facade; use Reader |
| Sequential Reader (`tlv_reader_*`) | Implemented: typed `reader` and ranges | Implemented: `Reader` | Implemented: `Reader` | Implemented: `reader` | Implemented: `Reader` |
| Resumable Reader (`init_incremental`, `set_input`) | Implemented | Implemented | Implemented | Missing | Implemented: `NewIncrementalReader`, `SetInput` |
| Tree Reader / events (`tlv_tree_reader_*`) | Implemented: items, events, limits and skip | Implemented | Implemented | Partial: tree Visitor, no pull/event cursor | Missing |
| Resumable Tree Reader | Implemented | Implemented | Implemented | Missing | Missing |
| Visitor (`tlv_reader_visit*`, `tlv_tree_reader_visit*`) | Implemented: Reader and Tree Reader callbacks | Implemented | Implemented | Partial: complete-buffer tree Visitor | Missing |
| Sequential Writer (`tlv_writer_*`) | Implemented: typed Writer, explicit output | Implemented: fixed output | Implemented: fixed or growable output | Implemented: bounded output | Implemented: fixed or growable output |
| Tree Writer (`tlv_tree_writer_*`) | Implemented: events, begin/end and scoped Builder | Implemented: events, measure and Tag capacity | Implemented: events, measure and Tag capacity | Partial: begin/end, no public event/measure facade | Partial: staged Begin/End; no public event facade |
| Copy/preservation (`tlv_writer_copy_encoded*`, `tlv_source_preserve`) | Implemented | Implemented | Implemented | Missing | Missing |
| Reader/Writer diagnostics | Implemented: native structured detail with C++ operation errors | Implemented: owned snapshots | Implemented: structured exceptions | Implemented for exposed Reader/Writer operations: owned tables | Implemented for exposed operations: owned ParseError/WriteError |
| Borrowed Query (`tlv_query_*`) | Implemented: Query and resumable matcher | Implemented: Query and matcher | Implemented: Query and matcher | Partial: complete-buffer Query evaluation; no resumable matcher facade | Missing |
| Document Query | Implemented: first match and `select` all matches | Partial: `find_path` / `find_path_mut` first match | Partial: `find_path` first match | Implemented: first match and Query results | Implemented: `Document.Query` all matches |
| Schema (`tlv/schema/`) | Partial: C schema descriptions with validation helpers | Partial: length/structure schemas and detailed reports | Partial: length/structure schemas and detailed reports | Partial: structural schemas/reports; no standalone length-schema facade | Missing |
| Value Codec (`tlv/codec/` and built-ins) | Partial: generic typed codecs/fields and standard conveniences; no claim of every C descriptor | Partial: configured NumberCodec and EMV codecs | Partial: configured NumberCodec and EMV amount | Partial: generic/configured codecs, EMV and custom callbacks | Partial: generic typed codecs; no protocol/custom/Structure codecs |
| Structure Codec (`tlv_structure_codec_t`) | Implemented: application-object adapters | Missing | Missing | Missing | Missing |
| Definition / dictionaries (`tlv_definition_*`) | Partial: generic registry and standard lookups | Partial: generic registry and EMV dictionary | Partial: generic registry | Missing generic facade | Missing |
| Field Encoding / reusable Layout configuration | Partial: custom Format can compose C through explicit interop; no complete idiomatic configuration facade | Missing general configuration facade | Missing general configuration facade | Missing general configuration facade | Missing general configuration facade |
| Owned mutable Document (`tlv_document_*`) | Implemented: RAII, Node, edit, encode; native allocator options | Partial: Document/Node/NodeMut; no allocator adaptation | Partial: safe Node handles; no allocator adaptation | Partial: checked Nodes and edits; no allocator adaptation | Partial: copied Node content, edits and Close; no allocator adaptation |
| Resumable Document Builder | Implemented | Implemented | Implemented | Missing | Missing |

Audit evidence is the public facade and consumer tests, rather than raw FFI:

| Language | Public implementation | Consumer/parity tests | User guide |
| --- | --- | --- | --- |
| C++ | [headers](../../tlv++/include/tlv++/) | [reader](../../tests/unit/reader/), [writer](../../tests/unit/writer/), [document](../../tests/unit/document/), [codecs](../../tests/unit/codec/) | [C++ examples](../guides/cxx-examples.md) |
| Rust | [opentlv/src](../../bindings/rust/opentlv/src/) | [opentlv/tests](../../bindings/rust/opentlv/tests/) | [Rust](../guides/rust.md) |
| Python | [opentlv facade](../../bindings/python/opentlv/src/opentlv/) | [facade tests](../../bindings/python/opentlv/tests/) | [Python](../guides/python.md) |
| Lua | [facade adapters](../../bindings/lua/src/) | [consumer tests](../../bindings/lua/tests/) | [Lua](../guides/lua.md) |
| Go | [public package](../../bindings/go/) | [public tests](../../bindings/go/tests/reader_test.go), [boundary tests](../../bindings/go/internal/capi/) | [Go](../guides/go.md) |

The WASM parse-to-JSON operation is a tooling embedding, not a general binding
with Reader/Writer/Document parity. Java remains future work. Exact signatures
belong in generated references and binding source documentation; this matrix
records supported workflows and their limits. Do not treat an experimental
label or raw FFI declaration as proof of parity.

### C++ resumable traversal

`tlv::reader<>` and `tlv::tree_reader` accept `tlv::input_mode::incremental`.
Their `next` operations return `expected` results with the original C codes:
`TLV_NEED_MORE_DATA` is resumable and `TLV_ERR_END_OF_BUFFER` is final exhaustion.
Use `set_input` to replace the contiguous input window and declare final input;
`consumed` bounds the discardable prefix and `offset` remains absolute.

Tree Reader takes a borrowed `span<tree_frame>` plus depth and item limits.
`next` returns the complete borrowed Element, source ranges, depth, absolute
offset and constructed classification together. `skip_subtree` can avoid
descent even after a depth or frame limit error. Tree Reader is noncopyable
because copying would alias its mutable frame storage.

Both Readers expose `visit` for language callables, backed by the C Visitor
engine. `query_matcher` owns a copy of its parsed `query` and exposes `matches`
for externally supplied preorder items and `visit` for a `tree_reader`.
Retain the matcher across STOP and input replacement; do not interleave
unmatched pulls with Query traversal. The matcher is noncopyable to keep its
native reference to the owned query stable.

## Rust and Python Reader and Query facades

Rust `Reader::incremental` and Python `Reader(..., final_input=False)` use the
canonical C sequential cursor. Rust `read_source` and Python `read_source`
return content and original source ranges in one decode. `TreeReader` in both
languages yields complete preorder items containing source metadata, depth,
absolute offset and constructed classification. Frame capacity, maximum depth
and item count are explicit constructor options. `skip_subtree` delegates to C,
including recovery after a descent limit failure.

`set_input` checks that undiscarded bytes remain identical before asking C to
replace the window. `consumed` bounds the discardable prefix, while `offset`
remains absolute. NEED_MORE_DATA remains distinct from final EOF and malformed
input. Rust returns `Error::NeedMoreData`; Python raises `NeedMoreDataError`.
Neither outcome permanently exhausts the incremental iterator. Sequential
convenience iterators still stop after a terminal error; explicit source pulls
remain available for advanced cursor control.

Rust borrows input and Fixed configuration through lifetimes; retained items
can outlive the cursor but not their storage. Frame storage is owned by the
Tree Reader. Rust diagnostics copy borrowed diagnostic fields into owned values.
Python retains immutable bytes without copying them; bytearray, memoryview and
other buffer inputs are snapshotted into bytes. Returned memoryviews keep old
storage alive across cursor destruction and input replacement. This deliberately
changes Python's former borrowing of mutable input, making source metadata stable.

Both languages expose `visit` on Readers and Tree Readers. Sequential callbacks
receive an Element; tree callbacks also receive depth and absolute offset.
Callbacks return `Visit` actions; Python also accepts None as CONTINUE. All
iteration is performed by C Visitor functions. Python callbacks receive owned
snapshots, and reentry into the active cursor is rejected. Rust callbacks borrow
immutable input, and panics are caught before the C boundary and resumed after
C returns. Python exceptions likewise propagate after the C adapter returns.
STOP preserves canonical continuation; callback effects are never rolled back.

`Query` parses through C and exposes path steps. `QueryMatcher` owns a stable
copy of its Query and provides `matches` and `visit`. Keep the same matcher
across STOP and input replacement; do not interleave unmatched pulls. Python
`Query.visit_buffer` composes the same C Tree Reader and Query matcher for
complete input. No language implements its own query grammar or matching rules.

Parity scenarios are exercised in `bindings/rust/opentlv/tests/tree_reader.rs`
and `bindings/python/opentlv/tests/test_tree_reader.py`. Writer and Document
coverage gaps remain tracked separately in the matrix above.

## Rust and Python Tree Writer facades

`TreeWriter` in both languages delegates begin, write, end, finish and finalized
output sizing to the C Tree Writer. Frame capacity, maximum item depth and
element count are explicit. Scratch capacity bounds the largest parent Value
that can be closed. Output and scratch do not grow implicitly.

Rust borrows caller-owned output exclusively and owns stable frame/scratch
storage. Python owns all these buffers and returns copied finalized bytes.
Both retain immutable copies of open tags until a successful `end`; temporary
language tag objects can therefore expire safely after `begin`. Neither facade
implements header patching, encoding or a second tree construction engine.

Rust `written` and Python `bytes()` expose only the finalized prefix, excluding
open roots. `finish` rejects unclosed parents without sealing the cursor.
Failures preserve the C operation's state/output guarantees. Rust exposes owned
`WriterDiagnostic` detail and Python uses structured exceptions. Tests in
`bindings/rust/opentlv/tests/tree_writer.rs` and
`bindings/python/opentlv/tests/test_tree_writer.py` cover open-tag ownership,
BER/CER output, item limits and scratch exhaustion.

C++ `measure_tree`, Rust `TreeWriter::measure` and Python `TreeWriter.measure`
consume semantic preorder records through `tlv_tree_writer_measure`. C owns
parent closure, depth validation and content-dependent encoding. Successful
measurement stages the actual bytes, so they can be reused without replay.
C++ returns a size into caller-owned workspace; Rust returns a borrowed staged
slice; Python returns immutable copied bytes. Source errors and native Writer
errors propagate. Rust catches source panics before crossing C and resumes
unwinding afterwards; Python propagates source exceptions after C returns.
On exhaustion, workspace requirements are discovered lower bounds, not the
final size prediction. Retrying requires a fresh source.

Rust `Writer::preserve` and Python `Writer.preserve` append unchanged source
bytes through C equality checks. `Decoded::preserve`/`Decoded.preserve_into`
provide standalone preservation. Python retains both the immutable input and
the native Format owner across cursor replacement or destruction. Changed
semantic content is rejected; raw `copy_encoded` intentionally does not validate.

## Schema constraints and bounded reports

Lua `schema:validate(data, format, options)` delegates to the same C report
validator. It snapshots rule/group descriptions, retains child schemas and
returns owned diagnostic tables. Schema violations return bounded reports;
fatal wire/configuration errors return a single basic diagnostic, including
only the location/context available from C. See the
[Lua Schema guide](../guides/lua.md#structural-schemas).

Rust `StructureSchema::with_constraints` and Python `StructureSchema` accept
`SchemaOrder` and `StructureGroup` descriptions. Each rule may select a group
and set native length flags and multiples. C validates rule-table ordering,
group identity, occurrence totals and all length policies; bindings only retain
or marshal the descriptions. Rust keeps stable group storage when schemas move.

`StructureSchema.validate_diagnostics` in both languages uses the C diagnostic report validator.
`UnknownPolicy` controls unknown-tag handling. A report retains at most the
requested capacity while `total_count` reports every violation, including at
zero capacity. Diagnostics own copied Tags, optional offsets and native issue names.
Reports survive input and schema destruction. Schema
violations return a report; malformed wire input and invalid configuration
still fail. `validate_diagnostics` returns owned expected/actual length,
occurrence and form constraints, group identity, severity, field names and
source offsets. Its path contains enclosing scopes; the affected Tag is a
separate field, matching the C diagnostic contract. Rust `validate_fixed` and
`validate_diagnostics_fixed` accept a borrowed
`FixedFormat`; Python accepts `FixedFormat` through the same `format` argument.

`NumberCodec` in Rust and Python selects binary big/little endian or BCD,
fixed/minimal width and BCD precision. Decode, encode, size queries and writing
into caller storage delegate to the C numeric codec. It interprets Values only;
it does not attach protocol tags or field-length rules.

`DefinitionRegistry` owns immutable generic definitions in Rust and Python;
C++ `definition_registry` borrows the caller's table. All three use the C lookup,
including first-match behavior for duplicate identifiers and empty identifiers.
Definition contains only a canonical identifier and optional descriptive name.
It does not select codecs, validate fields or resolve protocol context.

## Owning Documents and safe handles

Rust's default-enabled `document` Cargo feature exposes `Document`, immutable
`Node`, exclusive `NodeMut`, and `DocumentBuilder`. Disable it when linking C
without `OPENTLV_DOCUMENT`. C owns parsing, navigation, Query lookup, edits,
measurement and destination-format encoding. Immutable node/value borrows
prevent document mutation or destruction. Mutable navigation consumes its
handle; temporary immutable views block mutation until they expire. Fixed
configuration is borrowed for the document lifetime.

Python `Node` retains its Document and checks ownership metadata before each
native access. Erasure invalidates the node and all descendants; replacing a
constructed Value invalidates old descendants only after successful mutation.
Unrelated handles and the replaced parent remain usable. Closing the document
invalidates all handles. Invalid access and foreign-document arguments raise
`ValueError` before dereferencing native storage. Ownership tokens follow
parent relationships obtained from C; they do not parse or process TLV trees.
Invalidation is armed before native mutation and rolled back on a reported C
failure; asynchronous interruption may conservatively invalidate handles even
if the operation did not complete, preventing stale access after an interrupt.

Both languages expose the canonical resumable Document builder. Whole-stream
materialization requires a fresh Tree Reader. The next-subtree operation pulls
one root then copies exactly that subtree without decoding its following
sibling. NEED_MORE_DATA retains unfinished state; terminal failure discards
it. Rust borrows the reader exclusively and permits input replacement through
the builder. Python rejects pulls/skips/visitors while a builder is active but
allows `reader.set_input` and status queries. Closing or dropping the builder
releases its reader; completed documents survive. Python retains the native
cursor as the Format owner for such documents. Rust conservatively retains the
reader's combined input/Format lifetime in the resulting Document.

Python `Document.encode(format)` and `Node.encode(format)` support builtin
destination formats, with `encoded_size_as` for measurement. Rust also offers
caller-owned output and reports required capacity on shortage. Remaining
configuration/allocator differences remain tracked coverage gaps and are
not yet exposed by their public facades.

## Shared concepts and intentional differences

Format describes wire representation; Layout locates an encoded instance;
Element holds its Tag and logical Value. Schema describes structural rules and
Codec interprets Value. Reader/Writer, traversal, Query and Document consume
these contracts as described in the [canonical architecture](architecture.md).

Borrowed C/C++/Rust views preserve storage lifetimes explicitly. Python retains
immutable bytes and snapshots mutable input; Lua copies bytes into strings;
Go Elements borrow slices while Node content and diagnostics are copied.
These are language ergonomics, not different TLV representations. Document
owns data in every binding, with language-specific cleanup and invalidation.
See each language's guide for the actual allocation and lifetime boundaries.

## Adapting ergonomics, not architecture

Bindings must adapt syntax and behavior to the conventions of their target
language; they must not introduce a different conceptual architecture to do
it. For example:

- Rust's `Reader` implements `Iterator<Item = Result<Element>>`, so callers
  write `for element in reader { ... }` instead of an explicit `at_end()`/
  `next()` loop. `tlv++` offers range iteration through `tlv::parse` and built-in `parse`
  helpers, alongside explicit pulls and `reader.visit` / `tree_reader.visit`.
- Python's `Reader` iterates the same reader concept with
  `for element in reader:`, and raises a native `Exception` subclass instead of
  returning an error code.
- Lua's `Reader`, returned by `opentlv.reader()`, is directly usable as a
  generic-for iterator (`for element in reader do ... end`) via Lua's `__call`
  metamethod, rather than a separate iterator protocol; it raises a plain
  table via `error()` instead of an exception object, since Lua has no
  exception hierarchy to subclass.
- Rust's and `tlv++`'s `Writer` fill a caller-provided fixed-capacity buffer
  and report an error when an element does not fit, matching the C library's
  allocation-free `tlv_writer_t`. Python's `Writer(format, buffer=storage)`
  borrows writable contiguous storage with the same capacity and position
  semantics. Omitting `buffer` retains the growable `bytearray` convenience
  wrapper. Exact Element sizing is available before allocating output in C,
  C++, Rust and Python; see the [allocation contract](../guides/memory.md#writing).
- `tlv_document_t` is explicitly freed with `tlv_document_free()` in C, and
  by RAII (`tlv::document`'s destructor) in `tlv++`. Python's `Document`
  frees the same underlying allocation either way: deterministically via
  `close()` or a `with` block, the closest Python equivalent to RAII, or
  otherwise whenever garbage collection reclaims it. Ownership (the document
  owns every node, tag and value in it) is the same in every binding; only
  how and when that ownership ends differs.
- Go exposes `Reader.Next()` as a boolean, the current `Element()` as a
  borrowed view, and `Reader.Err()` after iteration. Fallible constructors,
  writes and Document operations return errors through Go's normal conventions;
  `errors.Is` and `errors.As` retain native status and diagnostic context.
- A future JavaScript binding could expose a reader as a JS iterable and
  surface failures as native exceptions.

The syntax changes; the concepts (a read-only, one-pass `Reader` yielding
`Element` values) do not.

## Status across current bindings

Capability status is recorded once in the matrix above. Packaging and user
entry points are:

| Language / consumer | Packaging and maturity | Usage | Development |
| --- | --- | --- | --- |
| C++ | Header-only C++11 facade shipped with OpenTLV; links the C engine | [C++ examples](../guides/cxx-examples.md) | [Public/native contract](cxx-native-boundary.md) |
| Rust | Experimental `opentlv` facade plus `opentlv-sys` FFI crate | [Rust guide](../guides/rust.md) | [Rust development](../development/rust.md) |
| Python | Experimental `opentlv` facade plus `opentlv-core` extension | [Python guide](../guides/python.md) | [Python development](../development/python.md) |
| Lua | Experimental `opentlv` module with native `opentlv._core` implementation | [Lua guide](../guides/lua.md) | [Lua development](../development/lua.md) |
| Go | Experimental public `opentlv` package with private `internal/capi` bridge | [Go guide](../guides/go.md) | [Go development](../development/go.md) |
| WebAssembly | Narrow parse-to-JSON tooling embedding; general facade parity does not apply | [WASM tooling](../development/webassembly.md) | [WASM sources](../../bindings/wasm/) |

Language-specific copying, cleanup, errors and current limitations are documented
in those guides; an experimental label neither implies full parity nor excuses
an undocumented missing capability.

## Implementation package names

The binding boundary is shared; implementation names follow each language.
Rust uses the raw FFI crate `opentlv-sys` (`opentlv_sys` in code). Python uses
the private extension module `_opentlv`, distributed as `opentlv-core`. Lua
loads `opentlv._core` from `opentlv/_core` under its native module search path.
Go keeps its C bridge in `internal/capi`; `internal` enforces the private import
boundary, while `capi` describes the package responsibility. Applications use
the public `opentlv` facade in each language.

For existing checkouts, update Rust dependencies from `opentlv-native` to
`opentlv-sys` and raw imports from `opentlv_native` to `opentlv_sys`. Python
install commands now use `bindings/python/opentlv-core`; code directly using
the implementation extension imports `_opentlv`. Lua installation places the
compiled module under `opentlv/_core`, and direct implementation imports use
`require("opentlv._core")`. Public facade imports remain `opentlv`.

## See also

- [Layered architecture](architecture.md) for how these concepts are
  organized inside the C library and `tlv++` itself.
- [C API reference](../reference/c-api.md) and [C++ API
  reference](../reference/cxx-api.md).
- [Using OpenTLV from Rust](../guides/rust.md) for a worked example of a
  binding that follows this contract.
