# Common conceptual model for language bindings

OpenTLV ships one C library (`tlv`) and is expected to grow bindings for
several languages. A header-only C++ wrapper (`tlv++`) ships in this
repository today, an experimental Rust crate (`opentlv`, in `bindings/rust/`),
an experimental Python package (`opentlv`, in `bindings/python/`) and an
experimental Lua module (`opentlv`, in `bindings/lua/`) are under active
development, and further bindings may follow. Without a shared
contract, each binding could invent its own vocabulary for the same
operation, for example `Reader` in C++, `parse()` in Python, `Parser` in Rust,
and `Decoder` elsewhere, and a developer who already knows OpenTLV in one
language would have to relearn it in the next.

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

C++, Rust and Python expose Readers, Writers and Document facades today.
Lua (`bindings/lua/`) currently binds Reader, Writer, Tree Writer, Schema, Value Codec, Element and Tag.
Go is illustrative here, not yet scaffolded, to show the contract extends past the
current bindings. The trailing `...` stands for any further binding.

The public OpenTLV C API (see the [C API reference](../reference/c-api.md)) is
the single language boundary every binding wraps. A binding calls into the C
library directly for parsing, encoding, validation and codec work instead of
reimplementing it, and it does not depend on another language's binding: the
Rust crate does not sit on top of the C++ wrapper, and a future binding would
not sit on top of Rust either. This keeps behavior identical across languages,
since one C implementation backs every one of them, and lets each binding be
built and shipped independently of the others. `tlv++` differs only in build
shape, not in boundary: it is header-only and compiles directly against the C
headers instead of linking a separately built library, but it still wraps only
the public C API. See [relationship to the C
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
target; [#400](https://github.com/marekcingel/OpenTLV/issues/400) delivers the
scoped implementation described below.

## Capability implementation matrix

The current #400 implementation scope is C++, Rust and Python. Lua parity is
handled by separate stories and does not block this implementation; its column
below remains informational.

The following remaining capabilities are explicitly **out of scope for #400**
and are deferred to follow-up work:

- Additional codecs beyond the facades already implemented.
- Additional protocol-specific Definition/dictionary registries and lookup.
- Further Format/Layout extensions, including custom callbacks, additional
  optional builtins and destination-format configuration not yet exposed.
- Custom Document allocator adaptation.

Existing implementations in these families remain part of #400. The deferred
capabilities do not block acceptance of its scoped implementation. They remain
coverage gaps against the long-term full-parity contract; excluding them from
this issue does not mark them implemented.

The public C headers are the source of truth. Each row must cover all public
operations in the referenced family before it can be marked complete. **Bound**
means the listed operations have a public facade; it does not imply every
edge case has a parity test. **Partial** means only a subset is exposed.
**Missing** means the capability has no public facade. **Audit** means operation
coverage still needs verification; it must not be counted as parity.

| Capability and canonical C operations | C++ | Rust | Python | Lua |
| --- | --- | --- | --- | --- |
| Single-element Reader: `tlv_read`, `tlv_read_diag`, `tlv_read_source_diag` | Bound: `read` | Bound: `read`, `read_fixed` | Bound: `read` | Audit |
| Sequential Reader: `tlv_reader_init`, `tlv_reader_next`, `tlv_reader_at_end` | Bound: `reader` | Bound: `Reader` | Bound: `Reader` | Bound: `reader` |
| Incremental Reader: `tlv_reader_init_incremental`, `tlv_reader_set_input`, `tlv_reader_consumed`, `tlv_reader_offset` | Bound: `input_mode`, `set_input`, `consumed`, `offset` | Bound: `Reader::incremental`, continuation methods | Bound: `Reader(final_input=False)`, continuation methods | Missing |
| Tree Reader: `tlv_tree_reader_init`, `tlv_tree_reader_next`, `tlv_tree_reader_at_end` | Bound: `tree_reader` | Bound: `TreeReader` | Bound: `TreeReader` | Missing pull facade |
| Event measurement: `tlv_tree_writer_measure_events` | Bound: `measure_tree_events` | Bound: `measure_events` | Bound: `measure_events` | Missing |
| Bounded Tag copying: `tlv_tree_writer_set_tag_storage` | Bound: `set_tag_storage` | Bound: `set_tag_capacity` | Bound: `set_tag_capacity` | Partial: constructor `tag_capacity`; no storage replacement |
| Structural events: `tlv_tree_reader_next_event`, `tlv_tree_writer_write_event` | Bound: `next_event`, `write_event` | Bound: `read_event`, `write_event` | Bound: `next_event`, `write_event` | Missing tree facades |
| Incremental Tree Reader: `tlv_tree_reader_init_incremental`, `tlv_tree_reader_set_input`, `tlv_tree_reader_consumed`, `tlv_tree_reader_offset` | Bound: `tree_reader` continuation methods | Bound: `TreeReader` continuation methods | Bound: `TreeReader` continuation methods | Missing |
| Reader diagnostics: `tlv_reader_next_diag`, `tlv_tree_reader_next_diag`, `tlv_reader_diagnostic_init` | Bound: optional diagnostics and value initialization | Bound: owned `ReaderDiagnostic` | Bound: structured exceptions | Partial |
| Source information and instance Layout: `tlv_reader_next_source_diag`, `tlv_source_t`, Tree Reader item source/depth/offset | Bound: `next_source`, `tree_item`, `source` | Bound: `Decoded`, `Layout`, `TreeItem` | Bound: `Decoded`, `Layout`, `TreeItem` | Partial |
| Reader limits: Tree Reader frame capacity, maximum depth and item count | Bound: `tree_reader` construction | Bound: `TreeReader` construction | Bound: `TreeReader` construction | Partial: Visitor options |
| Subtree control: `tlv_tree_reader_skip_subtree` | Bound: `skip_subtree` | Bound: `skip_subtree` | Bound: `skip_subtree` | Audit |
| Visitor: `tlv_reader_visit[_diag]`, `tlv_tree_reader_visit[_diag]` | Bound: Reader and Tree Reader `visit` | Bound: Reader and Tree Reader `visit` | Bound: Reader and Tree Reader `visit` | Partial: tree Visitor |
| Single-element Writer: `tlv_write[_diag]`, `tlv_write_element[_diag]` | Bound: `write` overloads | Bound: `write_element`, `write_element_fixed` | Audit | Missing |
| Sequential Writer: `tlv_writer_init`, `tlv_writer_write[_diag]`, `tlv_writer_write_element[_diag]`, size/remaining | Audit | Bound: `Writer`, owned diagnostics | Audit | Bound: `writer`, write/Element, size/remaining |
| Tree Writer: `tlv_tree_writer_init`, begin/write/end and diagnostic variants, finish/size | Bound: `tree_writer` | Bound: `TreeWriter` | Bound: `TreeWriter` | Bound: `tree_writer`, begin/write/end, finish/size |
| Element measurement: `tlv_encoded_size`, `tlv_element_encoded_size[_diag]` | Bound: `encoded_size` overloads | Bound: `measure_element`, `encoded_size` | Bound | Missing |
| Tree measurement: `tlv_tree_writer_measure`, staging and capacity requirements | Bound: `measure_tree` | Bound: `TreeWriter::measure`, `required_workspace` | Bound: `TreeWriter.measure`, exception requirements | Missing |
| Writer diagnostics: `tlv_writer_diagnostic_t` and diagnostic operations | Audit | Bound: owned sequential, single-element and Tree Writer diagnostics | Audit | Bound: owned sequential and Tree Writer error fields; single-element facade missing |
| Exact copy/preservation: `tlv_writer_copy_encoded[_diag]`, `tlv_writer_preserve[_diag]`, `tlv_source_preserve` | Audit | Bound: `Writer::copy_encoded`, `Writer::preserve`, `Decoded::preserve` | Bound: `Writer.copy_encoded`, `Writer.preserve`, `Decoded.preserve_into` | Missing |
| Query: parse/step, matcher init/visit, `tlv_query_visit`, `tlv_query_visit_buffer` | Bound: `query`, `query_matcher` | Bound: `Query`, `QueryMatcher` | Bound: `Query`, `QueryMatcher` | Missing |
| Schema: public `tlv/schema/` operations, constraints and diagnostics | Audit | Partial: constraints, named fields/groups, bounded detailed reports and Fixed Format validation bound; remaining Format extensions out of scope for #400 | Partial: constraints, named fields/groups, bounded detailed reports and Fixed Format validation bound; remaining Format extensions out of scope for #400 | Partial: structural schemas and bounded detailed reports; standalone length-schema operations remain unbound |
| Codec: public `tlv/codec/` operations and builtin codecs (additional codecs out of scope for #400) | Audit | Partial: configured `NumberCodec` and EMV codecs | Partial: configured `NumberCodec` and EMV amount | Value codecs, configuration, builtin EMV selection and custom callbacks (#302); structure codecs remain unbound |
| Generic Definition: `tlv_definition_t`, `tlv_definition_registry_t`, `tlv_definition_find` | Bound: borrowed `definition_registry` | Bound: owned `DefinitionRegistry` | Bound: owned `DefinitionRegistry` | Missing generic facade |
| Builtin Definition/dictionary registries and protocol-specific lookup (additional coverage out of scope for #400) | Audit | Partial: EMV dictionary | Missing | Separate stories |
| Format: decode/measure/encode, configuration, custom callbacks and optional builtins (remaining extensions out of scope for #400) | Audit | Partial | Partial | Partial |
| Format field-layout configuration: public `tlv/layout.h` operations (remaining extensions out of scope for #400) | Audit | Audit | Audit | Audit |
| Document: public `tlv/document/document.h` operations and node lifetimes | Audit | Partial: owning `Document`, borrowed `Node`/`NodeMut`, builder; allocator adaptation out of scope for #400 | Partial: safe invalidation, builder, builtin destination formats; allocator and remaining destination configuration out of scope for #400 | Missing |

Go and Java are future bindings, not existing implementations to mark complete.
The current WASM tooling embedding exposes only a parse-to-JSON operation; it
does not satisfy general binding parity. Its classification is described below.
Neither an experimental label nor an FFI declaration closes a matrix gap.

The first implementation slice has focused C++ tests in
`tests/unit/reader/test_reader.cpp`: borrowed source results, incomplete/final
input, discarded-window offsets, preorder agreement with C, resource limits,
subtree skipping, Visitor STOP/resume and incremental Query continuation.
Rows marked Audit require a function-by-function review before claiming full
capability parity. For #400 acceptance, this review applies to its in-scope
operations; the exclusions above are tracked for follow-up work.

### C++ resumable traversal

`tlv::reader` and `tlv::tree_reader` accept `tlv::input_mode::incremental`.
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
explicitly out of scope for #400.

## Core concepts

| Concept | Responsibility | C | C++ (`tlv++`) | Rust (`opentlv`, experimental) | Python (`opentlv`, experimental) | Lua (`opentlv`, experimental) |
| --- | --- | --- | --- | --- | --- | --- |
| Reader | Read-only parsing and traversal | `tlv_reader_t`, `tlv_reader_next()` | `tlv::reader` | `Reader<'a>` | `Reader` | `opentlv.reader()` |
| Writer | Construction and serialization | `tlv_writer_t` | `tlv::writer` | `Writer<'a>` | `Writer` | `opentlv.writer()` |
| Document | Optional owning, mutable representation | `tlv_document_t` | `tlv::document` | `Document`, `Node`, `NodeMut`, `DocumentBuilder` | `Document`, `Node`, `DocumentBuilder` | not bound yet |
| Element | One TLV element with borrowed wire fields | `tlv_element_t` | `tlv::element` | `Element<'a>` | `Element` | a plain table (`tag`/`raw_length`/`length`/`value`/`offset` fields) |
| Tag | The TLV tag abstraction: raw identifying bytes | `tlv_tag_t` | `tlv::tag_t` (alias) | `Tag` | `Tag` | a raw Lua string (content equality already compares it) |
| Schema | Structural validation: tags, lengths, occurrence and nesting rules | `tlv_schema_t`, `tlv_structure_schema_t` | same C types, wrapped by `tlv::validate`/`tlv::validate_all_diag` | `LengthSchema`, `StructureSchema` | `LengthSchema`, `StructureSchema` | `schema` / `Schema:validate` (structural reports) |
| Codec | Typed encoding and decoding of a value | `tlv_codec_t`, `tlv_structure_codec_t` | `TlvCodec` concept, `tlv::decode_structure<T>`/`encode_structure` | `Codec` | `NumberCodec` and EMV amount functions | `codecs`, `codec {decode, encode}`; Value codecs only |
| Diagnostics | Structured diagnostic information for a failure | `tlv_diagnostic_t` | `tlv::diagnostic` (alias) | `SchemaError`, `ValidationError`, `CodecError` (each carries the failing offset; no unified diagnostic type yet) | `OpenTLVError` subclasses carry the offset, expected/actual text and operation, when the C API reports them | owned tables with common code/message/severity, optional native context/path/offset, and Reader/Writer or Schema detail |

Bindings may reach parity incrementally, but missing capabilities remain
tracked gaps against the public facade contract. The table above describes
concept coverage; exposing a concept does not establish coverage of every C
operation belonging to it.

## Adapting ergonomics, not architecture

Bindings must adapt syntax and behavior to the conventions of their target
language; they must not introduce a different conceptual architecture to do
it. For example:

- Rust's `Reader` implements `Iterator<Item = Result<Element>>`, so callers
  write `for element in reader { ... }` instead of an explicit `at_end()`/
  `next()` loop. `tlv++`'s `reader` uses that explicit loop today (or a
  visitor passed to `reader.visit` or `tree_reader.visit`); a future C++ range-based `for` over a
  `reader` would be the same adaptation applied there.
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
- A future Go binding could return `(Element, error)` pairs from a `Next()`
  method, or a range-over-func iterator (`for element, err := range
  reader.All() { ... }`), matching Go's own error-handling convention instead
  of Rust's `Result` or C's error codes.
- A future JavaScript binding could expose a reader as a JS iterable and
  surface failures as native exceptions.

The syntax changes; the concepts (a read-only, one-pass `Reader` yielding
`Element` values) do not.

## Status across current bindings

- **C++ (`tlv++`)**: ships in this repository, header-only, and covers every
  concept above except a standalone `Diagnostics` type (it reuses the C
  `tlv_diagnostic_t` directly as `tlv::diagnostic`).
- **Rust (`opentlv`)**: experimental, in `bindings/rust/`. Covers Reader,
  Writer, Tree Reader/Writer, Query, Visitors, Document, Element, Tag, Schema
  and EMV Codec. Codec conversion delegates to public C codecs; earlier
  binding-side EMV conversions are no longer the implementation. Generic
  codecs, structure codecs, allocator adaptation and other matrix gaps still
  require work. See [Rust bindings](../development/rust.md) and [using
  OpenTLV from Rust](../guides/rust.md).
- **WebAssembly**: in `bindings/wasm/`, a deliberately narrow `parse()`
  function that returns a JSON element tree for browser tooling, not a
  general-purpose object-oriented binding. It is a small embedding built on
  the C API rather than a binding this contract's Reader/Writer/Element shape
  applies to. See [WebAssembly build](../development/webassembly.md).
- **Python**: experimental, in `bindings/python/`, split into
  `opentlv-native` (a native extension written against the CPython C API,
  using the CPython Limited API where compatible, that calls the public C
  API) and `opentlv` (a pure-Python package on top of it) — the same split
  as the Rust `opentlv-native`/`opentlv` crates. Covers Reader, Writer,
  Tree Reader/Writer, Query, Visitors, Document, Element, Tag and Schema.
  Codec coverage includes configured numeric codecs and the EMV amount codec;
  other public C codecs still need facade support. See [Python bindings](../development/python.md)
  and [using OpenTLV from Python](../guides/python.md).
- **Lua**: experimental, in `bindings/lua/`, split into `opentlv-native` (a
  native extension written directly against the Lua C API) and `opentlv`
  (a one-line pure-Lua entry point on top of it, `lua/opentlv/init.lua`) —
  the same split as the Rust and Python `opentlv-native`/`opentlv` packages,
  though here the pure layer adds no ergonomics of its own, since Lua's C
  API is already close to the concepts bound. Targets Lua 5.1 through 5.4
  and LuaJIT. Covers Reader, Writer, Tree Writer, Element and Tag, across
  the default, BER, CER, DER, Bluetooth LTV and configurable fixed-width formats, plus preorder tree
  traversal (`opentlv.visit_tree()`, built on `tlv_tree_reader_visit()`/
  `tlv_der_visit()`). Pull-based Tree Reader and advanced Writer capabilities
  (measurement, structural events and exact copy/preservation) remain gaps
  in Lua. Value codecs expose builtin representations, configured codecs,
  EMV dictionary selection and custom callbacks through `tlv_codec_t` (#302).
  Structure codecs remain unbound. See [Lua bindings](../development/lua.md) and
  [using OpenTLV from Lua](../guides/lua.md).
- **Go**: planned, not started yet. No `bindings/go/` directory exists; when
  work on it begins, it follows this contract like the Rust crate does.

## See also

- [Layered architecture](architecture.md) for how these concepts are
  organized inside the C library and `tlv++` itself.
- [C API reference](../reference/c-api.md) and [C++ API
  reference](../reference/cxx-api.md).
- [Using OpenTLV from Rust](../guides/rust.md) for a worked example of a
  binding that follows this contract.
