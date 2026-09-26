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

C++ and Rust ship today; Python (`bindings/python/`) now binds Reader, Writer,
Document, Entry and Tag — including Document, which neither Rust nor
WebAssembly bind yet. Lua (`bindings/lua/`) binds Reader, Entry and Tag. Go is
illustrative here, not yet scaffolded, to show the contract extends past the
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

## Core concepts

| Concept | Responsibility | C | C++ (`tlv++`) | Rust (`opentlv`, experimental) | Python (`opentlv`, experimental) | Lua (`opentlv`, experimental) |
| --- | --- | --- | --- | --- | --- | --- |
| Reader | Read-only parsing and traversal | `tlv_reader_t`, `tlv_reader_next()` | `tlv::reader` | `Reader<'a>` | `Reader` | `opentlv.reader()` |
| Writer | Construction and serialization | `tlv_writer_t` | `tlv::writer` | `Writer<'a>` | `Writer` | not bound yet |
| Document | Optional owning, mutable representation | `tlv_document_t` | `tlv::document` | not bound yet | `Document`, `Node` | not bound yet |
| Entry | One TLV entry, or a view onto one | `tlv_view_t` | `tlv::entry` | `Entry<'a>` | `Entry` | a plain table (`tag`/`length`/`value`/`offset` fields) |
| Tag | The TLV tag abstraction: raw identifying bytes | `tlv_tag_t` | `tlv::tag_t` (alias) | `Tag` | `Tag` | a raw Lua string (content equality already compares it) |
| Schema | Structural validation: tags, lengths, occurrence and nesting rules | `tlv_schema_t`, `tlv_structure_schema_t` | same C types, wrapped by `tlv::validate`/`tlv::validate_all` | `LengthSchema`, `StructureSchema` | `LengthSchema`, `StructureSchema` | not bound yet |
| Codec | Typed encoding and decoding of a value | `tlv_codec_t`, `tlv_structure_codec_t` | `TlvCodec` concept, `tlv::decode_structure<T>`/`encode_structure` | `Codec` | `codec` submodule, narrow: only the public `tlv_emv_codec_amount` | not bound yet |
| Diagnostics | Structured diagnostic information for a failure | `tlv_diagnostic_t` | `tlv::diagnostic` (alias) | `SchemaError`, `ProfileError`, `CodecError` (each carries the failing offset; no unified diagnostic type yet) | `OpenTLVError` subclasses carry the offset, expected/actual text and operation, when the C API reports them | a plain table with `code`/`message` and, when reported, `offset`/`expected`/`actual`/`operation`/`tag` |

A binding adopts a concept when it needs it, not all at once: the table above
already shows gaps (Rust has no `Document` yet, and no single `Diagnostics`
type), and future bindings will fill in concepts incrementally too. What the
contract fixes is the name and role a concept gets once a binding does expose
it, not a deadline for exposing all eight.

## Adapting ergonomics, not architecture

Bindings must adapt syntax and behavior to the conventions of their target
language; they must not introduce a different conceptual architecture to do
it. For example:

- Rust's `Reader` implements `Iterator<Item = Result<Entry>>`, so callers
  write `for entry in reader { ... }` instead of an explicit `at_end()`/
  `next()` loop. `tlv++`'s `reader` uses that explicit loop today (or a
  visitor passed to `tlv::walk_tree`); a future C++ range-based `for` over a
  `reader` would be the same adaptation applied there.
- Python's `Reader` iterates the same reader concept with
  `for entry in reader:`, and raises a native `Exception` subclass instead of
  returning an error code.
- Lua's `Reader`, returned by `opentlv.reader()`, is directly usable as a
  generic-for iterator (`for entry in reader do ... end`) via Lua's `__call`
  metamethod, rather than a separate iterator protocol; it raises a plain
  table via `error()` instead of an exception object, since Lua has no
  exception hierarchy to subclass.
- Rust's and `tlv++`'s `Writer` fill a caller-provided fixed-capacity buffer
  and report an error when an entry does not fit, matching the C library's
  allocation-free `tlv_writer_t`. Python's `Writer` owns a `bytearray` it
  grows as needed instead, so `write` never fails for lack of space: Python
  callers do not pre-size a buffer or retry a failed write the way C, C++ and
  Rust callers do. The concept (construction and serialization into a
  sequential output) is unchanged; only which language owns the
  buffer-sizing problem moves.
- `tlv_document_t` is explicitly freed with `tlv_document_free()` in C, and
  by RAII (`tlv::document`'s destructor) in `tlv++`. Python's `Document`
  frees the same underlying allocation either way: deterministically via
  `close()` or a `with` block, the closest Python equivalent to RAII, or
  otherwise whenever garbage collection reclaims it. Ownership (the document
  owns every node, tag and value in it) is the same in every binding; only
  how and when that ownership ends differs.
- A future Go binding could return `(Entry, error)` pairs from a `Next()`
  method, or a range-over-func iterator (`for entry, err := range
  reader.All() { ... }`), matching Go's own error-handling convention instead
  of Rust's `Result` or C's error codes.
- A future JavaScript binding could expose a reader as a JS iterable and
  surface failures as native exceptions.

The syntax changes; the concepts (a read-only, one-pass `Reader` yielding
`Entry` values) do not.

## Status across current bindings

- **C++ (`tlv++`)**: ships in this repository, header-only, and covers every
  concept above except a standalone `Diagnostics` type (it reuses the C
  `tlv_diagnostic_t` directly as `tlv::diagnostic`).
- **Rust (`opentlv`)**: experimental, in `bindings/rust/`. Covers Reader,
  Writer, Entry, Tag, Schema and Codec; `Document` and the callback-based
  visitors, structure codecs and DOL profile are not bound yet. Its `Codec`
  is the exception to this page's binding-boundary rule: beyond the one
  concrete codec the C API exports publicly (`tlv_emv_codec_amount`), the
  per-kind EMV decoding it implements only exists in a C function private to
  `tlv/src/`, so `Codec` reimplements that logic in Rust instead of calling
  into C for it. See [Rust bindings](../development/rust.md) and [using
  OpenTLV from Rust](../guides/rust.md).
- **WebAssembly**: in `bindings/wasm/`, a deliberately narrow `parse()`
  function that returns a JSON element tree for browser tooling, not a
  general-purpose object-oriented binding. It is a small embedding built on
  the C API rather than a binding this contract's Reader/Writer/Entry shape
  applies to. See [WebAssembly build](../development/webassembly.md).
- **Python**: experimental, in `bindings/python/`, split into
  `opentlv-native` (a native extension written against the CPython C API,
  using the CPython Limited API where compatible, that calls the public C
  API) and `opentlv` (a pure-Python package on top of it) — the same split
  as the Rust `opentlv-native`/`opentlv` crates. Covers Reader, Writer,
  Document, Entry, Tag and Schema, across the default, BER, CER, DER and
  fixed-1-byte wire formats, plus a deliberately narrow Codec (only the one
  concrete codec, `tlv_emv_codec_amount`, that the public C API exports —
  unlike Rust's `Codec`, the rest is not a thin C wrapper and reimplements
  EMV decoding logic that only exists in a private C header). See [Python
  bindings](../development/python.md) and [using OpenTLV from
  Python](../guides/python.md).
- **Lua**: experimental, in `bindings/lua/`, split into `opentlv-native` (a
  native extension written directly against the Lua C API) and `opentlv`
  (a one-line pure-Lua entry point on top of it, `lua/opentlv/init.lua`) —
  the same split as the Rust and Python `opentlv-native`/`opentlv` packages,
  though here the pure layer adds no ergonomics of its own, since Lua's C
  API is already close to the concepts bound. Targets Lua 5.1 through 5.4
  and LuaJIT. Covers Reader, Entry and Tag, across the default, BER, CER, DER,
  Bluetooth LTV and configurable fixed-width formats, plus preorder tree
  traversal (`opentlv.walk_tree()`, built on `tlv_walk_tree()`/
  `tlv_der_walk()`) — the one traversal capability neither Rust nor Python
  exposes directly yet. See [Lua bindings](../development/lua.md) and
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
