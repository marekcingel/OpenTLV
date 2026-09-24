# Common conceptual model for language bindings

OpenTLV ships one C library (`tlv`) and is expected to grow bindings for
several languages. A header-only C++ wrapper (`tlv++`) ships in this
repository today, an experimental Rust crate (`opentlv`, in `bindings/rust/`)
and an experimental Python package (`opentlv`, in `bindings/python/`) are
under active development, and further bindings may follow. Without a shared
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
    +----------+---------+---------+----------+
    |          |         |         |          |
   C++       Rust        Go      Python       ...
    |          |         |         |          |
idiomatic  idiomatic  idiomatic  idiomatic  idiomatic
   C++       Rust        Go       Python    <language>
```

C++ and Rust ship today; Python is now scaffolded (`bindings/python/`) but
does not bind any of the concepts below yet. Go is illustrative here, not yet
scaffolded, to show the contract extends past the current bindings. The
trailing `...` stands for any further binding.

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

| Concept | Responsibility | C | C++ (`tlv++`) | Rust (`opentlv`, experimental) |
| --- | --- | --- | --- | --- |
| Reader | Read-only parsing and traversal | `tlv_reader_t`, `tlv_reader_next()` | `tlv::reader` | `Reader<'a>` |
| Writer | Construction and serialization | `tlv_writer_t` | `tlv::writer` | `Writer<'a>` |
| Document | Optional owning, mutable representation | `tlv_document_t` | `tlv::document` | not bound yet |
| Entry | One TLV entry, or a view onto one | `tlv_view_t` | `tlv::entry` | `Entry<'a>` |
| Tag | The TLV tag abstraction: raw identifying bytes | `tlv_tag_t` | `tlv::tag_t` (alias) | `Tag` |
| Schema | Structural validation: tags, lengths, occurrence and nesting rules | `tlv_schema_t`, `tlv_structure_schema_t` | same C types, wrapped by `tlv::validate`/`tlv::validate_all` | `LengthSchema`, `StructureSchema` |
| Codec | Typed encoding and decoding of a value | `tlv_codec_t`, `tlv_structure_codec_t` | `TlvCodec` concept, `tlv::decode_structure<T>`/`encode_structure` | `Codec` |
| Diagnostics | Structured diagnostic information for a failure | `tlv_diagnostic_t` | `tlv::diagnostic` (alias) | `SchemaError`, `ProfileError`, `CodecError` (each carries the failing offset; no unified diagnostic type yet) |

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
- A future Python binding could iterate the same reader concept with
  `for entry in reader:`, and raise a native `Exception` from `Result`-style
  errors instead of returning an error code.
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
  visitors, structure codecs and DOL profile are not bound yet. See [Rust
  bindings](../development/rust.md) and [using OpenTLV from
  Rust](../guides/rust.md).
- **WebAssembly**: in `bindings/wasm/`, a deliberately narrow `parse()`
  function that returns a JSON element tree for browser tooling, not a
  general-purpose object-oriented binding. It is a small embedding built on
  the C API rather than a binding this contract's Reader/Writer/Entry shape
  applies to. See [WebAssembly build](../development/webassembly.md).
- **Python**: experimental, in `bindings/python/`, split into
  `opentlv-native` (a native extension written against the CPython C API,
  using the CPython Limited API where compatible, that calls the public C
  API) and `opentlv` (a pure-Python package on top of it) — the same split
  as the Rust `opentlv-native`/`opentlv` crates. Infrastructure only so far:
  only the linked library's version is exposed. None of the concepts above
  are bound yet; see [Python bindings](../development/python.md) and [using
  OpenTLV from Python](../guides/python.md).
- **Go**: planned, not started yet. No `bindings/go/` directory exists; when
  work on it begins, it follows this contract like the Rust crate does.

## See also

- [Layered architecture](architecture.md) for how these concepts are
  organized inside the C library and `tlv++` itself.
- [C API reference](../reference/c-api.md) and [C++ API
  reference](../reference/cxx-api.md).
- [Using OpenTLV from Rust](../guides/rust.md) for a worked example of a
  binding that follows this contract.
