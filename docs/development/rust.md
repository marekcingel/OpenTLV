# Rust bindings (experimental)

The Rust bindings live in `bindings/rust/`, a Cargo workspace with two crates:

| Crate | Purpose |
| --- | --- |
| `opentlv-sys` | Raw `extern "C"` declarations of the OpenTLV C API and the build script that links the C library |
| `opentlv` | Safe Rust API built on `opentlv-sys` |

For setup, examples, error handling and ownership as a user, see
[Using OpenTLV from Rust](../guides/rust.md).

All `unsafe` FFI interaction is isolated in `opentlv-sys`; `opentlv` contains no
`extern` declarations. Only the part of the C API the safe crate needs is bound
so far.

## Core types

The `opentlv` crate exposes these safe types; none of them exposes a raw pointer:

| Type | Wraps | Notes |
| --- | --- | --- |
| `Tag` | `tlv_tag_t` | Owned, `Copy`; built with `from_bytes` or `from_u64`, read with `as_bytes` or `to_u64` |
| `Entry<'a>` | `tlv_view_t` | A `Tag` plus a value borrowed as `&'a [u8]` |
| `Error` | `tlv_result_t` | One variant per `TLV_ERR_*` code, plus `Unknown(code)`; implements `std::error::Error` |
| `Result<T>` | | Alias for `std::result::Result<T, Error>` |
| `ByteOrder` | `tlv_byte_order_t` | Byte order for numeric tag conversions |

`Tag::CAPACITY` mirrors the C `TLV_TAG_CAPACITY` (default 8). The layout of
`tlv_tag_t` is part of the C ABI, so the bindings only support a library built
with the default capacity.

## Reader

`Reader<'a>` parses a `&'a [u8]` and iterates over `Result<Entry<'a>>`. It wraps
the C `tlv_reader_t`; entry values are zero-copy slices of the input, and the
borrow checker keeps the input alive for as long as the reader or any entry.

```rust
let reader = opentlv::Reader::new(&data);

for entry in reader {
    let entry = entry?;
    println!("{:?}: {:?}", entry.tag(), entry.value());
}
```

`Reader::new` uses the default format (one-byte tag, definite BER length);
`Reader::with_format` takes a `Format` (`Default`, `Ber`, `Cer`, `Der`,
`Fixed1Byte`). Malformed input yields an `Err(Error)` item, after which the
iterator ends, since the C reader does not advance past bad data. Library users
need no `unsafe`.

## Writer

`Writer<'a>` encodes entries into a caller-owned `&'a mut [u8]`. It wraps the C
`tlv_writer_t` and never allocates. Tags are `Tag`s and values are `&[u8]`.

```rust
let mut buf = [0u8; 64];
let mut writer = opentlv::Writer::new(&mut buf);
writer.write(&opentlv::Tag::from_bytes(&[0x01])?, b"abc")?;
let encoded: &[u8] = writer.written();
```

`Writer::with_format` takes the same `Format` as the reader. `write_entry`
appends an `Entry` (for example one produced by a `Reader`), `position`,
`remaining` and `capacity` report buffer usage, and `finish` returns the written
bytes with the buffer's lifetime. `encoded_size` computes the size of an entry
without writing it. Failures use the common `Error`; an entry that does not fit
gives `Error::BufferTooShort` and leaves the position unchanged. Library users
need no `unsafe`.

## Schemas

Both schema types wrap the C library's tables; validation runs in C.

| Type | Wraps | Purpose |
| --- | --- | --- |
| `LengthSchema` | `tlv_schema_t` | Per-tag length rules: `find` and `validate_length` |
| `StructureSchema` | `tlv_structure_schema_t` | Required, optional, duplicate, kind and child-membership rules for a whole buffer |

`LengthSchema::new` and `StructureSchema::new` build owned tables from
`LengthRule` and `StructureRule` values; `LengthSchema::emv`,
`LengthSchema::emv_for` and `StructureSchema::emv` return the built-in EMV
schemas. `StructureSchema::validate` takes the data, a `Format` (which decides
which tags are constructed) and `ValidationLimits`, and returns
`Result<(), SchemaError>`. `SchemaError` carries the C `Error`
(`Schema`, `SchemaMissing`, `InvalidLength`, `Limit`, ...) and the failing
offset.

```rust
let tag = opentlv::Tag::from_bytes(&[0x84])?;
let schema = opentlv::StructureSchema::new(
    [opentlv::StructureRule::new(tag).length(5, 16).required_once()],
    false,
);
schema.validate(&data, opentlv::Format::Ber, &opentlv::ValidationLimits::default())?;
```

## Codecs and the EMV dictionary

`Codec` converts a raw value to a typed `Value` (`Number`, `Flags`, `Digits`,
`Date`, `Time`, `Afl`, `Track2`, ...) with `decode`, and back with `encode`,
`encode_into` and `encoded_size`. Errors use `CodecError`, mapped from
`tlv_codec_result_t`, which is separate from the framing `Error`. `Codec::amount`
is the amount codec; every other codec comes from the EMV dictionary:

```rust
use opentlv::emv::{self, Context};

let tag = opentlv::Tag::from_bytes(&[0x9A])?;
let definition = emv::find(Context::Base, &tag).unwrap();
let date = definition.codec().unwrap().decode(&[0x25, 0x12, 0x31])?;
```

`emv::find` returns a `Definition` (name, `ValueKind`, length bounds and step,
`validate_length`, optional `Codec`); `Context::child` follows template
contexts. Opaque bytes, text and templates have no codec; use the reader's
borrowed value.

## Profiles and formats

`Format` (`Default`, `Ber`, `Cer`, `Der`, `Fixed1Byte`) selects the wire
encoding; it implements `FromStr` and `Display` for names such as `"der"`.
`Profile` (`Der`, `Cer`) adds canonical-encoding checks and resource `Limits`
on top of the format: `validate`, `read`, `encoded_size` and `write`, each with
a `Strictness` (`Canonical` or `Strict`, which also validates UNIVERSAL
content). Failures are `ProfileError` values with the failing offset.

The DOL profile and the callback-based visitors and structure codecs of the C
API are not bound yet.

## Build

Requirements: a Rust toolchain (1.70 or newer), CMake 3.16 or newer and a C99
compiler. On Windows use the MSVC Rust toolchain with Visual Studio.

```sh
cd bindings/rust
cargo build
cargo test
```

By default the build script configures and builds the OpenTLV C library from the
repository root with CMake, as a static Release library inside Cargo's `target`
directory, and links it. The C++ layer, CLI, tests and examples are not built.

The build script passes no `OPENTLV_FORMAT_*` or `OPENTLV_PROFILE_*` options, so the
C library is built with its default components, all built-in formats and profiles. The
crates define no Cargo features for selecting components. Choosing components from Cargo
(the [include only what you need](../concepts/architecture.md#include-only-what-you-need)
rule) is not implemented yet.

## Continuous integration and quality checks

The [Rust Bindings workflow](https://github.com/marekcingel/OpenTLV/blob/main/.github/workflows/rust.yml)
runs on every push and pull request to `main` and fails on any of:

- `cargo fmt --all --check`, formatting differs from rustfmt;
- `cargo clippy --workspace --all-targets -- -D warnings`, any clippy or
  compiler warning;
- `cargo build` and `cargo test` on Linux, Windows and macOS, with warnings
  denied.

Run the same checks locally from `bindings/rust`:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

`opentlv/tests/corpus.rs` replays the C fuzz seeds in `tests/fuzz/corpus`
through the safe API (reader on every format, DER and CER profiles, writer and
reader round trips, every EMV codec), so seeds added for the C harnesses also
cover the bindings without being copied.

## Linking a prebuilt library

To link a library you built yourself, point `OPENTLV_LIB_DIR` at the directory
containing it:

```sh
OPENTLV_LIB_DIR=/path/to/build/tlv cargo build
```

`OPENTLV_LINK_KIND` selects `static` or `dylib` (default `dylib`, matching the
default CMake build). With a shared library, the platform's loader must find it
at run time (`PATH` on Windows, `LD_LIBRARY_PATH` on Linux, `DYLD_LIBRARY_PATH`
on macOS).
