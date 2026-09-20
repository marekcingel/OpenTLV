# Rust bindings (experimental)

The Rust bindings live in `bindings/rust/`, a Cargo workspace with two crates:

| Crate | Purpose |
| --- | --- |
| `opentlv-sys` | Raw `extern "C"` declarations of the OpenTLV C API and the build script that links the C library |
| `opentlv` | Safe Rust API built on `opentlv-sys` |

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
