# Using OpenTLV from Rust

The `opentlv` crate is an experimental safe Rust API over the OpenTLV C library.
This guide covers setup, reading, writing, error handling and ownership. For
crate layout, schemas, codecs, profiles and CI, see
[Rust bindings](../development/rust.md); every public item also has Rustdoc
(`cargo doc -p opentlv --open` from `bindings/rust`).

## Cargo setup

The crates are not published to crates.io yet. Depend on them by path from a
checkout of the repository:

```toml
[dependencies]
opentlv = { path = "OpenTLV/bindings/rust/opentlv" }
```

The build script of `opentlv-sys` builds the C library with CMake and links it,
so you need a Rust toolchain (1.70 or newer), CMake 3.16 or newer and a C99
compiler. To link a library you built yourself, set `OPENTLV_LIB_DIR` (and
optionally `OPENTLV_LINK_KIND`); see
[Linking a prebuilt library](../development/rust.md#linking-a-prebuilt-library).

## Reading

`Reader` iterates over `Result<Entry>`. Each `Entry` has a `Tag` and a value
that is a `&[u8]` slice of your input. Constructed entries are not expanded
automatically; create a new `Reader` over `entry.value()` to descend.

```rust
use opentlv::{Format, Reader};

for entry in Reader::with_format(&data, Format::Ber) {
    let entry = entry?;
    println!("{:02X?}: {:02X?}", entry.tag().as_bytes(), entry.value());
}
```

`Reader::new` uses the default format (one-byte tag, definite BER length).
Runnable version with nesting and EMV tag names:
[reader.rs](https://github.com/marekcingel/OpenTLV/blob/main/bindings/rust/opentlv/examples/reader.rs)
(`cargo run --example reader`).

## Writing

`Writer` encodes into a buffer you own and never allocates. To build a nested
structure, encode the children into one buffer and write them as the value of
the parent.

```rust
use opentlv::{Format, Tag, Writer};

let mut buf = [0u8; 64];
let mut writer = Writer::with_format(&mut buf, Format::Ber);
writer.write(&Tag::from_bytes(&[0x50]), b"VISA")?;
let encoded: &[u8] = writer.written();
```

Use `encoded_size` to size the buffer beforehand. Runnable version:
[writer.rs](https://github.com/marekcingel/OpenTLV/blob/main/bindings/rust/opentlv/examples/writer.rs)
(`cargo run --example writer`).

## Error handling

Every fallible call returns `opentlv::Result<T>`, an alias for
`Result<T, opentlv::Error>`. There are no panics on bad input and no
`unsafe` in caller code.

- `Error` has one variant per C `TLV_ERR_*` code and implements
  `std::error::Error` and `Display` (the text comes from C `tlv_strerror`), so
  it works with `?` and `Box<dyn Error>`. It is `#[non_exhaustive]`: a code from
  a newer C library becomes `Error::Unknown(code)`, and `code()` returns the raw
  value.
- `Reader` yields an `Err` item on malformed input and then ends; it does not
  skip ahead.
- `Writer::write` returns `Error::BufferTooShort` when the entry does not fit
  and leaves the position unchanged, so you can retry with a bigger buffer.
- Layers with more context use their own types: `SchemaError` and
  `ProfileError` carry the C `Error` plus the failing offset, and `CodecError`
  maps the separate `tlv_codec_result_t`.

## Ownership and lifetimes

| Type | Owns | Borrows |
| --- | --- | --- |
| `Tag` | its bytes (`Copy`) | nothing |
| `Entry<'a>` | its `Tag` | value `&'a [u8]` from the input |
| `Reader<'a>` | its cursor | the input `&'a [u8]` |
| `Writer<'a>` | its position | the output `&'a mut [u8]` |
| `LengthSchema`, `StructureSchema` | their rule tables | nothing |

- Entry values are zero-copy. `Reader<'a>` yields `Entry<'a>` tied to the
  input, not to the reader, so entries stay valid after the reader is dropped
  but not after the input is freed or mutated; the borrow checker enforces it.
  Copy with `to_vec()` when you need the bytes longer.
- While a `Writer` exists it holds the only `&mut` to its buffer. `written()`
  borrows the writer; `finish()` consumes it and returns the buffer with its
  full lifetime.
- `Tag` owns its bytes, while the C `tlv_tag_t` only borrows them. Reading an
  entry copies its tag out of the input, so a `Tag` stays valid after the input
  is gone; the value stays zero-copy.
- Schemas own their C tables, and the tags those tables borrow, and free them
  on `Drop`.
- The layout of `tlv_tag_t` is a pointer and a size, independent of any C build
  configuration, so the bindings work with a library built any way.

## Relationship to the C API

`opentlv-sys` declares the C functions as raw `extern "C"` items; `opentlv`
wraps them and contains no `extern` blocks. The wrappers call the C library for
all parsing, encoding, validation and codec work instead of reimplementing it,
so behavior matches the C API, and the C error codes map one to one onto
`Error`. What the safe API changes is memory handling: pointer and length pairs
become slices, initialization and `NULL` checks are done internally, and
lifetimes replace the borrowing rules the [C memory guide](memory.md)
documents. Parts of the C API that need callbacks (visitors, structure codecs,
the DOL profile) are not bound yet; see the [C API reference](../reference/c-api.md).
