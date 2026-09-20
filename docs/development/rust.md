# Rust bindings (experimental)

The Rust bindings live in `bindings/rust/`, a Cargo workspace with two crates:

| Crate | Purpose |
| --- | --- |
| `opentlv-sys` | Raw `extern "C"` declarations of the OpenTLV C API and the build script that links the C library |
| `opentlv` | Safe Rust API built on `opentlv-sys` |

All `unsafe` FFI interaction is isolated in `opentlv-sys`; `opentlv` contains no
`extern` declarations. So far only the version functions and `tlv_strerror` are
bound, and `opentlv::version()` is the first safe function.

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
