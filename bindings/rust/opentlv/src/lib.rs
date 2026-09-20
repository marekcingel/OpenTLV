//! Safe Rust bindings for OpenTLV.
//!
//! All `unsafe` FFI interaction lives in `opentlv-sys`; this crate builds the
//! safe API on top of it. It provides the core types [`Tag`], [`Entry`],
//! [`Error`] and [`Result`], the [`Reader`] that parses TLV buffers, the
//! [`Writer`] that encodes them, and reports the library version. Higher-level
//! layers wrap the C library's implementation instead of reimplementing it:
//! [`LengthSchema`] and [`StructureSchema`] validate data, [`Codec`] converts
//! values to and from typed [`Value`]s, [`Profile`] enforces the DER and CER
//! canonical rules, and the [`emv`] module exposes the EMV dictionary. No raw
//! pointers appear in the public API.
//!
//! # Setup
//!
//! Add the crate by path from an OpenTLV checkout; the build script builds and
//! links the C library with CMake (see `docs/guides/rust.md`).
//!
//! ```toml
//! [dependencies]
//! opentlv = { path = "OpenTLV/bindings/rust/opentlv" }
//! ```
//!
//! # Reading and writing
//!
//! ```
//! use opentlv::{Format, Reader, Tag, Writer};
//!
//! # fn main() -> opentlv::Result<()> {
//! let mut buf = [0u8; 16];
//! let mut writer = Writer::with_format(&mut buf, Format::Ber);
//! writer.write(&Tag::from_bytes(&[0x50])?, b"VISA")?;
//!
//! for entry in Reader::with_format(writer.written(), Format::Ber) {
//!     let entry = entry?;
//!     assert_eq!(entry.tag().as_bytes(), [0x50]);
//!     assert_eq!(entry.value(), b"VISA");
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Complete programs are in the crate's `examples/` directory
//! (`cargo run --example reader`, `cargo run --example writer`).
//!
//! # Errors
//!
//! Fallible operations return [`Result`], whose error is [`Error`]: one variant
//! per C `TLV_ERR_*` code, [`Display`](std::fmt::Display)ed with the C
//! description. [`SchemaError`] and [`ProfileError`] add the failing offset and
//! [`CodecError`] maps the separate codec result codes. Malformed input never
//! panics. A [`Reader`] ends after its first error; a [`Writer`] that reports
//! [`Error::BufferTooShort`] keeps its position.
//!
//! # Ownership and lifetimes
//!
//! [`Tag`] is an owned `Copy` value. [`Reader<'a>`](Reader) borrows its input
//! and yields [`Entry<'a>`](Entry) values that are zero-copy slices of it, so
//! entries outlive the reader but not the input. [`Writer<'a>`](Writer)
//! exclusively borrows a caller-owned output buffer and never allocates.
//! Schemas own their C tables and free them on drop.
//!
//! # Relationship to the C API
//!
//! Every operation calls into the OpenTLV C library through `opentlv-sys`, so
//! behavior and error codes match the C API. The safe layer replaces pointer and
//! length pairs with slices and lifetimes. Callback-based visitors, structure
//! codecs and the DOL profile are not bound yet.

#![warn(missing_docs)]

mod codec;
mod entry;
mod error;
mod format;
mod profile;
mod reader;
mod schema;
mod tag;
mod writer;

pub mod emv;

pub use codec::{
    AccountType, AflEntry, BiometricType, Codec, CodecError, CodecResult, CryptogramInfo,
    CryptogramType, CvmResult, Date, Time, Track2, Value, ValueKind,
};
pub use entry::Entry;
pub use error::{Error, Result};
pub use format::Format;
pub use profile::{Limits, Profile, ProfileError, Strictness};
pub use reader::Reader;
pub use schema::{
    Kind, LengthRule, LengthSchema, SchemaError, StructureRule, StructureSchema, ValidationLimits,
};
pub use tag::{ByteOrder, Tag};
pub use writer::{encoded_size, Writer};

use std::ffi::CStr;

/// Returns the version of the linked OpenTLV C library, for example `"0.6.0"`.
pub fn version() -> &'static str {
    // SAFETY: `tlv_version_string` returns a pointer to a static,
    // NUL-terminated ASCII string that is valid for the program's lifetime.
    unsafe { CStr::from_ptr(opentlv_sys::tlv_version_string()) }
        .to_str()
        .expect("OpenTLV version string is ASCII")
}

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_not_empty() {
        assert!(!super::version().is_empty());
    }
}
