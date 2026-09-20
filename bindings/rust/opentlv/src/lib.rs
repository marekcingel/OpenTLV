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
