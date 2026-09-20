//! Safe Rust bindings for OpenTLV.
//!
//! All `unsafe` FFI interaction lives in `opentlv-sys`; this crate builds the
//! safe API on top of it. It provides the core types [`Tag`], [`Entry`],
//! [`Error`] and [`Result`], and reports the library version. No raw pointers
//! appear in the public API.

mod entry;
mod error;
mod tag;

pub use entry::Entry;
pub use error::{Error, Result};
pub use tag::{ByteOrder, Tag};

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
