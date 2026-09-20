//! Raw, unsafe FFI bindings to the OpenTLV C API.
//!
//! This crate is the only place in the Rust bindings that declares `extern "C"`
//! items. Prefer the safe `opentlv` crate unless you need the C API directly.
//! Only a small part of the C API is declared so far.

#![allow(non_camel_case_types)]

use std::os::raw::{c_char, c_int};

/// Result code returned by fallible OpenTLV functions (`tlv_result_t`).
/// Zero is success.
pub type tlv_result_t = c_int;

/// The operation succeeded (`TLV_OK`).
pub const TLV_OK: tlv_result_t = 0;

extern "C" {
    /// Returns the library version as a NUL-terminated static string, for example `"0.6.0"`.
    pub fn tlv_version_string() -> *const c_char;
    /// Returns the major version number.
    pub fn tlv_version_major() -> u32;
    /// Returns the minor version number.
    pub fn tlv_version_minor() -> u32;
    /// Returns the patch version number.
    pub fn tlv_version_patch() -> u32;
    /// Returns a NUL-terminated static description of a result code.
    pub fn tlv_strerror(result: tlv_result_t) -> *const c_char;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[test]
    fn links_and_reports_version() {
        let version = unsafe { CStr::from_ptr(tlv_version_string()) }
            .to_str()
            .unwrap();
        let expected = unsafe {
            format!("{}.{}.{}", tlv_version_major(), tlv_version_minor(), tlv_version_patch())
        };
        assert!(version.starts_with(&expected), "{version} vs {expected}");
    }

    #[test]
    fn strerror_describes_ok() {
        let message = unsafe { CStr::from_ptr(tlv_strerror(TLV_OK)) };
        assert!(!message.to_bytes().is_empty());
    }
}
