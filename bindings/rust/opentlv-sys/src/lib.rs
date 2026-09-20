//! Raw, unsafe FFI bindings to the OpenTLV C API.
//!
//! This crate is the only place in the Rust bindings that declares `extern "C"`
//! items. Prefer the safe `opentlv` crate unless you need the C API directly.
//! Only the part of the C API needed by the safe crate is declared so far.

#![allow(non_camel_case_types)]

use std::os::raw::{c_char, c_int};

/// Logical TLV value length (`tlv_length_t`), always 64 bits wide.
pub type tlv_length_t = u64;

/// Result code returned by fallible OpenTLV functions (`tlv_result_t`).
/// Zero is success.
pub type tlv_result_t = c_int;

/// The operation succeeded (`TLV_OK`).
pub const TLV_OK: tlv_result_t = 0;
/// A supplied buffer is too small (`TLV_ERR_BUFFER_TOO_SHORT`).
pub const TLV_ERR_BUFFER_TOO_SHORT: tlv_result_t = 1;
/// A length is malformed or out of range (`TLV_ERR_INVALID_LENGTH`).
pub const TLV_ERR_INVALID_LENGTH: tlv_result_t = 2;
/// A required pointer argument is `NULL` (`TLV_ERR_NULL_ARG`).
pub const TLV_ERR_NULL_ARG: tlv_result_t = 3;
/// An allocation failed (`TLV_ERR_OUT_OF_MEMORY`).
pub const TLV_ERR_OUT_OF_MEMORY: tlv_result_t = 4;
/// No further element exists, or the input is empty (`TLV_ERR_END_OF_BUFFER`).
pub const TLV_ERR_END_OF_BUFFER: tlv_result_t = 5;
/// A tag is malformed or invalid (`TLV_ERR_INVALID_TAG`).
pub const TLV_ERR_INVALID_TAG: tlv_result_t = 6;
/// A visitor callback requested an error stop (`TLV_ERR_VISITOR`).
pub const TLV_ERR_VISITOR: tlv_result_t = 7;
/// A configured limit was exceeded (`TLV_ERR_LIMIT`).
pub const TLV_ERR_LIMIT: tlv_result_t = 8;
/// Input violates a schema rule (`TLV_ERR_SCHEMA`).
pub const TLV_ERR_SCHEMA: tlv_result_t = 9;
/// An argument has an invalid value (`TLV_ERR_INVALID_ARG`).
pub const TLV_ERR_INVALID_ARG: tlv_result_t = 10;
/// Tag size is outside the supported range (`TLV_ERR_INVALID_TAG_SIZE`).
pub const TLV_ERR_INVALID_TAG_SIZE: tlv_result_t = 11;
/// Byte order is unknown or unsupported (`TLV_ERR_INVALID_BYTE_ORDER`).
pub const TLV_ERR_INVALID_BYTE_ORDER: tlv_result_t = 12;
/// A value does not fit the requested width (`TLV_ERR_OVERFLOW`).
pub const TLV_ERR_OVERFLOW: tlv_result_t = 13;
/// Primitive content is malformed (`TLV_ERR_INVALID_VALUE`).
pub const TLV_ERR_INVALID_VALUE: tlv_result_t = 14;
/// A universal tag has no implemented validation (`TLV_ERR_UNSUPPORTED_TYPE`).
pub const TLV_ERR_UNSUPPORTED_TYPE: tlv_result_t = 15;
/// A required schema field is absent (`TLV_ERR_SCHEMA_MISSING`).
pub const TLV_ERR_SCHEMA_MISSING: tlv_result_t = 16;

/// Byte order of a multi-byte integer (`tlv_byte_order_t`).
pub type tlv_byte_order_t = c_int;
/// Unknown byte order, rejected by the library (`TLV_BYTE_ORDER_UNKNOWN`).
pub const TLV_BYTE_ORDER_UNKNOWN: tlv_byte_order_t = 0;
/// Most significant byte first (`TLV_BYTE_ORDER_BIG_ENDIAN`).
pub const TLV_BYTE_ORDER_BIG_ENDIAN: tlv_byte_order_t = 1;
/// Least significant byte first (`TLV_BYTE_ORDER_LITTLE_ENDIAN`).
pub const TLV_BYTE_ORDER_LITTLE_ENDIAN: tlv_byte_order_t = 2;

/// Inline tag storage capacity in bytes (`TLV_TAG_CAPACITY`, default 8).
///
/// This is part of the C ABI: it must match the capacity the C library was
/// built with.
pub const TLV_TAG_CAPACITY: usize = 8;

/// A raw TLV tag with inline storage (`tlv_tag_t`).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct tlv_tag_t {
    /// Tag bytes in wire order.
    pub data: [u8; TLV_TAG_CAPACITY],
    /// Number of valid bytes in `data`.
    pub size: u8,
}

/// A non-owning view of a TLV value (`tlv_value_t`).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct tlv_value_t {
    /// Borrowed value bytes; may be null only when `length` is zero.
    pub data: *const u8,
    /// Value length in bytes.
    pub length: tlv_length_t,
}

/// A decoded TLV element: an inline tag and a borrowed value (`tlv_view_t`).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct tlv_view_t {
    /// Element tag.
    pub tag: tlv_tag_t,
    /// Element value.
    pub value: tlv_value_t,
}

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
    /// Narrows a length to the native `size_t`.
    pub fn tlv_length_to_size(length: tlv_length_t, size: *mut usize) -> tlv_result_t;
    /// Constructs a tag from raw bytes.
    pub fn tlv_tag_from_bytes(data: *const u8, size: usize, tag: *mut tlv_tag_t) -> tlv_result_t;
    /// Constructs a tag of `size` bytes from a 64-bit value.
    pub fn tlv_tag_from_u64(
        value: u64,
        size: usize,
        order: tlv_byte_order_t,
        tag: *mut tlv_tag_t,
    ) -> tlv_result_t;
    /// Converts a tag of 1..8 bytes to a 64-bit value.
    pub fn tlv_tag_to_u64(
        tag: *const tlv_tag_t,
        order: tlv_byte_order_t,
        value: *mut u64,
    ) -> tlv_result_t;
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
