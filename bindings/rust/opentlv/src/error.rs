//! Error type mapped from OpenTLV result codes.

use std::error;
use std::ffi::CStr;
use std::fmt;

use opentlv_sys as sys;

/// An OpenTLV error, mapped from a non-zero `tlv_result_t`.
///
/// Variants mirror the C `TLV_ERR_*` codes. A code this crate does not know
/// (for example one added by a newer C library) is preserved as
/// [`Error::Unknown`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Error {
    /// A supplied buffer is too small for the data or output required.
    BufferTooShort,
    /// A length is malformed, out of range, or not representable as `usize`.
    InvalidLength,
    /// A required pointer argument is `NULL`.
    NullArg,
    /// An allocation failed.
    OutOfMemory,
    /// No further element exists, or the input is empty.
    EndOfBuffer,
    /// A tag is malformed or invalid for the format or profile.
    InvalidTag,
    /// A visitor callback requested an error stop.
    Visitor,
    /// A configured depth, size, or element-count limit was exceeded.
    Limit,
    /// Input violates a schema rule.
    Schema,
    /// An argument has an invalid value that no more specific code describes.
    InvalidArg,
    /// Tag size violates the range supported by the operation.
    InvalidTagSize,
    /// Byte order is unknown or unsupported.
    InvalidByteOrder,
    /// An unsigned value cannot fit the requested numeric width.
    Overflow,
    /// Universal primitive content is malformed or fails a canonical rule.
    InvalidValue,
    /// A universal tag number has no implemented canonical validation.
    UnsupportedType,
    /// A required schema field is absent.
    SchemaMissing,
    /// A result code not known to this crate; carries the raw code.
    Unknown(i32),
}

/// Result type used by all fallible OpenTLV operations.
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Maps a raw `tlv_result_t` to an error, or `None` for success (`TLV_OK`).
    pub fn from_code(code: i32) -> Option<Error> {
        Some(match code {
            sys::TLV_OK => return None,
            sys::TLV_ERR_BUFFER_TOO_SHORT => Error::BufferTooShort,
            sys::TLV_ERR_INVALID_LENGTH => Error::InvalidLength,
            sys::TLV_ERR_NULL_ARG => Error::NullArg,
            sys::TLV_ERR_OUT_OF_MEMORY => Error::OutOfMemory,
            sys::TLV_ERR_END_OF_BUFFER => Error::EndOfBuffer,
            sys::TLV_ERR_INVALID_TAG => Error::InvalidTag,
            sys::TLV_ERR_VISITOR => Error::Visitor,
            sys::TLV_ERR_LIMIT => Error::Limit,
            sys::TLV_ERR_SCHEMA => Error::Schema,
            sys::TLV_ERR_INVALID_ARG => Error::InvalidArg,
            sys::TLV_ERR_INVALID_TAG_SIZE => Error::InvalidTagSize,
            sys::TLV_ERR_INVALID_BYTE_ORDER => Error::InvalidByteOrder,
            sys::TLV_ERR_OVERFLOW => Error::Overflow,
            sys::TLV_ERR_INVALID_VALUE => Error::InvalidValue,
            sys::TLV_ERR_UNSUPPORTED_TYPE => Error::UnsupportedType,
            sys::TLV_ERR_SCHEMA_MISSING => Error::SchemaMissing,
            other => Error::Unknown(other),
        })
    }

    /// Returns the raw `tlv_result_t` code of this error.
    pub fn code(self) -> i32 {
        match self {
            Error::BufferTooShort => sys::TLV_ERR_BUFFER_TOO_SHORT,
            Error::InvalidLength => sys::TLV_ERR_INVALID_LENGTH,
            Error::NullArg => sys::TLV_ERR_NULL_ARG,
            Error::OutOfMemory => sys::TLV_ERR_OUT_OF_MEMORY,
            Error::EndOfBuffer => sys::TLV_ERR_END_OF_BUFFER,
            Error::InvalidTag => sys::TLV_ERR_INVALID_TAG,
            Error::Visitor => sys::TLV_ERR_VISITOR,
            Error::Limit => sys::TLV_ERR_LIMIT,
            Error::Schema => sys::TLV_ERR_SCHEMA,
            Error::InvalidArg => sys::TLV_ERR_INVALID_ARG,
            Error::InvalidTagSize => sys::TLV_ERR_INVALID_TAG_SIZE,
            Error::InvalidByteOrder => sys::TLV_ERR_INVALID_BYTE_ORDER,
            Error::Overflow => sys::TLV_ERR_OVERFLOW,
            Error::InvalidValue => sys::TLV_ERR_INVALID_VALUE,
            Error::UnsupportedType => sys::TLV_ERR_UNSUPPORTED_TYPE,
            Error::SchemaMissing => sys::TLV_ERR_SCHEMA_MISSING,
            Error::Unknown(code) => code,
        }
    }

    /// Converts a raw result code into `Ok(())` or the matching error.
    pub(crate) fn check(code: sys::tlv_result_t) -> Result<()> {
        match Error::from_code(code) {
            None => Ok(()),
            Some(error) => Err(error),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // SAFETY: `tlv_strerror` never returns NULL; it returns a static,
        // NUL-terminated string for every input.
        let message = unsafe { CStr::from_ptr(sys::tlv_strerror(self.code())) };
        f.write_str(&message.to_string_lossy())
    }
}

impl error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    const KNOWN: [(i32, Error); 16] = [
        (1, Error::BufferTooShort),
        (2, Error::InvalidLength),
        (3, Error::NullArg),
        (4, Error::OutOfMemory),
        (5, Error::EndOfBuffer),
        (6, Error::InvalidTag),
        (7, Error::Visitor),
        (8, Error::Limit),
        (9, Error::Schema),
        (10, Error::InvalidArg),
        (11, Error::InvalidTagSize),
        (12, Error::InvalidByteOrder),
        (13, Error::Overflow),
        (14, Error::InvalidValue),
        (15, Error::UnsupportedType),
        (16, Error::SchemaMissing),
    ];

    #[test]
    fn success_maps_to_none() {
        assert_eq!(Error::from_code(0), None);
        assert_eq!(Error::check(0), Ok(()));
    }

    #[test]
    fn every_known_code_round_trips() {
        for (code, error) in KNOWN {
            assert_eq!(Error::from_code(code), Some(error));
            assert_eq!(error.code(), code);
            assert_eq!(Error::check(code), Err(error));
        }
    }

    #[test]
    fn unknown_code_is_preserved() {
        assert_eq!(Error::from_code(999), Some(Error::Unknown(999)));
        assert_eq!(Error::Unknown(-5).code(), -5);
    }

    #[test]
    fn display_uses_the_c_description() {
        for (_, error) in KNOWN {
            let text = error.to_string();
            assert!(!text.is_empty());
            assert_ne!(text, "unknown error", "{error:?}");
        }
        assert_eq!(Error::Unknown(999).to_string(), "unknown error");
    }

    #[test]
    fn implements_std_error() {
        fn assert_error<E: std::error::Error + Send + Sync + 'static>() {}
        assert_error::<Error>();
    }
}
