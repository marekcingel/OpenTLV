//! The DER and CER profiles: strict, limit-bounded validation and canonical
//! writing of ASN.1 encodings.
//!
//! Unlike the plain [`Format`]s, which only frame elements, a [`Profile`]
//! enforces canonical-encoding rules and resource [`Limits`]. All checks run in
//! the C library.

use std::error;
use std::fmt;
use std::mem::MaybeUninit;
use std::ptr;

use opentlv_native as native;

use crate::entry::Entry;
use crate::error::Error;
use crate::format::Format;
use crate::tag::Tag;

/// An ASN.1 encoding profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Profile {
    /// Distinguished Encoding Rules.
    Der,
    /// Canonical Encoding Rules.
    Cer,
}

/// How much of the content a [`Profile`] checks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Strictness {
    /// Check framing, tags and lengths against the profile's canonical rules.
    #[default]
    Canonical,
    /// Additionally validate the content of every UNIVERSAL-class element
    /// against the ASN.1 canonical rules for its type.
    Strict,
}

/// Inclusive resource limits for a [`Profile`]. Zero is a real limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Limits {
    /// Maximum number of constructed ancestors, at most 64.
    pub max_depth: usize,
    /// Bounds the supplied input, or the complete encoded output when writing.
    pub max_input_size: usize,
    /// Bounds each value.
    pub max_value_size: usize,
    /// Bounds the total visited elements.
    pub max_elements: usize,
}

/// A failed profile operation: the error and where it happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProfileError {
    /// The error reported by the C library.
    pub error: Error,
    /// Offset of the failing tag, length or value field, relative to the input
    /// (or to the would-be output when writing); 0 for argument and
    /// input-limit errors.
    pub offset: usize,
}

impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at offset {}", self.error, self.offset)
    }
}

impl error::Error for ProfileError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        Some(&self.error)
    }
}

impl From<ProfileError> for Error {
    fn from(err: ProfileError) -> Error {
        err.error
    }
}

impl Limits {
    fn der(&self) -> native::tlv_der_limits_t {
        native::tlv_der_limits_t {
            max_depth: self.max_depth,
            max_input_size: self.max_input_size,
            max_value_size: self.max_value_size,
            max_elements: self.max_elements,
        }
    }

    fn cer(&self) -> native::tlv_cer_limits_t {
        native::tlv_cer_limits_t {
            max_depth: self.max_depth,
            max_input_size: self.max_input_size,
            max_value_size: self.max_value_size,
            max_elements: self.max_elements,
        }
    }
}

fn outcome(code: native::tlv_result_t, offset: usize) -> Result<(), ProfileError> {
    match Error::from_code(code) {
        None => Ok(()),
        Some(error) => Err(ProfileError { error, offset }),
    }
}

impl Profile {
    /// Every supported profile.
    pub const ALL: [Profile; 2] = [Profile::Der, Profile::Cer];

    /// Returns the [`Format`] that frames elements of this profile.
    pub fn format(self) -> Format {
        match self {
            Profile::Der => Format::Der,
            Profile::Cer => Format::Cer,
        }
    }

    /// Returns the library's default limits for this profile.
    pub fn default_limits(self) -> Limits {
        // SAFETY: reads an immutable static of plain integers.
        unsafe {
            match self {
                Profile::Der => {
                    let l = ptr::addr_of!(native::tlv_der_default_limits).read();
                    Limits {
                        max_depth: l.max_depth,
                        max_input_size: l.max_input_size,
                        max_value_size: l.max_value_size,
                        max_elements: l.max_elements,
                    }
                }
                Profile::Cer => {
                    let l = ptr::addr_of!(native::tlv_cer_default_limits).read();
                    Limits {
                        max_depth: l.max_depth,
                        max_input_size: l.max_input_size,
                        max_value_size: l.max_value_size,
                        max_elements: l.max_elements,
                    }
                }
            }
        }
    }

    /// Validates all concatenated elements of `data`, recursively. Empty input
    /// is valid.
    ///
    /// # Errors
    ///
    /// A [`ProfileError`]: [`Error::Limit`] if a limit is exceeded,
    /// [`Error::InvalidValue`] or [`Error::UnsupportedType`] for content that
    /// fails [`Strictness::Strict`], or another error for malformed or
    /// noncanonical input.
    ///
    /// ```
    /// use opentlv::{Limits, Profile, Strictness};
    ///
    /// let limits = Profile::Der.default_limits();
    /// // INTEGER 5, then the same element with a non-minimal length.
    /// assert!(Profile::Der.validate(&[0x02, 0x01, 0x05], &limits, Strictness::Canonical).is_ok());
    /// assert!(Profile::Der.validate(&[0x02, 0x81, 0x01, 0x05], &limits, Strictness::Canonical).is_err());
    /// ```
    pub fn validate(
        self,
        data: &[u8],
        limits: &Limits,
        strictness: Strictness,
    ) -> Result<(), ProfileError> {
        let mut offset = 0usize;
        let (ptr, len) = (data.as_ptr(), data.len());
        let no_context = ptr::null_mut();
        // SAFETY: `data` is a valid slice, the limits are valid for the call,
        // there is no visitor, and `offset` is a writable `usize`.
        let code = unsafe {
            match (self, strictness) {
                (Profile::Der, Strictness::Canonical) => {
                    native::tlv_der_walk(ptr, len, &limits.der(), None, no_context, &mut offset)
                }
                (Profile::Der, Strictness::Strict) => native::tlv_der_walk_strict(
                    ptr,
                    len,
                    &limits.der(),
                    None,
                    no_context,
                    &mut offset,
                ),
                (Profile::Cer, Strictness::Canonical) => {
                    native::tlv_cer_walk(ptr, len, &limits.cer(), None, no_context, &mut offset)
                }
                (Profile::Cer, Strictness::Strict) => native::tlv_cer_walk_strict(
                    ptr,
                    len,
                    &limits.cer(),
                    None,
                    no_context,
                    &mut offset,
                ),
            }
        };
        outcome(code, offset)
    }

    /// Validates the first complete element of `data` and returns it with the
    /// number of bytes it occupies. Trailing bytes are ignored.
    ///
    /// The returned entry's value borrows `data`.
    ///
    /// # Errors
    ///
    /// Same as [`Profile::validate`], plus [`Error::EndOfBuffer`] for empty
    /// input.
    pub fn read<'a>(
        self,
        data: &'a [u8],
        limits: &Limits,
        strictness: Strictness,
    ) -> Result<(Entry<'a>, usize), ProfileError> {
        let mut view = MaybeUninit::<native::tlv_view_t>::uninit();
        let mut consumed = 0usize;
        let mut offset = 0usize;
        let (ptr, len) = (data.as_ptr(), data.len());
        let out = view.as_mut_ptr();
        // SAFETY: `data` is a valid slice, the limits are valid for the call,
        // and `out`, `consumed` and `offset` are writable.
        let code = unsafe {
            match (self, strictness) {
                (Profile::Der, Strictness::Canonical) => {
                    native::tlv_der_read(ptr, len, &limits.der(), out, &mut consumed, &mut offset)
                }
                (Profile::Der, Strictness::Strict) => native::tlv_der_read_strict(
                    ptr,
                    len,
                    &limits.der(),
                    out,
                    &mut consumed,
                    &mut offset,
                ),
                (Profile::Cer, Strictness::Canonical) => {
                    native::tlv_cer_read(ptr, len, &limits.cer(), out, &mut consumed, &mut offset)
                }
                (Profile::Cer, Strictness::Strict) => native::tlv_cer_read_strict(
                    ptr,
                    len,
                    &limits.cer(),
                    out,
                    &mut consumed,
                    &mut offset,
                ),
            }
        };
        outcome(code, offset)?;
        // SAFETY: the read succeeded, so `view` is initialized and its value
        // borrows `data`, which lives for `'a`.
        let entry = unsafe { Entry::from_raw(&view.assume_init()) }
            .map_err(|error| ProfileError { error, offset: 0 })?;
        Ok((entry, consumed))
    }

    fn write_raw(
        self,
        tag: &Tag,
        value: &[u8],
        limits: &Limits,
        strictness: Strictness,
        data: *mut u8,
        capacity: usize,
    ) -> Result<usize, ProfileError> {
        let mut written = 0usize;
        let mut offset = 0usize;
        let (vptr, vlen) = (value.as_ptr(), value.len());
        // SAFETY: `data` is null with zero capacity (a size query) or a
        // writable buffer of `capacity` bytes; `value` is a valid slice that
        // does not overlap it; the limits are valid for the call; `written`
        // and `offset` are writable.
        let code = unsafe {
            match (self, strictness) {
                (Profile::Der, Strictness::Canonical) => native::tlv_der_write(
                    data,
                    capacity,
                    tag.raw(),
                    vptr,
                    vlen,
                    &limits.der(),
                    &mut written,
                    &mut offset,
                ),
                (Profile::Der, Strictness::Strict) => native::tlv_der_write_strict(
                    data,
                    capacity,
                    tag.raw(),
                    vptr,
                    vlen,
                    &limits.der(),
                    &mut written,
                    &mut offset,
                ),
                (Profile::Cer, Strictness::Canonical) => native::tlv_cer_write(
                    data,
                    capacity,
                    tag.raw(),
                    vptr,
                    vlen,
                    &limits.cer(),
                    &mut written,
                    &mut offset,
                ),
                (Profile::Cer, Strictness::Strict) => native::tlv_cer_write_strict(
                    data,
                    capacity,
                    tag.raw(),
                    vptr,
                    vlen,
                    &limits.cer(),
                    &mut written,
                    &mut offset,
                ),
            }
        };
        outcome(code, offset)?;
        Ok(written)
    }

    /// Validates an element and returns the size of its canonical encoding
    /// without writing it.
    ///
    /// # Errors
    ///
    /// A [`ProfileError`] for an invalid tag, value or child.
    pub fn encoded_size(
        self,
        tag: &Tag,
        value: &[u8],
        limits: &Limits,
        strictness: Strictness,
    ) -> Result<usize, ProfileError> {
        self.write_raw(tag, value, limits, strictness, ptr::null_mut(), 0)
    }

    /// Writes one canonical element into `out` and returns the number of bytes
    /// written.
    ///
    /// The value is copied verbatim; the value of a constructed element must
    /// already hold canonical children, which are validated first.
    ///
    /// # Errors
    ///
    /// [`Error::BufferTooShort`] if `out` is too small, or another
    /// [`ProfileError`] for an invalid tag, value or child.
    ///
    /// ```
    /// use opentlv::{Profile, Strictness, Tag};
    ///
    /// let mut out = [0u8; 8];
    /// let tag = Tag::from_bytes(&[0x04]); // OCTET STRING
    /// let limits = Profile::Der.default_limits();
    /// let n = Profile::Der.write(&tag, &[0xAB], &limits, Strictness::Strict, &mut out).unwrap();
    /// assert_eq!(&out[..n], &[0x04, 0x01, 0xAB]);
    /// ```
    pub fn write(
        self,
        tag: &Tag,
        value: &[u8],
        limits: &Limits,
        strictness: Strictness,
        out: &mut [u8],
    ) -> Result<usize, ProfileError> {
        self.write_raw(tag, value, limits, strictness, out.as_mut_ptr(), out.len())
    }
}
