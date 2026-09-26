//! Wire formats shared by the reader and the writer.

use std::fmt;
use std::ptr;
use std::str::FromStr;

use opentlv_native as native;

use crate::error::Error;

/// The wire format a [`Reader`](crate::Reader), [`Writer`](crate::Writer) or
/// [`StructureSchema`](crate::StructureSchema) uses.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Format {
    /// One-byte tag and a definite BER length.
    #[default]
    Default,
    /// BER-TLV.
    Ber,
    /// Canonical Encoding Rules.
    Cer,
    /// Distinguished Encoding Rules.
    Der,
}

impl Format {
    /// Every supported format.
    pub const ALL: [Format; 4] = [Format::Default, Format::Ber, Format::Cer, Format::Der];

    /// Returns the lowercase name of the format, accepted by [`FromStr`].
    pub fn name(self) -> &'static str {
        match self {
            Format::Default => "default",
            Format::Ber => "ber",
            Format::Cer => "cer",
            Format::Der => "der",
        }
    }

    /// Returns the nesting predicate of the format, or `None` if the format
    /// has no constructed values (every value is opaque).
    pub(crate) fn is_constructed_raw(self) -> Option<native::tlv_is_constructed_fn> {
        match self {
            Format::Ber => Some(native::tlv_ber_is_constructed),
            Format::Cer => Some(native::tlv_cer_is_constructed),
            Format::Der => Some(native::tlv_der_is_constructed),
            Format::Default => None,
        }
    }

    pub(crate) fn reader_raw(self) -> *const native::tlv_reader_format_t {
        // SAFETY: only the address of an immutable static is taken; the
        // static lives for the whole program and is never written. Newer
        // compilers treat this as safe, but the MSRV (1.70) needs `unsafe`.
        #[allow(unused_unsafe)]
        unsafe {
            match self {
                Format::Default => ptr::addr_of!(native::tlv_reader_format_default),
                Format::Ber => ptr::addr_of!(native::tlv_reader_format_ber),
                Format::Cer => ptr::addr_of!(native::tlv_reader_format_cer),
                Format::Der => ptr::addr_of!(native::tlv_reader_format_der),
            }
        }
    }

    pub(crate) fn writer_raw(self) -> *const native::tlv_writer_format_t {
        // SAFETY: only the address of an immutable static is taken; the
        // static lives for the whole program and is never written. Newer
        // compilers treat this as safe, but the MSRV (1.70) needs `unsafe`.
        #[allow(unused_unsafe)]
        unsafe {
            match self {
                Format::Default => ptr::addr_of!(native::tlv_writer_format_default),
                Format::Ber => ptr::addr_of!(native::tlv_writer_format_ber),
                Format::Cer => ptr::addr_of!(native::tlv_writer_format_cer),
                Format::Der => ptr::addr_of!(native::tlv_writer_format_der),
            }
        }
    }
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for Format {
    type Err = Error;

    /// Parses a format name as returned by [`Format::name`], ignoring case.
    ///
    /// Fails with [`Error::InvalidArg`] for an unknown name.
    fn from_str(s: &str) -> Result<Format, Error> {
        Format::ALL
            .into_iter()
            .find(|format| format.name().eq_ignore_ascii_case(s))
            .ok_or(Error::InvalidArg)
    }
}
