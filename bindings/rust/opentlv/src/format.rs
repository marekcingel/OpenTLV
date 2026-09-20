//! Wire formats shared by the reader and the writer.

use std::fmt;
use std::ptr;
use std::str::FromStr;

use opentlv_sys as sys;

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
    /// One-byte tag and one-byte length.
    Fixed1Byte,
}

impl Format {
    /// Every supported format.
    pub const ALL: [Format; 5] = [
        Format::Default,
        Format::Ber,
        Format::Cer,
        Format::Der,
        Format::Fixed1Byte,
    ];

    /// Returns the lowercase name of the format, accepted by [`FromStr`].
    pub fn name(self) -> &'static str {
        match self {
            Format::Default => "default",
            Format::Ber => "ber",
            Format::Cer => "cer",
            Format::Der => "der",
            Format::Fixed1Byte => "fixed-1byte",
        }
    }

    /// Returns the nesting predicate of the format, or `None` if the format
    /// has no constructed values (every value is opaque).
    pub(crate) fn is_constructed_raw(self) -> Option<sys::tlv_is_constructed_fn> {
        match self {
            Format::Ber => Some(sys::tlv_ber_is_constructed),
            Format::Cer => Some(sys::tlv_cer_is_constructed),
            Format::Der => Some(sys::tlv_der_is_constructed),
            Format::Default | Format::Fixed1Byte => None,
        }
    }

    pub(crate) fn reader_raw(self) -> *const sys::tlv_reader_format_t {
        // SAFETY: only the address of an immutable static is taken; the
        // static lives for the whole program and is never written.
        unsafe {
            match self {
                Format::Default => ptr::addr_of!(sys::tlv_reader_format_default),
                Format::Ber => ptr::addr_of!(sys::tlv_reader_format_ber),
                Format::Cer => ptr::addr_of!(sys::tlv_reader_format_cer),
                Format::Der => ptr::addr_of!(sys::tlv_reader_format_der),
                Format::Fixed1Byte => ptr::addr_of!(sys::tlv_reader_format_fixed_1byte),
            }
        }
    }

    pub(crate) fn writer_raw(self) -> *const sys::tlv_writer_format_t {
        // SAFETY: only the address of an immutable static is taken; the
        // static lives for the whole program and is never written.
        unsafe {
            match self {
                Format::Default => ptr::addr_of!(sys::tlv_writer_format_default),
                Format::Ber => ptr::addr_of!(sys::tlv_writer_format_ber),
                Format::Cer => ptr::addr_of!(sys::tlv_writer_format_cer),
                Format::Der => ptr::addr_of!(sys::tlv_writer_format_der),
                Format::Fixed1Byte => ptr::addr_of!(sys::tlv_writer_format_fixed_1byte),
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
