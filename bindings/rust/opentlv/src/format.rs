//! Wire formats shared by the reader and the writer.

use std::ptr;

use opentlv_sys as sys;

/// The wire format a [`Reader`](crate::Reader) or [`Writer`](crate::Writer) uses.
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
