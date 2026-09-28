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
    /// BER-TLV.
    #[default]
    Ber,
    /// Canonical Encoding Rules.
    Cer,
    /// Distinguished Encoding Rules.
    Der,
    /// LLDP packed Type/Length framing; no LLDPDU semantic validation.
    #[cfg(feature = "lldp")]
    Lldp,
}

impl Format {
    /// Every supported format.
    pub const ALL: [Format; 3 + cfg!(feature = "lldp") as usize] = [
        Format::Ber,
        Format::Cer,
        Format::Der,
        #[cfg(feature = "lldp")]
        Format::Lldp,
    ];

    /// Returns the lowercase name of the format, accepted by [`FromStr`].
    pub fn name(self) -> &'static str {
        match self {
            Format::Ber => "ber",
            Format::Cer => "cer",
            Format::Der => "der",
            #[cfg(feature = "lldp")]
            Format::Lldp => "lldp",
        }
    }

    pub(crate) fn raw(self) -> *const native::tlv_format_t {
        // SAFETY: only the address of an immutable static is taken; the
        // static lives for the whole program and is never written. Newer
        // compilers treat this as safe, but the MSRV (1.70) needs `unsafe`.
        #[allow(unused_unsafe)]
        unsafe {
            match self {
                Format::Ber => ptr::addr_of!(native::tlv_format_ber),
                Format::Cer => ptr::addr_of!(native::tlv_format_cer),
                Format::Der => ptr::addr_of!(native::tlv_format_der),
                #[cfg(feature = "lldp")]
                Format::Lldp => ptr::addr_of!(native::tlv_format_lldp),
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
