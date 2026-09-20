//! Sequential reader over a borrowed TLV buffer.

use std::iter::FusedIterator;
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::ptr;

use opentlv_sys as sys;

use crate::entry::Entry;
use crate::error::{Error, Result};

/// The wire format a [`Reader`] decodes.
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
    fn raw(self) -> *const sys::tlv_reader_format_t {
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
}

/// A sequential reader that parses TLV entries from a byte slice.
///
/// `Reader` is an [`Iterator`] over `Result<Entry<'a>>`. Entries borrow the
/// input, so the input must outlive them; the compiler enforces this. After
/// the first error the iterator yields nothing more, because the C reader does
/// not advance past malformed input.
///
/// ```
/// let data = [0x01, 0x02, 0xAA, 0xBB, 0x02, 0x00];
/// let mut found = Vec::new();
/// for entry in opentlv::Reader::new(&data) {
///     let entry = entry.unwrap();
///     found.push((entry.tag().as_bytes()[0], entry.value().len()));
/// }
/// assert_eq!(found, [(0x01, 2), (0x02, 0)]);
/// ```
#[derive(Clone, Debug)]
pub struct Reader<'a> {
    raw: sys::tlv_reader_t,
    failed: bool,
    _data: PhantomData<&'a [u8]>,
}

impl<'a> Reader<'a> {
    /// Creates a reader for the default format: a one-byte tag and a definite
    /// BER length.
    pub fn new(data: &'a [u8]) -> Reader<'a> {
        Reader::with_format(data, Format::Default)
    }

    /// Creates a reader for the given wire format.
    pub fn with_format(data: &'a [u8], format: Format) -> Reader<'a> {
        let mut raw = MaybeUninit::<sys::tlv_reader_t>::uninit();
        // SAFETY: `raw` is writable; `data` is a valid slice (a non-null
        // pointer even when empty); `format.raw()` points to a static format.
        let code = unsafe {
            sys::tlv_reader_init(raw.as_mut_ptr(), data.as_ptr(), data.len(), format.raw())
        };
        // Every argument is non-null and the built-in formats are complete, so
        // initialization cannot fail.
        assert_eq!(code, sys::TLV_OK, "tlv_reader_init failed");
        Reader {
            // SAFETY: `tlv_reader_init` succeeded and initialized every field.
            raw: unsafe { raw.assume_init() },
            failed: false,
            _data: PhantomData,
        }
    }

    /// Returns the offset in the input of the next element to read.
    pub fn position(&self) -> usize {
        self.raw.pos
    }

    /// Returns `true` if all input has been consumed.
    pub fn is_at_end(&self) -> bool {
        // SAFETY: `self.raw` was initialized by `tlv_reader_init`.
        unsafe { sys::tlv_reader_at_end(&self.raw) != 0 }
    }

    /// Reads the next entry, or returns `None` once the input is consumed or
    /// after an error.
    pub fn next_entry(&mut self) -> Option<Result<Entry<'a>>> {
        self.next()
    }
}

impl<'a> Iterator for Reader<'a> {
    type Item = Result<Entry<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.is_at_end() {
            return None;
        }
        let mut view = MaybeUninit::<sys::tlv_view_t>::uninit();
        // SAFETY: `self.raw` is initialized and `view` is writable.
        let code = unsafe { sys::tlv_reader_next(&mut self.raw, view.as_mut_ptr()) };
        if let Err(error) = Error::check(code) {
            self.failed = true;
            return Some(Err(error));
        }
        // SAFETY: on success the C reader initialized `view`, and its value
        // points into the `'a` input this reader borrows.
        let entry = unsafe { Entry::from_raw(&view.assume_init()) };
        if entry.is_err() {
            self.failed = true;
        }
        Some(entry)
    }
}

impl FusedIterator for Reader<'_> {}
