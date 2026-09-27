//! Sequential reader over a borrowed TLV buffer.

use std::iter::FusedIterator;
use std::marker::PhantomData;
use std::mem::MaybeUninit;

use opentlv_native as native;

use crate::element::Element;
use crate::error::{Error, Result};
use crate::fixed_format::FixedFormat;
use crate::format::Format;

/// A sequential reader that parses TLV elements from a byte slice.
///
/// `Reader` is an [`Iterator`] over `Result<Element<'a>>`. Elements borrow the
/// input, so the input must outlive them; the compiler enforces this. After
/// the first error the iterator yields nothing more, because the C reader does
/// not advance past malformed input.
///
/// ```
/// let data = [0x01, 0x02, 0xAA, 0xBB, 0x02, 0x00];
/// let mut found = Vec::new();
/// for element in opentlv::Reader::new(&data) {
///     let element = element.unwrap();
///     found.push((element.tag().as_bytes()[0], element.value().len()));
/// }
/// assert_eq!(found, [(0x01, 2), (0x02, 0)]);
/// ```
#[derive(Clone, Debug)]
pub struct Reader<'a> {
    raw: native::tlv_reader_t,
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
        let mut raw = MaybeUninit::<native::tlv_reader_t>::uninit();
        // SAFETY: `raw` is writable; `data` is a valid slice (a non-null
        // pointer even when empty); `format.raw()` points to a static format.
        let code = unsafe {
            native::tlv_reader_init(raw.as_mut_ptr(), data.as_ptr(), data.len(), format.raw())
        };
        // Every argument is non-null and the built-in formats are complete, so
        // initialization cannot fail.
        assert_eq!(code, native::TLV_OK, "tlv_reader_init failed");
        Reader {
            // SAFETY: `tlv_reader_init` succeeded and initialized every field.
            raw: unsafe { raw.assume_init() },
            failed: false,
            _data: PhantomData,
        }
    }

    /// Creates a reader for a [`FixedFormat`]; `format` must outlive the reader.
    pub fn with_fixed_format<'f>(data: &'a [u8], format: &'a FixedFormat<'f>) -> Reader<'a> {
        let mut raw = MaybeUninit::<native::tlv_reader_t>::uninit();
        // SAFETY: `raw` is writable; `data` is a valid slice (a non-null
        // pointer even when empty); `format.raw()` points at storage
        // owned by `format`, which the borrow checker keeps alive for `'a`.
        let code = unsafe {
            native::tlv_reader_init(raw.as_mut_ptr(), data.as_ptr(), data.len(), format.raw())
        };
        assert_eq!(code, native::TLV_OK, "tlv_reader_init failed");
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
        unsafe { native::tlv_reader_at_end(&self.raw) != 0 }
    }

    /// Reads the next element, or returns `None` once the input is consumed or
    /// after an error.
    pub fn next_element(&mut self) -> Option<Result<Element<'a>>> {
        self.next()
    }
}

impl<'a> Iterator for Reader<'a> {
    type Item = Result<Element<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.is_at_end() {
            return None;
        }
        let mut element = MaybeUninit::<native::tlv_element_t>::uninit();
        // SAFETY: `self.raw` is initialized and `element` is writable.
        let code = unsafe { native::tlv_reader_next(&mut self.raw, element.as_mut_ptr()) };
        if let Err(error) = Error::check(code) {
            self.failed = true;
            return Some(Err(error));
        }
        // SAFETY: on success the C reader initialized `element`, and its value
        // points into the `'a` input this reader borrows.
        let element = unsafe { Element::from_raw(&element.assume_init()) };
        if element.is_err() {
            self.failed = true;
        }
        Some(element)
    }
}

impl FusedIterator for Reader<'_> {}
