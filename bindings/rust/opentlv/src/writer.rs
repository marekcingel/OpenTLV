//! Sequential writer over a borrowed output buffer.

use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::slice;

use opentlv_native as native;

use crate::entry::Entry;
use crate::error::{Error, Result};
use crate::fixed_format::FixedFormat;
use crate::format::Format;
use crate::tag::Tag;

/// Returns the encoded size of an element with the given tag and value length
/// in `format`, without writing anything.
///
/// # Errors
///
/// [`Error::InvalidTagSize`] for an empty tag, [`Error::InvalidLength`] if the
/// total does not fit in `usize`, or any error of the format.
///
/// ```
/// use opentlv::{encoded_size, Format, Tag};
///
/// let tag = Tag::from_bytes(&[0x01]);
/// assert_eq!(encoded_size(&tag, 3, Format::Default).unwrap(), 5);
/// ```
pub fn encoded_size(tag: &Tag, value_len: usize, format: Format) -> Result<usize> {
    let mut size = 0usize;
    // SAFETY: `format.writer_raw()` points to a static format and `size` is
    // a valid, writable `usize`.
    let code =
        unsafe { native::tlv_encoded_size(tag.raw(), value_len, format.writer_raw(), &mut size) };
    Error::check(code)?;
    Ok(size)
}

/// Returns the encoded size of an element with the given tag and value length
/// in a [`FixedFormat`], without writing anything.
///
/// # Errors
///
/// Same as [`encoded_size`].
pub fn encoded_size_fixed(tag: &Tag, value_len: usize, format: &FixedFormat) -> Result<usize> {
    let mut size = 0usize;
    // SAFETY: `format.writer_raw()` points at storage owned by `format`,
    // borrowed for this call only, and `size` is a valid, writable `usize`.
    let code =
        unsafe { native::tlv_encoded_size(tag.raw(), value_len, format.writer_raw(), &mut size) };
    Error::check(code)?;
    Ok(size)
}

/// A sequential writer that encodes TLV entries into a byte slice.
///
/// The writer never allocates: it fills the caller's buffer and reports
/// [`Error::BufferTooShort`] when an entry does not fit. A failed write leaves
/// the position unchanged. Values are supplied as `&[u8]`.
///
/// ```
/// use opentlv::{Tag, Writer};
///
/// let mut buf = [0u8; 16];
/// let mut writer = Writer::new(&mut buf);
/// writer.write(&Tag::from_bytes(&[0x01]), &[0xAA, 0xBB]).unwrap();
/// writer.write(&Tag::from_bytes(&[0x02]), &[]).unwrap();
/// assert_eq!(writer.written(), &[0x01, 0x02, 0xAA, 0xBB, 0x02, 0x00]);
/// ```
#[derive(Debug)]
pub struct Writer<'a> {
    raw: native::tlv_writer_t,
    _buf: PhantomData<&'a mut [u8]>,
}

impl<'a> Writer<'a> {
    /// Creates a writer for the default format: a one-byte tag and a definite
    /// BER length.
    pub fn new(buf: &'a mut [u8]) -> Writer<'a> {
        Writer::with_format(buf, Format::Default)
    }

    /// Creates a writer for the given wire format.
    pub fn with_format(buf: &'a mut [u8], format: Format) -> Writer<'a> {
        let mut raw = MaybeUninit::<native::tlv_writer_t>::uninit();
        // SAFETY: `raw` is writable; `buf` is a valid slice (a non-null
        // pointer even when empty); `format.writer_raw()` points to a static
        // format.
        let code = unsafe {
            native::tlv_writer_init(
                raw.as_mut_ptr(),
                buf.as_mut_ptr(),
                buf.len(),
                format.writer_raw(),
            )
        };
        // Every argument is non-null and the built-in formats are complete, so
        // initialization cannot fail.
        assert_eq!(code, native::TLV_OK, "tlv_writer_init failed");
        Writer {
            // SAFETY: `tlv_writer_init` succeeded and initialized every field.
            raw: unsafe { raw.assume_init() },
            _buf: PhantomData,
        }
    }

    /// Creates a writer for a [`FixedFormat`]; `format` must outlive the writer.
    pub fn with_fixed_format(buf: &'a mut [u8], format: &'a FixedFormat) -> Writer<'a> {
        let mut raw = MaybeUninit::<native::tlv_writer_t>::uninit();
        // SAFETY: `raw` is writable; `buf` is a valid slice (a non-null
        // pointer even when empty); `format.writer_raw()` points at storage
        // owned by `format`, which the borrow checker keeps alive for `'a`.
        let code = unsafe {
            native::tlv_writer_init(
                raw.as_mut_ptr(),
                buf.as_mut_ptr(),
                buf.len(),
                format.writer_raw(),
            )
        };
        assert_eq!(code, native::TLV_OK, "tlv_writer_init failed");
        Writer {
            // SAFETY: `tlv_writer_init` succeeded and initialized every field.
            raw: unsafe { raw.assume_init() },
            _buf: PhantomData,
        }
    }

    /// Appends one entry with the given tag and value.
    ///
    /// # Errors
    ///
    /// [`Error::BufferTooShort`] if the entry does not fit in the remaining
    /// space, or any error of the format (for example an invalid tag). On error
    /// the position is unchanged, though bytes past it may have been modified.
    pub fn write(&mut self, tag: &Tag, value: &[u8]) -> Result<()> {
        // SAFETY: `self.raw` is initialized and its buffer is exclusively
        // borrowed for `'a`; `value` is a valid slice of `value.len()` bytes.
        let code = unsafe {
            native::tlv_writer_write(&mut self.raw, tag.raw(), value.as_ptr(), value.len())
        };
        Error::check(code)
    }

    /// Appends a decoded [`Entry`], for example one produced by a `Reader`.
    ///
    /// # Errors
    ///
    /// Same as [`Writer::write`].
    pub fn write_entry(&mut self, entry: &Entry<'_>) -> Result<()> {
        self.write(entry.tag(), entry.value())
    }

    /// Returns the number of bytes written so far.
    pub fn position(&self) -> usize {
        // SAFETY: `self.raw` was initialized by `tlv_writer_init`.
        unsafe { native::tlv_writer_size(&self.raw) }
    }

    /// Returns the total capacity of the output buffer in bytes.
    pub fn capacity(&self) -> usize {
        self.raw.capacity
    }

    /// Returns the number of bytes that can still be written.
    pub fn remaining(&self) -> usize {
        self.raw.capacity - self.position()
    }

    /// Returns the bytes written so far.
    pub fn written(&self) -> &[u8] {
        // SAFETY: the first `position()` bytes of the buffer were written by
        // the C library and are valid; the buffer is not mutated while `self`
        // is borrowed shared.
        unsafe { slice::from_raw_parts(self.raw.buf, self.position()) }
    }

    /// Ends writing and returns the written bytes with the buffer's lifetime.
    pub fn finish(self) -> &'a mut [u8] {
        // SAFETY: as in `written`; consuming `self` guarantees exclusive access
        // to the buffer, which was exclusively borrowed for `'a`.
        unsafe { slice::from_raw_parts_mut(self.raw.buf, self.position()) }
    }
}
