//! The decoded TLV element type.

use std::slice;

use opentlv_sys as sys;

use crate::error::{Error, Result};
use crate::tag::Tag;

/// A decoded TLV element: a tag and a borrowed value.
///
/// The value borrows the input it was decoded from, so the input must outlive
/// the entry. The tag is copied out of the input, so it does not. Cloning an
/// entry clones the tag but not the value bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry<'a> {
    tag: Tag,
    value: &'a [u8],
}

impl<'a> Entry<'a> {
    /// Creates an entry from a tag and a value.
    pub fn new(tag: Tag, value: &'a [u8]) -> Entry<'a> {
        Entry { tag, value }
    }

    /// Returns the element tag.
    pub fn tag(&self) -> &Tag {
        &self.tag
    }

    /// Returns the element value bytes.
    pub fn value(&self) -> &'a [u8] {
        self.value
    }

    /// Converts a raw C view into an entry, validating every field.
    ///
    /// # Safety
    ///
    /// If `raw.value.data` is non-null, it must point to `raw.value.length`
    /// readable bytes that stay valid and unmodified for `'a`.
    pub(crate) unsafe fn from_raw(raw: &sys::tlv_view_t) -> Result<Entry<'a>> {
        // SAFETY: the caller guarantees the tag bytes are readable, as for the value.
        let tag = unsafe { Tag::from_raw(&raw.tag) }?;

        let mut length = 0usize;
        // SAFETY: `length` is a valid, writable `usize`.
        Error::check(unsafe { sys::tlv_length_to_size(raw.value.length, &mut length) })?;

        let value: &'a [u8] = if length == 0 {
            &[]
        } else if raw.value.data.is_null() {
            return Err(Error::NullArg);
        } else {
            // SAFETY: non-null, and the caller guarantees `length` readable
            // bytes valid for `'a`.
            unsafe { slice::from_raw_parts(raw.value.data, length) }
        };
        Ok(Entry { tag, value })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_view(tag: &[u8], data: *const u8, length: u64) -> sys::tlv_view_t {
        let raw_tag = sys::tlv_tag_t {
            data: if tag.is_empty() {
                std::ptr::null()
            } else {
                tag.as_ptr()
            },
            size: tag.len(),
        };
        sys::tlv_view_t {
            tag: raw_tag,
            value: sys::tlv_value_t { data, length },
        }
    }

    #[test]
    fn exposes_tag_and_value() {
        let tag = Tag::from_bytes(&[0x5A]);
        let entry = Entry::new(tag.clone(), &[1, 2, 3]);
        assert_eq!(entry.tag(), &tag);
        assert_eq!(entry.value(), &[1, 2, 3]);
    }

    #[test]
    fn from_raw_borrows_the_value() {
        let bytes = [0xDE, 0xAD, 0xBE, 0xEF];
        let raw = raw_view(&[0x9F, 0x02], bytes.as_ptr(), bytes.len() as u64);
        // SAFETY: `bytes` outlives `entry` and matches the declared length.
        let entry = unsafe { Entry::from_raw(&raw) }.unwrap();
        assert_eq!(entry.tag().as_bytes(), &[0x9F, 0x02]);
        assert_eq!(entry.value(), &bytes);
        assert_eq!(entry.value().as_ptr(), bytes.as_ptr());
    }

    #[test]
    fn from_raw_accepts_empty_value_with_null_data() {
        let raw = raw_view(&[0x01], std::ptr::null(), 0);
        // SAFETY: a null pointer with zero length is valid.
        let entry = unsafe { Entry::from_raw(&raw) }.unwrap();
        assert!(entry.value().is_empty());
    }

    #[test]
    fn from_raw_rejects_null_data_with_length() {
        let raw = raw_view(&[0x01], std::ptr::null(), 4);
        // SAFETY: the null pointer is rejected before any read.
        assert_eq!(unsafe { Entry::from_raw(&raw) }, Err(Error::NullArg));
    }

    #[test]
    fn from_raw_rejects_a_tag_size_without_bytes() {
        let mut raw = raw_view(&[0x01], std::ptr::null(), 0);
        raw.tag.data = std::ptr::null();
        // SAFETY: the tag is rejected before the value is touched.
        assert_eq!(unsafe { Entry::from_raw(&raw) }, Err(Error::NullArg));
    }

    #[test]
    fn from_raw_accepts_tags_of_any_length() {
        let tag = [0x5A; 300];
        let raw = raw_view(&tag, std::ptr::null(), 0);
        // SAFETY: `tag` outlives the call and matches the declared size.
        let entry = unsafe { Entry::from_raw(&raw) }.unwrap();
        assert_eq!(entry.tag().as_bytes(), &tag[..]);
    }

    #[cfg(target_pointer_width = "32")]
    #[test]
    fn from_raw_rejects_length_beyond_usize() {
        let bytes = [0u8; 1];
        let raw = raw_view(&[0x01], bytes.as_ptr(), u64::MAX);
        // SAFETY: the length is rejected before any read.
        assert_eq!(unsafe { Entry::from_raw(&raw) }, Err(Error::InvalidLength));
    }
}
