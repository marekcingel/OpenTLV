//! The TLV tag type.

use std::fmt;
use std::hash::{Hash, Hasher};

use opentlv_sys as sys;

use crate::error::{Error, Result};

/// Byte order of a multi-byte integer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ByteOrder {
    /// Most significant byte first.
    BigEndian,
    /// Least significant byte first.
    LittleEndian,
}

impl ByteOrder {
    fn to_raw(self) -> sys::tlv_byte_order_t {
        match self {
            ByteOrder::BigEndian => sys::TLV_BYTE_ORDER_BIG_ENDIAN,
            ByteOrder::LittleEndian => sys::TLV_BYTE_ORDER_LITTLE_ENDIAN,
        }
    }
}

/// A TLV tag: up to [`Tag::CAPACITY`] raw bytes in wire order.
///
/// A tag owns its bytes and is `Copy`. Whether the bytes form a valid tag for
/// a particular format or profile is a separate question; this type only
/// enforces the size limit. Tags compare equal when their bytes are equal.
#[derive(Clone, Copy)]
pub struct Tag {
    raw: sys::tlv_tag_t,
}

impl Tag {
    /// Maximum number of bytes a tag can hold.
    pub const CAPACITY: usize = sys::TLV_TAG_CAPACITY;

    fn empty_raw() -> sys::tlv_tag_t {
        sys::tlv_tag_t {
            data: [0; sys::TLV_TAG_CAPACITY],
            size: 0,
        }
    }

    /// Creates a tag from raw bytes in wire order.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidTagSize`] if `bytes` is longer than [`Tag::CAPACITY`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Tag> {
        let mut raw = Self::empty_raw();
        // SAFETY: `bytes` is a valid slice of `bytes.len()` readable bytes and
        // `raw` is a valid, writable `tlv_tag_t`.
        let code = unsafe { sys::tlv_tag_from_bytes(bytes.as_ptr(), bytes.len(), &mut raw) };
        Error::check(code)?;
        Ok(Tag { raw })
    }

    /// Creates a tag of exactly `size` bytes holding the numeric `value`.
    ///
    /// Unused most-significant bytes are zero. For example, `0x9F02` with size
    /// 2 and [`ByteOrder::BigEndian`] is the bytes `9F 02`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidTagSize`] if `size` is 0 or above the supported range;
    /// [`Error::Overflow`] if `value` does not fit in `size` bytes.
    pub fn from_u64(value: u64, size: usize, order: ByteOrder) -> Result<Tag> {
        let mut raw = Self::empty_raw();
        // SAFETY: `raw` is a valid, writable `tlv_tag_t`.
        let code = unsafe { sys::tlv_tag_from_u64(value, size, order.to_raw(), &mut raw) };
        Error::check(code)?;
        Ok(Tag { raw })
    }

    /// Validates a raw tag received from the C library and normalizes it.
    pub(crate) fn from_raw(raw: &sys::tlv_tag_t) -> Result<Tag> {
        let size = usize::from(raw.size);
        match raw.data.get(..size) {
            Some(bytes) => Tag::from_bytes(bytes),
            None => Err(Error::InvalidTagSize),
        }
    }

    /// Returns the underlying C tag, for passing by value to the C library.
    pub(crate) fn raw(&self) -> sys::tlv_tag_t {
        self.raw
    }

    /// Returns the tag bytes in wire order.
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw.data[..usize::from(self.raw.size)]
    }

    /// Returns the number of bytes in the tag.
    pub fn len(&self) -> usize {
        usize::from(self.raw.size)
    }

    /// Returns `true` if the tag has no bytes.
    pub fn is_empty(&self) -> bool {
        self.raw.size == 0
    }

    /// Interprets the tag bytes as an unsigned integer with the given byte order.
    ///
    /// This is a plain integer read, not a BER tag-number decode.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidTagSize`] for an empty tag or one longer than 8 bytes.
    pub fn to_u64(&self, order: ByteOrder) -> Result<u64> {
        let mut value = 0u64;
        // SAFETY: both pointers refer to valid, live locals/fields.
        let code = unsafe { sys::tlv_tag_to_u64(&self.raw, order.to_raw(), &mut value) };
        Error::check(code)?;
        Ok(value)
    }
}

impl PartialEq for Tag {
    fn eq(&self, other: &Tag) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for Tag {}

impl Hash for Tag {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state);
    }
}

impl AsRef<[u8]> for Tag {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl TryFrom<&[u8]> for Tag {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Tag> {
        Tag::from_bytes(bytes)
    }
}

/// Formats the tag as uppercase hexadecimal, for example `9F02`.
impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_bytes()
            .iter()
            .try_for_each(|byte| write!(f, "{byte:02X}"))
    }
}

impl fmt::Debug for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Tag({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn from_bytes_keeps_wire_order() {
        let tag = Tag::from_bytes(&[0x9F, 0x02]).unwrap();
        assert_eq!(tag.as_bytes(), &[0x9F, 0x02]);
        assert_eq!(tag.len(), 2);
        assert!(!tag.is_empty());
    }

    #[test]
    fn empty_tag_is_allowed() {
        let tag = Tag::from_bytes(&[]).unwrap();
        assert!(tag.is_empty());
        assert_eq!(tag.as_bytes(), &[] as &[u8]);
    }

    #[test]
    fn full_capacity_is_allowed_and_more_is_rejected() {
        let bytes = [0xAB; Tag::CAPACITY + 1];
        assert!(Tag::from_bytes(&bytes[..Tag::CAPACITY]).is_ok());
        assert_eq!(Tag::from_bytes(&bytes), Err(Error::InvalidTagSize));
    }

    #[test]
    fn from_u64_pads_and_orders_bytes() {
        let big = Tag::from_u64(0x9F02, 3, ByteOrder::BigEndian).unwrap();
        assert_eq!(big.as_bytes(), &[0x00, 0x9F, 0x02]);
        let little = Tag::from_u64(0x9F02, 2, ByteOrder::LittleEndian).unwrap();
        assert_eq!(little.as_bytes(), &[0x02, 0x9F]);
    }

    #[test]
    fn from_u64_reports_errors() {
        assert_eq!(
            Tag::from_u64(0x1_0000, 2, ByteOrder::BigEndian),
            Err(Error::Overflow)
        );
        assert_eq!(
            Tag::from_u64(1, 0, ByteOrder::BigEndian),
            Err(Error::InvalidTagSize)
        );
        assert_eq!(
            Tag::from_u64(1, Tag::CAPACITY + 1, ByteOrder::BigEndian),
            Err(Error::InvalidTagSize)
        );
    }

    #[test]
    fn to_u64_round_trips() {
        let tag = Tag::from_bytes(&[0x9F, 0x02]).unwrap();
        assert_eq!(tag.to_u64(ByteOrder::BigEndian), Ok(0x9F02));
        assert_eq!(tag.to_u64(ByteOrder::LittleEndian), Ok(0x029F));
    }

    #[test]
    fn to_u64_rejects_empty_and_oversized_tags() {
        let empty = Tag::from_bytes(&[]).unwrap();
        assert_eq!(
            empty.to_u64(ByteOrder::BigEndian),
            Err(Error::InvalidTagSize)
        );
        if Tag::CAPACITY > 8 {
            let long = Tag::from_bytes(&[1; 9]).unwrap();
            assert_eq!(
                long.to_u64(ByteOrder::BigEndian),
                Err(Error::InvalidTagSize)
            );
        }
    }

    #[test]
    fn equality_and_hash_use_bytes_only() {
        let a = Tag::from_bytes(&[0x5F, 0x2A]).unwrap();
        let b = Tag::try_from(&[0x5F, 0x2A][..]).unwrap();
        let c = Tag::from_bytes(&[0x5F]).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
        let set: HashSet<Tag> = [a, b, c].into_iter().collect();
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn formats_as_hex() {
        let tag = Tag::from_bytes(&[0x9F, 0x02]).unwrap();
        assert_eq!(tag.to_string(), "9F02");
        assert_eq!(format!("{tag:?}"), "Tag(9F02)");
    }

    #[test]
    fn from_raw_normalizes_and_validates() {
        let mut raw = Tag::empty_raw();
        raw.data = [0x11; Tag::CAPACITY];
        raw.size = 2;
        let tag = Tag::from_raw(&raw).unwrap();
        assert_eq!(tag.as_bytes(), &[0x11, 0x11]);
        assert_eq!(tag, Tag::from_bytes(&[0x11, 0x11]).unwrap());

        raw.size = u8::try_from(Tag::CAPACITY + 1).unwrap();
        assert_eq!(Tag::from_raw(&raw), Err(Error::InvalidTagSize));
    }
}
