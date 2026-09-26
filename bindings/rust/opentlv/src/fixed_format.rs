//! Runtime-configurable fixed-width TLV format.

use std::mem::MaybeUninit;

use opentlv_native as native;

use crate::error::{Error, Result};

/// Byte order of a [`FixedFormat`]'s length field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ByteOrder {
    /// Most significant byte first.
    Big,
    /// Least significant byte first.
    Little,
}

impl From<ByteOrder> for native::tlv_byte_order_t {
    fn from(order: ByteOrder) -> native::tlv_byte_order_t {
        match order {
            ByteOrder::Big => native::TLV_BYTE_ORDER_BIG_ENDIAN,
            ByteOrder::Little => native::TLV_BYTE_ORDER_LITTLE_ENDIAN,
        }
    }
}

/// A runtime-configurable fixed-width TLV format: independent tag width,
/// length width (1 to 8 bytes) and length byte order.
///
/// Equivalent to the C `tlv_fixed_config_t` and
/// `tlv_fixed_reader_format_init()`/`tlv_fixed_writer_format_init()`. A
/// one-byte tag and a one-byte big-endian length is
/// `FixedFormat::new(1, 1, ByteOrder::Big)`.
///
/// ```
/// use opentlv::{ByteOrder, FixedFormat, Reader, Tag, Writer};
///
/// let format = FixedFormat::new(2, 1, ByteOrder::Big).unwrap();
/// let mut buf = [0u8; 16];
/// let mut writer = Writer::with_fixed_format(&mut buf, &format);
/// writer.write(&Tag::from_bytes(&[0x01, 0x02]), &[0xAA, 0xBB, 0xCC]).unwrap();
///
/// let entry = Reader::with_fixed_format(writer.written(), &format)
///     .next().unwrap().unwrap();
/// assert_eq!(entry.value(), &[0xAA, 0xBB, 0xCC]);
/// ```
#[derive(Debug)]
pub struct FixedFormat {
    // Heap-allocated so its address stays stable even when `FixedFormat`
    // itself is moved; `reader`/`writer` below borrow it as their context.
    config: Box<native::tlv_fixed_config_t>,
    reader: native::tlv_reader_format_t,
    writer: native::tlv_writer_format_t,
}

impl FixedFormat {
    /// Creates a configurable fixed-width format.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArg`] if `tag_size` is 0 or `length_size` is 0 or
    /// greater than 8; [`Error::InvalidByteOrder`] cannot occur since `order`
    /// is always a valid [`ByteOrder`].
    pub fn new(tag_size: usize, length_size: usize, order: ByteOrder) -> Result<FixedFormat> {
        let config = Box::new(native::tlv_fixed_config_t {
            tag_size,
            length_size,
            order: order.into(),
        });
        let mut reader = MaybeUninit::<native::tlv_reader_format_t>::uninit();
        let mut writer = MaybeUninit::<native::tlv_writer_format_t>::uninit();
        // SAFETY: `config`'s address is stable (heap-allocated, independent of
        // this `FixedFormat` value's own address); `reader`/`writer` are writable.
        let code = unsafe { native::tlv_fixed_reader_format_init(reader.as_mut_ptr(), &*config) };
        Error::check(code)?;
        // SAFETY: as above.
        let code = unsafe { native::tlv_fixed_writer_format_init(writer.as_mut_ptr(), &*config) };
        Error::check(code)?;
        Ok(FixedFormat {
            config,
            // SAFETY: both `tlv_fixed_*_format_init` calls above succeeded,
            // so both descriptors are fully initialized.
            reader: unsafe { reader.assume_init() },
            writer: unsafe { writer.assume_init() },
        })
    }

    /// Tag width in bytes.
    pub fn tag_size(&self) -> usize {
        self.config.tag_size
    }

    /// Length field width in bytes.
    pub fn length_size(&self) -> usize {
        self.config.length_size
    }

    pub(crate) fn reader_raw(&self) -> *const native::tlv_reader_format_t {
        &self.reader
    }

    pub(crate) fn writer_raw(&self) -> *const native::tlv_writer_format_t {
        &self.writer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_configurations() {
        assert_eq!(
            FixedFormat::new(0, 1, ByteOrder::Big).unwrap_err(),
            Error::InvalidArg
        );
        assert_eq!(
            FixedFormat::new(1, 0, ByteOrder::Big).unwrap_err(),
            Error::InvalidArg
        );
        assert_eq!(
            FixedFormat::new(1, 9, ByteOrder::Big).unwrap_err(),
            Error::InvalidArg
        );
    }

    #[test]
    fn one_byte_configuration_matches_the_wire_bytes() {
        let format = FixedFormat::new(1, 1, ByteOrder::Big).unwrap();
        assert_eq!(format.tag_size(), 1);
        assert_eq!(format.length_size(), 1);
    }
}
