//! The simplest possible round trip: write one element with the
//! configurable fixed-width format, then read it back. See parse.rs and
//! write.rs for a nested BER document, and the C `quick_start.c` and C++
//! `quick_start.cpp` examples for the same round trip in those languages.
//!
//! Run with `cargo run --example quick_start` from `bindings/rust`.

use opentlv::{ByteOrder, FixedFormat, Reader, Result, Tag, Writer};

fn main() -> Result<()> {
    // One tag byte and one length byte; format must outlive its readers and writers.
    let format = FixedFormat::new(1, 1, ByteOrder::Big)?;

    let tag = Tag::from_bytes(&[0x01]);
    let value = [0xAA, 0xBB, 0xCC];

    let mut buf = [0u8; 5];
    let mut writer = Writer::with_fixed_format(&mut buf, &format);
    writer.write(&tag, &value)?;
    println!(
        "wrote {} bytes: {:02X?}",
        writer.written().len(),
        writer.written()
    );

    let mut reader = Reader::with_fixed_format(writer.written(), &format);
    let entry = reader.next_entry().expect("one entry was written")?;
    assert_eq!(entry.tag(), &tag);
    assert_eq!(entry.value(), &value);
    assert!(reader.is_at_end());
    println!(
        "read tag {:02X?} value {:02X?}",
        entry.tag().as_bytes(),
        entry.value()
    );
    Ok(())
}
