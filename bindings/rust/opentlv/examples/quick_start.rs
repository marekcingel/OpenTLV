// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

//! The simplest possible round trip: write one element with the
//! configurable fixed-width format, then read it back. See parse.rs and
//! write.rs for a nested BER document, and the C `quick_start.c` and C++
//! `quick_start.cpp` examples for the same round trip in those languages.
//!
//! Run with `cargo run --example quick_start` from `bindings/rust`.

use opentlv::{ByteOrder, FixedFormat, FixedFormatConfig, Reader, Result, Tag, Writer};

fn main() -> Result<()> {
    // One tag byte and one length byte; config must outlive format, and format
    // must outlive its readers and writers.
    let config = FixedFormatConfig::new(1, 1, ByteOrder::Big);
    let format = FixedFormat::new(&config)?;

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
    let element = reader.next_element().expect("one element was written")?;
    assert_eq!(element.tag(), &tag);
    assert_eq!(element.value(), &value);
    assert!(reader.is_at_end());
    println!(
        "read tag {:02X?} value {:02X?}",
        element.tag().as_bytes(),
        element.value()
    );
    Ok(())
}
