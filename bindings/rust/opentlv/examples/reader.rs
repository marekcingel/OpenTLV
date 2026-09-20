//! Reads a BER-TLV buffer with `Reader`, descends into a constructed entry and
//! decodes values with the EMV dictionary.
//!
//! Run with `cargo run --example reader` from `bindings/rust`.

use opentlv::emv::{self, Context};
use opentlv::{Format, Reader, Result};

/// An FCI template (6F) holding a DF name (84) and an application label (50).
const FCI: [u8; 17] = [
    0x6F, 0x0F, 0x84, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, 0x50, 0x04, b'V', b'I', b'S',
    b'A',
];

fn print_entries(data: &[u8], depth: usize) -> Result<()> {
    // Entries borrow `data`; the reader itself can be dropped early.
    for entry in Reader::with_format(data, Format::Ber) {
        let entry = entry?;
        let tag = entry.tag();
        let name = emv::find(Context::Base, tag).map_or("unknown", |definition| definition.name());
        println!(
            "{:indent$}{:02X?} {name}: {:02X?}",
            "",
            tag.as_bytes(),
            entry.value(),
            indent = depth * 2
        );

        // Bit 6 of the first tag byte marks a constructed (template) entry.
        if tag.as_bytes()[0] & 0x20 != 0 {
            print_entries(entry.value(), depth + 1)?;
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    println!("OpenTLV {}", opentlv::version());
    print_entries(&FCI, 0)?;

    // Malformed input surfaces as an `Err` item; the iterator then ends.
    let truncated = &FCI[..FCI.len() - 2];
    for entry in Reader::with_format(truncated, Format::Ber) {
        if let Err(error) = entry {
            println!("truncated input: {error} ({error:?})");
        }
    }
    Ok(())
}
