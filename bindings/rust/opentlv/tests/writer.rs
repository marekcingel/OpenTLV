//! Integration tests for the safe writer API and reader/writer round trips.

use opentlv::{encoded_size, Error, Format, Reader, Tag, Writer};

fn tag(bytes: &[u8]) -> Tag {
    Tag::from_bytes(bytes).unwrap()
}

#[test]
fn writes_entries_with_expected_bytes() {
    let mut buf = [0u8; 16];
    let mut writer = Writer::new(&mut buf);
    writer.write(&tag(&[0x01]), b"abc").unwrap();
    writer.write(&tag(&[0x02]), &[]).unwrap();
    assert_eq!(writer.position(), 7);
    assert_eq!(
        writer.written(),
        &[0x01, 0x03, b'a', b'b', b'c', 0x02, 0x00]
    );
}

#[test]
fn tracks_capacity_and_remaining() {
    let mut buf = [0u8; 8];
    let mut writer = Writer::new(&mut buf);
    assert_eq!((writer.capacity(), writer.remaining()), (8, 8));
    writer.write(&tag(&[0x01]), &[0xFF]).unwrap();
    assert_eq!((writer.capacity(), writer.remaining()), (8, 5));
}

#[test]
fn buffer_too_short_leaves_position_unchanged() {
    let mut buf = [0u8; 4];
    let mut writer = Writer::new(&mut buf);
    writer.write(&tag(&[0x01]), &[0xAA]).unwrap();
    assert_eq!(
        writer.write(&tag(&[0x02]), &[1, 2, 3]),
        Err(Error::BufferTooShort)
    );
    assert_eq!(writer.position(), 3);
    // A smaller entry that does not fit either still reports the same error.
    assert_eq!(writer.write(&tag(&[0x03]), &[]), Err(Error::BufferTooShort));
    assert_eq!(writer.position(), 3);
}

#[test]
fn empty_buffer_rejects_every_entry() {
    let mut writer = Writer::new(&mut []);
    assert_eq!(writer.write(&tag(&[0x01]), &[]), Err(Error::BufferTooShort));
    assert!(writer.written().is_empty());
}

#[test]
fn empty_tag_is_an_error() {
    let mut buf = [0u8; 8];
    let mut writer = Writer::new(&mut buf);
    let empty = Tag::from_bytes(&[]).unwrap();
    assert!(writer.write(&empty, &[]).is_err());
    assert_eq!(writer.position(), 0);
}

#[test]
fn encoded_size_matches_written_size() {
    let value = vec![0u8; 300];
    let t = tag(&[0x9F, 0x02]);
    let size = encoded_size(&t, value.len(), Format::Ber).unwrap();
    let mut buf = vec![0u8; size];
    let mut writer = Writer::with_format(&mut buf, Format::Ber);
    writer.write(&t, &value).unwrap();
    assert_eq!(writer.position(), size);
    assert_eq!(writer.remaining(), 0);
}

#[test]
fn finish_returns_the_written_prefix() {
    let mut buf = [0u8; 8];
    let mut writer = Writer::new(&mut buf);
    writer.write(&tag(&[0x05]), &[0x01]).unwrap();
    assert_eq!(writer.finish(), &[0x05, 0x01, 0x01]);
}

fn round_trip(format: Format, entries: &[(&[u8], &[u8])]) {
    let mut buf = vec![0u8; 512];
    let mut writer = Writer::with_format(&mut buf, format);
    for (t, v) in entries {
        writer.write(&tag(t), v).unwrap();
    }
    let encoded = writer.finish();

    let decoded: Vec<_> = Reader::with_format(encoded, format)
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(decoded.len(), entries.len(), "{format:?}");
    for (entry, (t, v)) in decoded.iter().zip(entries) {
        assert_eq!(entry.tag().as_bytes(), *t, "{format:?}");
        assert_eq!(entry.value(), *v, "{format:?}");
    }
}

#[test]
fn round_trips_default_format() {
    round_trip(
        Format::Default,
        &[(&[0x01], b"hello"), (&[0x02], &[]), (&[0x7F], &[0x55; 300])],
    );
}

#[test]
fn round_trips_ber_format_with_multi_byte_tags() {
    round_trip(
        Format::Ber,
        &[
            (&[0x01], b"hello"),
            (&[0x02], &[]),
            (&[0x9F, 0x02], &[0xDE, 0xAD, 0xBE, 0xEF]),
            (&[0x40], &[0x55; 200]),
        ],
    );
}

#[test]
fn default_format_rejects_multi_byte_tags() {
    let mut buf = [0u8; 16];
    let mut writer = Writer::new(&mut buf);
    assert_eq!(
        writer.write(&tag(&[0x9F, 0x02]), &[]),
        Err(Error::InvalidTagSize)
    );
    assert_eq!(writer.position(), 0);
}

#[test]
fn round_trips_fixed_and_der_formats() {
    for format in [Format::Fixed1Byte, Format::Der] {
        let mut buf = [0u8; 32];
        let mut writer = Writer::with_format(&mut buf, format);
        writer.write(&tag(&[0x04]), &[1, 2, 3]).unwrap();
        let encoded = writer.finish();
        let entry = Reader::with_format(encoded, format)
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(entry.tag().as_bytes(), &[0x04]);
        assert_eq!(entry.value(), &[1, 2, 3]);
    }
}

#[test]
fn write_entry_copies_entries_read_from_another_buffer() {
    let source = [0x01, 0x02, 0xAA, 0xBB, 0x02, 0x00];
    let mut buf = [0u8; 6];
    let mut writer = Writer::new(&mut buf);
    for entry in Reader::new(&source) {
        writer.write_entry(&entry.unwrap()).unwrap();
    }
    assert_eq!(writer.written(), &source);
}
