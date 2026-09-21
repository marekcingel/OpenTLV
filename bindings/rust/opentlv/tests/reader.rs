//! Integration tests for the safe reader API.

use opentlv::{Error, Format, Reader, Tag};

#[test]
fn parses_multiple_entries() {
    let data = [0x01, 0x03, b'a', b'b', b'c', 0x02, 0x00, 0x03, 0x01, 0xFF];
    let entries: Vec<_> = Reader::new(&data).collect::<Result<_, _>>().unwrap();

    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].tag(), &Tag::from_bytes(&[0x01]));
    assert_eq!(entries[0].value(), b"abc");
    assert_eq!(entries[1].tag().as_bytes(), &[0x02]);
    assert!(entries[1].value().is_empty());
    assert_eq!(entries[2].value(), &[0xFF]);
}

#[test]
fn values_are_zero_copy_slices_of_the_input() {
    let data = vec![0x07, 0x02, 0x10, 0x20];
    let entry = Reader::new(&data).next().unwrap().unwrap();
    assert_eq!(entry.value().as_ptr(), data[2..].as_ptr());
}

#[test]
fn empty_input_yields_no_entries() {
    let mut reader = Reader::new(&[]);
    assert!(reader.is_at_end());
    assert!(reader.next().is_none());
}

#[test]
fn tracks_position() {
    let data = [0x01, 0x01, 0xAA, 0x02, 0x00];
    let mut reader = Reader::new(&data);
    assert_eq!(reader.position(), 0);
    reader.next_entry().unwrap().unwrap();
    assert_eq!(reader.position(), 3);
    reader.next_entry().unwrap().unwrap();
    assert!(reader.is_at_end());
    assert!(reader.next_entry().is_none());
}

#[test]
fn truncated_value_is_an_error_then_iteration_stops() {
    let data = [0x01, 0x01, 0xAA, 0x02, 0x05, 0x00];
    let mut reader = Reader::new(&data);
    assert!(reader.next().unwrap().is_ok());
    assert_eq!(reader.next().unwrap().unwrap_err(), Error::BufferTooShort);
    assert!(reader.next().is_none());
    assert!(reader.next().is_none());
}

#[test]
fn truncated_length_is_an_error() {
    let data = [0x01];
    let err = Reader::new(&data).next().unwrap().unwrap_err();
    assert_eq!(err, Error::BufferTooShort);
}

#[test]
fn collecting_into_result_surfaces_malformed_input() {
    let data = [0x01, 0x04, 0x00];
    let result: Result<Vec<_>, _> = Reader::new(&data).collect();
    assert!(result.is_err());
}

#[test]
fn error_propagates_with_question_mark() {
    fn count(data: &[u8]) -> opentlv::Result<usize> {
        let mut n = 0;
        for entry in Reader::new(data) {
            entry?;
            n += 1;
        }
        Ok(n)
    }
    assert_eq!(count(&[0x01, 0x00, 0x02, 0x00]), Ok(2));
    assert_eq!(count(&[0x01, 0x02, 0x00]), Err(Error::BufferTooShort));
}

#[test]
fn reads_ber_multi_byte_tags() {
    let data = [0x9F, 0x02, 0x02, 0x12, 0x34];
    let entry = Reader::with_format(&data, Format::Ber)
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(entry.tag().as_bytes(), &[0x9F, 0x02]);
    assert_eq!(entry.value(), &[0x12, 0x34]);
}

#[test]
fn reads_der_and_fixed_formats() {
    let der = [0x04, 0x02, 0xCA, 0xFE];
    let entry = Reader::with_format(&der, Format::Der)
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(entry.value(), &[0xCA, 0xFE]);

    let fixed = [0x05, 0x01, 0x99];
    let entry = Reader::with_format(&fixed, Format::Fixed1Byte)
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(entry.value(), &[0x99]);
}

#[test]
fn entries_outlive_the_reader() {
    let data = [0x01, 0x02, 0xAA, 0xBB];
    let entry = {
        let mut reader = Reader::new(&data);
        reader.next().unwrap().unwrap()
    };
    assert_eq!(entry.value(), &[0xAA, 0xBB]);
}
