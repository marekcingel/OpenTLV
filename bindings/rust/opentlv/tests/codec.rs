//! Integration tests for value codecs and the EMV dictionary.

use opentlv::emv::{self, Context};
use opentlv::{
    AccountType, AflEntry, BiometricType, Codec, CodecError, CryptogramInfo, CryptogramType,
    CvmResult, Date, Error, Format, Reader, Tag, Time, Track2, Value, ValueKind,
};

fn tag(bytes: &[u8]) -> Tag {
    Tag::from_bytes(bytes).unwrap()
}

fn codec(context: Context, bytes: &[u8]) -> Codec {
    emv::find(context, &tag(bytes))
        .unwrap_or_else(|| panic!("no definition for {bytes:02X?}"))
        .codec()
        .expect("definition has a codec")
}

/// Decodes `raw`, checks the value and encodes it back to the same bytes.
fn round_trip(codec: Codec, raw: &[u8], expected: Value) {
    assert_eq!(codec.decode(raw).unwrap(), expected);
    assert_eq!(codec.encoded_size(&expected).unwrap(), raw.len());
    assert_eq!(codec.encode(&expected).unwrap(), raw);
}

#[test]
fn amount_codec_round_trips_bcd() {
    let amount = Codec::amount();
    assert_eq!(amount.kind(), ValueKind::Number);
    round_trip(amount, &[0, 0, 0, 0, 0x12, 0x34], Value::Number(1234));
    assert_eq!(
        amount.decode(&[0, 0, 0, 0, 0x1A, 0x34]),
        Err(CodecError::InvalidValue)
    );
    assert_eq!(amount.decode(&[0, 0, 0]), Err(CodecError::InvalidValue));
}

#[test]
fn dictionary_definitions_expose_metadata() {
    let afl = emv::find(Context::Base, &tag(&[0x94])).unwrap();
    assert_eq!(afl.name(), "afl");
    assert_eq!(afl.tag(), tag(&[0x94]));
    assert_eq!(afl.kind(), ValueKind::Afl);
    assert_eq!(
        (afl.min_length(), afl.max_length(), afl.length_step()),
        (4, Some(252), 4)
    );
    assert_eq!(afl.display_label(), Some("Application File Locator (AFL)"));
    assert_eq!(afl.validate_length(8), Ok(()));
    assert_eq!(afl.validate_length(5), Err(Error::InvalidLength));

    let label = emv::find(Context::Base, &tag(&[0x50])).unwrap();
    assert_eq!(label.kind(), ValueKind::Text);
    assert!(label.codec().is_none());

    let unbounded = emv::find(Context::Base, &tag(&[0x90])).unwrap();
    assert_eq!(unbounded.max_length(), None);

    assert!(emv::find(Context::Base, &tag(&[0x01])).is_none());
    // Contexts never fall back to the base dictionary.
    assert!(emv::find(Context::Bht, &tag(&[0x94])).is_none());
}

#[test]
fn context_follows_templates() {
    assert_eq!(Context::Base.child(&tag(&[0x7F, 0x60])), Some(Context::Bit));
    // A known base template keeps its children in the base context ...
    assert_eq!(Context::Base.child(&tag(&[0x6F])), Some(Context::Base));
    // ... while an unknown, possibly proprietary container is not guessed at.
    assert_eq!(Context::Base.child(&tag(&[0x01])), None);
}

#[test]
fn flags_and_numbers() {
    round_trip(
        codec(Context::Base, &[0x82]),
        &[0x20, 0x00],
        Value::Flags(0x2000),
    );
    round_trip(
        codec(Context::Base, &[0x9F, 0x1A]),
        &[0x08, 0x40],
        Value::Number(840),
    );
    round_trip(
        codec(Context::Base, &[0x9F, 0x03]),
        &[0, 0, 0, 0, 0x05, 0x00],
        Value::Number(500),
    );
}

#[test]
fn digits_drop_the_padding_nibble() {
    let pan = codec(Context::Base, &[0x5A]);
    round_trip(
        pan,
        &[0x41, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11],
        Value::Digits("4111111111111111".into()),
    );
    assert_eq!(
        pan.decode(&[0x41, 0x11, 0x1F]).unwrap(),
        Value::Digits("41111".into())
    );
    assert_eq!(
        pan.encode(&Value::Digits("41111".into())).unwrap(),
        [0x41, 0x11, 0x1F]
    );
    assert_eq!(pan.decode(&[]), Err(CodecError::InvalidValue));
}

#[test]
fn dates_and_times_are_range_checked() {
    let date = codec(Context::Base, &[0x9A]);
    round_trip(
        date,
        &[0x25, 0x12, 0x31],
        Value::Date(Date {
            year: 25,
            month: 12,
            day: 31,
        }),
    );
    assert_eq!(
        date.decode(&[0x25, 0x13, 0x01]),
        Err(CodecError::InvalidValue)
    );

    let time = codec(Context::Base, &[0x9F, 0x21]);
    round_trip(
        time,
        &[0x12, 0x34, 0x56],
        Value::Time(Time {
            hour: 12,
            minute: 34,
            second: 56,
        }),
    );
    assert_eq!(
        time.decode(&[0x24, 0x00, 0x00]),
        Err(CodecError::InvalidValue)
    );
}

#[test]
fn enumerations_reject_undefined_values() {
    let account = codec(Context::Base, &[0x5F, 0x57]);
    round_trip(account, &[0x10], Value::Account(AccountType::Savings));
    round_trip(account, &[0x30], Value::Account(AccountType::Credit));
    assert_eq!(account.decode(&[0x11]), Err(CodecError::InvalidValue));

    let biometric = codec(Context::Bht, &[0x81]);
    round_trip(biometric, &[0x08], Value::Biometric(BiometricType::Finger));
    assert_eq!(biometric.decode(&[0x01]), Err(CodecError::InvalidValue));

    let cid = codec(Context::Base, &[0x9F, 0x27]);
    round_trip(
        cid,
        &[0x80],
        Value::Cryptogram(CryptogramInfo {
            kind: CryptogramType::Arqc,
            flags: 0,
        }),
    );
    round_trip(
        cid,
        &[0x45],
        Value::Cryptogram(CryptogramInfo {
            kind: CryptogramType::Tc,
            flags: 0x05,
        }),
    );
}

#[test]
fn afl_round_trips_and_validates_entries() {
    let afl = codec(Context::Base, &[0x94]);
    let entries = vec![
        AflEntry {
            sfi: 1,
            first_record: 1,
            last_record: 3,
            offline_auth_record_count: 1,
        },
        AflEntry {
            sfi: 2,
            first_record: 1,
            last_record: 1,
            offline_auth_record_count: 0,
        },
    ];
    round_trip(
        afl,
        &[0x08, 0x01, 0x03, 0x01, 0x10, 0x01, 0x01, 0x00],
        Value::Afl(entries),
    );
    // SFI 0 is reserved.
    assert_eq!(
        afl.decode(&[0x00, 0x01, 0x01, 0x00]),
        Err(CodecError::InvalidValue)
    );
    let too_many = Value::Afl(vec![AflEntry::default(); 64]);
    assert_eq!(afl.encoded_size(&too_many), Err(CodecError::InvalidValue));
}

#[test]
fn cvm_results_are_preserved_raw() {
    round_trip(
        codec(Context::Base, &[0x9F, 0x34]),
        &[0x1E, 0x03, 0x02],
        Value::CvmResult(CvmResult {
            method: 0x1E,
            condition: 0x03,
            result: 0x02,
        }),
    );
}

#[test]
fn track2_round_trips() {
    let raw = [
        0x54, 0x13, 0x33, 0x00, 0x89, 0x02, 0x00, 0x11, 0xD2, 0x51, 0x22, 0x01, 0x00, 0x00,
    ];
    let value = Value::Track2(Track2 {
        pan: "5413330089020011".into(),
        expiration_year: 25,
        expiration_month: 12,
        service_code: 201,
        discretionary_data: "0000".into(),
    });
    let track2 = codec(Context::Base, &[0x57]);
    round_trip(track2, &raw, value);

    // A PAN that does not fit the C representation is rejected, not truncated.
    let long = Value::Track2(Track2 {
        pan: "1".repeat(20),
        ..Track2::default()
    });
    assert_eq!(track2.encoded_size(&long), Err(CodecError::InvalidValue));
    // Month 0 is invalid.
    let bad = Value::Track2(Track2 {
        pan: "1234".into(),
        ..Track2::default()
    });
    assert_eq!(track2.encoded_size(&bad), Err(CodecError::InvalidValue));
}

#[test]
fn encoding_reports_errors() {
    let aip = codec(Context::Base, &[0x82]);
    // Wrong value kind for the codec.
    assert_eq!(aip.encode(&Value::Number(1)), Err(CodecError::InvalidValue));
    // Value too large for the two-byte field.
    assert_eq!(
        aip.encode(&Value::Flags(0x1_0000)),
        Err(CodecError::InvalidValue)
    );

    let mut small = [0u8; 1];
    assert_eq!(
        aip.encode_into(&Value::Flags(0x2000), &mut small),
        Err(CodecError::BufferTooShort)
    );
    let mut exact = [0u8; 4];
    assert_eq!(aip.encode_into(&Value::Flags(0x2000), &mut exact), Ok(2));
    assert_eq!(&exact[..2], &[0x20, 0x00]);
}

#[test]
fn codec_errors_display_the_c_description() {
    assert!(!CodecError::InvalidValue.to_string().is_empty());
    assert_eq!(
        CodecError::from_code(CodecError::BufferTooShort.code()),
        Some(CodecError::BufferTooShort)
    );
    assert_eq!(CodecError::from_code(0), None);
    assert_eq!(CodecError::from_code(999), Some(CodecError::Unknown(999)));
    let _: &dyn std::error::Error = &CodecError::Unsupported;
}

#[test]
fn value_kinds_describe_themselves() {
    assert_eq!(ValueKind::Flags.description(), "Bit flags");
    assert!(!ValueKind::Bytes.has_codec());
    assert!(ValueKind::Track2.has_codec());
}

#[test]
fn reader_and_dictionary_decode_a_gpo_response() {
    let gpo = [
        0x77, 0x0A, 0x82, 0x02, 0x20, 0x00, 0x94, 0x04, 0x08, 0x01, 0x01, 0x00,
    ];
    let template = Reader::with_format(&gpo, Format::Ber)
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(template.tag().as_bytes(), &[0x77]);

    let mut decoded = Vec::new();
    for entry in Reader::with_format(template.value(), Format::Ber) {
        let entry = entry.unwrap();
        let definition = emv::find(Context::Base, entry.tag()).unwrap();
        definition.validate_length(entry.value().len()).unwrap();
        let value = definition.codec().unwrap().decode(entry.value()).unwrap();
        decoded.push((definition.name(), value));
    }
    assert_eq!(decoded[0], ("aip", Value::Flags(0x2000)));
    assert_eq!(
        decoded[1],
        (
            "afl",
            Value::Afl(vec![AflEntry {
                sfi: 1,
                first_record: 1,
                last_record: 1,
                offline_auth_record_count: 0
            }])
        )
    );
}
