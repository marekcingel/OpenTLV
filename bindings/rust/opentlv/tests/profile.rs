//! Integration tests for profile and format selection.

use opentlv::{
    Entry, Error, Format, Limits, Profile, ProfileError, Reader, Strictness, Tag, Writer,
};

fn tag(bytes: &[u8]) -> Tag {
    Tag::from_bytes(bytes)
}

#[test]
fn formats_are_selected_by_name() {
    for format in Format::ALL {
        assert_eq!(format.name().parse::<Format>(), Ok(format));
        assert_eq!(format.to_string(), format.name());
    }
    assert_eq!("DER".parse::<Format>(), Ok(Format::Der));
    assert_eq!("nope".parse::<Format>(), Err(Error::InvalidArg));
}

#[test]
fn selected_format_drives_reader_and_writer() {
    let format: Format = "ber".parse().unwrap();
    let mut buf = [0u8; 16];
    let mut writer = Writer::with_format(&mut buf, format);
    writer.write(&tag(&[0x05]), &[0xAA]).unwrap();
    let encoded = writer.finish();
    assert_eq!(encoded, &[0x05, 0x01, 0xAA]);
    let entry = Reader::with_format(encoded, format)
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(entry.value(), &[0xAA]);
}

#[test]
fn profiles_map_to_formats_and_have_default_limits() {
    assert_eq!(Profile::Der.format(), Format::Der);
    assert_eq!(Profile::Cer.format(), Format::Cer);
    for profile in Profile::ALL {
        let limits = profile.default_limits();
        assert!(limits.max_depth > 0 && limits.max_elements > 0);
    }
}

#[test]
fn der_validation_is_canonical() {
    let limits = Profile::Der.default_limits();
    let check = |data: &[u8]| Profile::Der.validate(data, &limits, Strictness::Canonical);

    assert_eq!(check(&[]), Ok(()));
    assert_eq!(check(&[0x02, 0x01, 0x05]), Ok(()));
    // Non-minimal length encoding.
    assert!(check(&[0x02, 0x81, 0x01, 0x05]).is_err());
    // Indefinite length is not DER.
    assert!(check(&[0x30, 0x80, 0x00, 0x00]).is_err());
}

#[test]
fn errors_carry_the_offset_of_the_failure() {
    let limits = Profile::Der.default_limits();
    let data = [0x02, 0x01, 0x05, 0x02, 0x81, 0x01, 0x05];
    let err: ProfileError = Profile::Der
        .validate(&data, &limits, Strictness::Canonical)
        .unwrap_err();
    assert!(err.offset >= 3, "offset {}", err.offset);
    assert_eq!(Error::from(err), err.error);
    assert!(err.to_string().contains("offset"));
}

#[test]
fn strict_validation_checks_universal_content() {
    let limits = Profile::Der.default_limits();
    // BOOLEAN TRUE must be encoded as FF in DER.
    let data = [0x01, 0x01, 0x01];
    assert_eq!(
        Profile::Der.validate(&data, &limits, Strictness::Canonical),
        Ok(())
    );
    let err = Profile::Der
        .validate(&data, &limits, Strictness::Strict)
        .unwrap_err();
    assert_eq!(err.error, Error::InvalidValue);
    assert_eq!(
        Profile::Der.validate(&[0x01, 0x01, 0xFF], &limits, Strictness::Strict),
        Ok(())
    );
}

#[test]
fn limits_are_enforced() {
    let mut limits = Profile::Der.default_limits();
    limits.max_input_size = 2;
    let err = Profile::Der
        .validate(&[0x02, 0x01, 0x05], &limits, Strictness::Canonical)
        .unwrap_err();
    assert_eq!(err.error, Error::Limit);

    let tight = Limits {
        max_depth: 0,
        ..Profile::Der.default_limits()
    };
    let nested = [0x30, 0x03, 0x02, 0x01, 0x05];
    assert_eq!(
        Profile::Der
            .validate(&nested, &tight, Strictness::Canonical)
            .unwrap_err()
            .error,
        Error::Limit
    );
}

#[test]
fn cer_requires_indefinite_constructed_lengths() {
    let indefinite = [0x30, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00];
    let cer = Profile::Cer.default_limits();
    let der = Profile::Der.default_limits();
    assert_eq!(
        Profile::Cer.validate(&indefinite, &cer, Strictness::Canonical),
        Ok(())
    );
    assert!(Profile::Der
        .validate(&indefinite, &der, Strictness::Canonical)
        .is_err());
    let definite = [0x30, 0x03, 0x02, 0x01, 0x05];
    assert!(Profile::Cer
        .validate(&definite, &cer, Strictness::Canonical)
        .is_err());
    assert_eq!(
        Profile::Der.validate(&definite, &der, Strictness::Canonical),
        Ok(())
    );
}

#[test]
fn read_returns_the_first_element_and_its_size() {
    let limits = Profile::Der.default_limits();
    let data = [0x04, 0x02, 0xAB, 0xCD, 0xFF];
    let (entry, consumed): (Entry<'_>, usize) = Profile::Der
        .read(&data, &limits, Strictness::Strict)
        .unwrap();
    assert_eq!(entry.tag().as_bytes(), &[0x04]);
    assert_eq!(entry.value(), &[0xAB, 0xCD]);
    assert_eq!(consumed, 4);

    assert_eq!(
        Profile::Der
            .read(&[], &limits, Strictness::Canonical)
            .unwrap_err()
            .error,
        Error::EndOfBuffer
    );
}

#[test]
fn write_produces_canonical_bytes() {
    let limits = Profile::Der.default_limits();
    let octets = tag(&[0x04]);
    let value = [0xAB; 200];

    let size = Profile::Der
        .encoded_size(&octets, &value, &limits, Strictness::Strict)
        .unwrap();
    assert_eq!(size, 203); // tag, two length bytes (81 C8), 200 value bytes
    let mut out = vec![0u8; size];
    let written = Profile::Der
        .write(&octets, &value, &limits, Strictness::Strict, &mut out)
        .unwrap();
    assert_eq!(written, size);
    assert_eq!(&out[..3], &[0x04, 0x81, 0xC8]);

    // What was written reads back through the same profile.
    let (entry, consumed) = Profile::Der
        .read(&out, &limits, Strictness::Strict)
        .unwrap();
    assert_eq!((entry.value(), consumed), (&value[..], size));

    let mut short = [0u8; 4];
    assert_eq!(
        Profile::Der
            .write(&octets, &value, &limits, Strictness::Strict, &mut short)
            .unwrap_err()
            .error,
        Error::BufferTooShort
    );
}

#[test]
fn write_rejects_noncanonical_children() {
    let limits = Profile::Der.default_limits();
    let sequence = tag(&[0x30]);
    let mut out = [0u8; 16];
    // The child has a non-minimal length, so it is not canonical DER.
    let err = Profile::Der
        .write(
            &sequence,
            &[0x02, 0x81, 0x01, 0x05],
            &limits,
            Strictness::Canonical,
            &mut out,
        )
        .unwrap_err();
    assert_ne!(err.error, Error::BufferTooShort);
    let ok = Profile::Der
        .write(
            &sequence,
            &[0x02, 0x01, 0x05],
            &limits,
            Strictness::Canonical,
            &mut out,
        )
        .unwrap();
    assert_eq!(&out[..ok], &[0x30, 0x03, 0x02, 0x01, 0x05]);
}
