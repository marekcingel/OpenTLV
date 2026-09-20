//! Integration tests for the length and structural schema wrappers.

use opentlv::emv::Context;
use opentlv::{
    Error, Format, Kind, LengthRule, LengthSchema, StructureRule, StructureSchema, Tag,
    ValidationLimits,
};

fn tag(bytes: &[u8]) -> Tag {
    Tag::from_bytes(bytes).unwrap()
}

fn limits() -> ValidationLimits {
    ValidationLimits::default()
}

#[test]
fn length_schema_finds_and_validates() {
    let schema = LengthSchema::new([
        LengthRule::new(tag(&[0x01]), 2, 4),
        LengthRule::exact(tag(&[0x02]), 1),
    ]);
    assert_eq!(schema.len(), 2);
    assert_eq!(
        schema.find(&tag(&[0x02])),
        Some(LengthRule::exact(tag(&[0x02]), 1))
    );
    assert_eq!(schema.find(&tag(&[0x03])), None);

    assert_eq!(schema.validate_length(&tag(&[0x01]), 2), Ok(()));
    assert_eq!(schema.validate_length(&tag(&[0x01]), 4), Ok(()));
    assert_eq!(
        schema.validate_length(&tag(&[0x01]), 1),
        Err(Error::InvalidLength)
    );
    assert_eq!(
        schema.validate_length(&tag(&[0x01]), 5),
        Err(Error::InvalidLength)
    );
    assert_eq!(schema.validate_length(&tag(&[0x03]), 1), Err(Error::Schema));
}

#[test]
fn empty_length_schema_knows_no_tag() {
    let schema = LengthSchema::new([]);
    assert!(schema.is_empty());
    assert_eq!(schema.validate_length(&tag(&[0x01]), 0), Err(Error::Schema));
}

#[test]
fn emv_length_schema_uses_the_builtin_dictionary() {
    let schema = LengthSchema::emv();
    assert!(!schema.is_empty());
    let amount = tag(&[0x9F, 0x02]);
    assert_eq!(schema.find(&amount), Some(LengthRule::exact(amount, 6)));
    assert_eq!(schema.validate_length(&amount, 6), Ok(()));
    assert_eq!(
        schema.validate_length(&amount, 5),
        Err(Error::InvalidLength)
    );
    // Contexts are explicit: 9F02 is not part of the biometric context.
    assert_eq!(LengthSchema::emv_for(Context::Bht).find(&amount), None);
}

/// Tag 01 is required exactly once with two bytes, tag 02 is an optional
/// primitive, and tag 30 holds one or two items of tag 11.
fn message_schema() -> StructureSchema {
    let items = StructureSchema::new(
        [StructureRule::new(tag(&[0x11])).length(1, 2).occurs(1, 2)],
        false,
    );
    StructureSchema::new(
        [
            StructureRule::new(tag(&[0x01]))
                .length(2, 2)
                .required_once(),
            StructureRule::new(tag(&[0x02])).kind(Kind::Primitive),
            StructureRule::new(tag(&[0x30])).children(items),
        ],
        false,
    )
}

#[test]
fn structure_schema_accepts_conforming_data() {
    let data = [
        0x01, 0x02, 0xAA, 0xBB, // required tag
        0x02, 0x00, // optional primitive
        0x30, 0x07, 0x11, 0x01, 0x01, 0x11, 0x02, 0x02, 0x03, // container with two items
    ];
    assert_eq!(
        message_schema().validate(&data, Format::Ber, &limits()),
        Ok(())
    );
}

#[test]
fn missing_required_field_reports_schema_missing() {
    let err = message_schema()
        .validate(&[0x02, 0x00], Format::Ber, &limits())
        .unwrap_err();
    assert_eq!(err.error, Error::SchemaMissing);
    // Reported at the end of the parent's value: here the end of the input.
    assert_eq!(err.offset, 2);
}

#[test]
fn duplicate_of_a_once_only_tag_is_a_schema_error() {
    let data = [0x01, 0x02, 0xAA, 0xBB, 0x01, 0x02, 0xCC, 0xDD];
    let err = message_schema()
        .validate(&data, Format::Ber, &limits())
        .unwrap_err();
    assert_eq!(err.error, Error::Schema);
}

#[test]
fn length_violation_reports_invalid_length_at_the_element() {
    let data = [0x01, 0x03, 0xAA, 0xBB, 0xCC];
    let err = message_schema()
        .validate(&data, Format::Ber, &limits())
        .unwrap_err();
    assert_eq!((err.error, err.offset), (Error::InvalidLength, 0));
}

#[test]
fn unknown_tag_is_rejected_unless_allowed() {
    let strict = StructureSchema::new([StructureRule::new(tag(&[0x01]))], false);
    let lenient = StructureSchema::new([StructureRule::new(tag(&[0x01]))], true);
    let data = [0x01, 0x00, 0x09, 0x00];
    let err = strict.validate(&data, Format::Ber, &limits()).unwrap_err();
    assert_eq!((err.error, err.offset), (Error::Schema, 2));
    assert_eq!(lenient.validate(&data, Format::Ber, &limits()), Ok(()));
}

#[test]
fn kind_mismatch_is_a_schema_error() {
    // 0x30 is constructed in BER, but the rule demands a primitive.
    let schema = StructureSchema::new(
        [StructureRule::new(tag(&[0x30])).kind(Kind::Primitive)],
        false,
    );
    let err = schema
        .validate(&[0x30, 0x00], Format::Ber, &limits())
        .unwrap_err();
    assert_eq!(err.error, Error::Schema);
}

#[test]
fn format_decides_which_values_are_nested() {
    // The child claims five bytes but only zero remain inside the container.
    let opaque = StructureSchema::new([StructureRule::new(tag(&[0x30]))], false);
    let data = [0x30, 0x02, 0x11, 0x05];
    // The default format has no constructed values, so the content is opaque.
    assert_eq!(opaque.validate(&data, Format::Default, &limits()), Ok(()));
    // In BER the container is walked and its malformed child is reported.
    assert!(opaque.validate(&data, Format::Ber, &limits()).is_err());
}

#[test]
fn limits_are_enforced() {
    let schema = StructureSchema::new([], true);
    let data = [0x01, 0x00, 0x02, 0x00];
    let tight = ValidationLimits {
        max_depth: 4,
        max_elements: 1,
    };
    let err = schema.validate(&data, Format::Ber, &tight).unwrap_err();
    assert_eq!(err.error, Error::Limit);
}

#[test]
fn malformed_framing_is_reported() {
    let schema = StructureSchema::new([], true);
    let err = schema
        .validate(&[0x01, 0x05, 0x00], Format::Ber, &limits())
        .unwrap_err();
    assert!(matches!(
        err.error,
        Error::BufferTooShort | Error::InvalidLength
    ));
}

#[test]
fn emv_structure_schema_validates_an_fci() {
    let schema = StructureSchema::emv();
    let fci = [
        0x6F, 0x09, 0x84, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10,
    ];
    assert_eq!(schema.validate(&fci, Format::Ber, &limits()), Ok(()));

    // DF Name is mandatory.
    let err = schema
        .validate(&[0x6F, 0x00], Format::Ber, &limits())
        .unwrap_err();
    assert_eq!(err.error, Error::SchemaMissing);

    // Application Label is not allowed directly under the FCI template.
    let bad = [0x6F, 0x0A, 0x84, 0x05, 1, 2, 3, 4, 5, 0x50, 0x01, 0x41];
    let err = schema.validate(&bad, Format::Ber, &limits()).unwrap_err();
    assert_eq!((err.error, err.offset), (Error::Schema, 9));
}

#[test]
fn emv_structure_schema_validates_a_gpo_response() {
    let schema = StructureSchema::emv();
    let gpo = [
        0x77, 0x0A, 0x82, 0x02, 0x20, 0x00, 0x94, 0x04, 0x08, 0x01, 0x01, 0x00,
    ];
    assert_eq!(schema.validate(&gpo, Format::Ber, &limits()), Ok(()));
    let missing_afl = [0x77, 0x04, 0x82, 0x02, 0x20, 0x00];
    let err = schema
        .validate(&missing_afl, Format::Ber, &limits())
        .unwrap_err();
    assert_eq!(err.error, Error::SchemaMissing);
}

#[test]
fn schemas_can_be_shared_across_threads() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<LengthSchema>();
    assert_send_sync::<StructureSchema>();

    let schema = std::sync::Arc::new(message_schema());
    let handle = {
        let schema = schema.clone();
        std::thread::spawn(move || {
            schema.validate(&[0x01, 0x02, 0xAA, 0xBB], Format::Ber, &limits())
        })
    };
    assert_eq!(handle.join().unwrap(), Ok(()));
}

#[test]
fn moving_a_schema_keeps_nested_tables_valid() {
    let moved = *Box::new(message_schema());
    let schemas = vec![moved, message_schema()];
    let data = [0x01, 0x02, 0xAA, 0xBB, 0x30, 0x03, 0x11, 0x01, 0x01];
    for schema in schemas {
        assert_eq!(schema.validate(&data, Format::Ber, &limits()), Ok(()));
    }
}
