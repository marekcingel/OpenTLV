import pytest

from opentlv import (
    Format,
    InvalidLengthError,
    Kind,
    LengthRule,
    LengthSchema,
    SchemaError,
    SchemaMissingError,
    StructureRule,
    StructureSchema,
    Tag,
    Writer,
)


def test_length_schema_validates_within_bounds():
    tag = Tag(b"\x01")
    schema = LengthSchema([LengthRule(tag, 2, 4)])
    schema.validate_length(tag, 2)
    schema.validate_length(tag, 4)
    with pytest.raises(InvalidLengthError):
        schema.validate_length(tag, 1)
    with pytest.raises(InvalidLengthError):
        schema.validate_length(tag, 5)


def test_length_schema_rejects_an_unknown_tag():
    schema = LengthSchema([LengthRule(Tag(b"\x01"), 0, 4)])
    with pytest.raises(SchemaError):
        schema.validate_length(Tag(b"\x99"), 1)


def test_length_schema_exact_requires_one_length():
    tag = Tag(b"\x01")
    schema = LengthSchema([LengthRule.exact(tag, 3)])
    schema.validate_length(tag, 3)
    with pytest.raises(InvalidLengthError):
        schema.validate_length(tag, 4)


def test_length_schema_find_and_len():
    tag = Tag(b"\x01")
    schema = LengthSchema([LengthRule(tag, 2, 4)])
    assert len(schema) == 1
    rule = schema.find(tag)
    assert rule.min_length == 2
    assert rule.max_length == 4
    assert schema.find(Tag(b"\x99")) is None


def test_length_schema_earlier_rule_wins_for_a_repeated_tag():
    tag = Tag(b"\x01")
    schema = LengthSchema([LengthRule(tag, 1, 1), LengthRule(tag, 9, 9)])
    assert schema.find(tag).min_length == 1


def test_structure_schema_accepts_a_present_required_field():
    schema = StructureSchema([StructureRule(Tag(b"\x01"), min_occurs=1, max_occurs=1)])
    schema.validate(bytes([0x01, 0x00]))


def test_structure_schema_reports_a_missing_required_field():
    schema = StructureSchema([StructureRule(Tag(b"\x01"), min_occurs=1, max_occurs=1)])
    with pytest.raises(SchemaMissingError) as excinfo:
        schema.validate(b"")
    assert excinfo.value.offset == 0


def test_structure_schema_rejects_an_unknown_tag_by_default():
    schema = StructureSchema([StructureRule(Tag(b"\x01"), min_occurs=0)])
    with pytest.raises(SchemaError):
        schema.validate(bytes([0x02, 0x00]))


def test_structure_schema_allow_unknown_accepts_it():
    schema = StructureSchema([StructureRule(Tag(b"\x01"), min_occurs=0)], allow_unknown=True)
    schema.validate(bytes([0x02, 0x00]))


def test_structure_schema_rejects_excess_occurrences():
    schema = StructureSchema([StructureRule(Tag(b"\x01"), min_occurs=0, max_occurs=1)])
    with pytest.raises(SchemaError):
        schema.validate(bytes([0x01, 0x00, 0x01, 0x00]))


def test_structure_schema_enforces_length_bounds():
    schema = StructureSchema([StructureRule(Tag(b"\x01"), min_length=2, max_length=2)])
    with pytest.raises(InvalidLengthError):
        schema.validate(bytes([0x01, 0x01, 0xAA]))


def test_structure_schema_validates_nested_children_in_ber():
    inner_tag = Tag(b"\x81")
    outer_tag = Tag(b"\xA0")
    child_schema = StructureSchema(
        [StructureRule(inner_tag, min_occurs=1, max_occurs=1, kind=Kind.PRIMITIVE)])
    outer_schema = StructureSchema(
        [StructureRule(outer_tag, min_occurs=1, max_occurs=1, children=child_schema)])

    inner_writer = Writer(Format.BER)
    inner_writer.write(inner_tag, b"\xAA")
    outer_writer = Writer(Format.BER)
    outer_writer.write(outer_tag, inner_writer.bytes())

    outer_schema.validate(outer_writer.bytes(), format=Format.BER)

    empty_outer = Writer(Format.BER)
    empty_outer.write(outer_tag, b"")
    with pytest.raises(SchemaMissingError):
        outer_schema.validate(empty_outer.bytes(), format=Format.BER)


def test_structure_rule_setting_children_implies_constructed_kind():
    child_schema = StructureSchema([StructureRule(Tag(b"\x81"))])
    rule = StructureRule(Tag(b"\xA0"), children=child_schema)
    assert rule.kind == Kind.CONSTRUCTED


def test_structure_schema_len():
    schema = StructureSchema([StructureRule(Tag(b"\x01")), StructureRule(Tag(b"\x02"))])
    assert len(schema) == 2
