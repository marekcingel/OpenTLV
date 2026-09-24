import opentlv_native as native

from opentlv.error import (
    BufferTooShortError,
    EndOfBufferError,
    InvalidArgError,
    InvalidByteOrderError,
    InvalidLengthError,
    InvalidTagError,
    InvalidTagSizeError,
    InvalidValueError,
    LimitError,
    NullArgError,
    OpenTLVError,
    OutOfMemoryError,
    SchemaError,
    SchemaMissingError,
    UnsupportedTypeError,
    ValueOverflowError,
    VisitorError,
    _from_native,
)

KNOWN = [
    (1, BufferTooShortError),
    (2, InvalidLengthError),
    (3, NullArgError),
    (4, OutOfMemoryError),
    (5, EndOfBufferError),
    (6, InvalidTagError),
    (7, VisitorError),
    (8, LimitError),
    (9, SchemaError),
    (10, InvalidArgError),
    (11, InvalidTagSizeError),
    (12, InvalidByteOrderError),
    (13, ValueOverflowError),
    (14, InvalidValueError),
    (15, UnsupportedTypeError),
    (16, SchemaMissingError),
]


def test_every_known_code_maps_to_its_typed_error():
    for code, error_type in KNOWN:
        native_error = native.Error({"code": code})
        error = _from_native(native_error)
        assert isinstance(error, error_type)
        assert isinstance(error, OpenTLVError)
        assert error.code == code
        assert str(error) == native.strerror(code)


def test_unknown_code_falls_back_to_the_base_error():
    native_error = native.Error({"code": 999})
    error = _from_native(native_error)
    assert type(error) is OpenTLVError
    assert error.code == 999


def test_missing_keys_default_to_none():
    native_error = native.Error({"code": 1})
    error = _from_native(native_error)
    assert error.offset is None
    assert error.expected is None
    assert error.actual is None
    assert error.operation is None
    assert error.tag is None
    assert error.length is None
    assert error.required is None
    assert error.available is None


def test_reader_diagnostic_fields_are_carried_through():
    native_error = native.Error({
        "code": 1,
        "offset": 4,
        "expected": "at least 2 bytes",
        "actual": "0 bytes",
        "operation": "value",
        "tag": b"\x9f\x02",
    })
    error = _from_native(native_error)
    assert error.offset == 4
    assert error.expected == "at least 2 bytes"
    assert error.actual == "0 bytes"
    assert error.operation == "value"
    assert error.tag == b"\x9f\x02"


def test_writer_diagnostic_fields_are_carried_through():
    native_error = native.Error({
        "code": 1,
        "operation": "value",
        "length": 10,
        "required": 12,
        "available": 8,
    })
    error = _from_native(native_error)
    assert error.length == 10
    assert error.required == 12
    assert error.available == 8
