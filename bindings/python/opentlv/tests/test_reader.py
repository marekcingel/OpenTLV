import pytest

from opentlv import BufferTooShortError, Entry, InvalidLengthError, OpenTLVError, Reader, Tag


def test_iterates_entries_with_the_default_format():
    data = bytes([0x01, 0x02, 0xAA, 0xBB, 0x02, 0x00])
    entries = list(Reader(data))
    assert entries == [
        Entry(Tag(b"\x01"), memoryview(b"\xaa\xbb")),
        Entry(Tag(b"\x02"), memoryview(b"")),
    ]


def test_value_is_a_zero_copy_view_onto_the_input():
    data = bytearray([0x01, 0x02, 0xAA, 0xBB])
    (entry,) = list(Reader(data))
    assert entry.value.obj is data or bytes(entry.value.obj) == bytes(data)
    assert bytes(entry.value) == b"\xaa\xbb"


def test_accepts_any_buffer_protocol_object():
    payload = bytes([0x01, 0x01, 0x42])
    for data in (payload, bytearray(payload), memoryview(payload)):
        (entry,) = list(Reader(data))
        assert bytes(entry.value) == b"\x42"


def test_rejects_non_buffer_input():
    with pytest.raises(TypeError):
        list(Reader("not bytes"))


def test_empty_input_yields_no_entries():
    reader = Reader(b"")
    assert reader.at_end is True
    assert list(reader) == []


def test_position_and_at_end_track_progress():
    reader = Reader(bytes([0x01, 0x01, 0x42, 0x02, 0x00]))
    assert reader.position == 0
    assert reader.at_end is False
    next(reader)
    assert reader.position == 3
    assert reader.at_end is False
    next(reader)
    assert reader.position == 5
    assert reader.at_end is True
    with pytest.raises(StopIteration):
        next(reader)


def test_truncated_value_raises_buffer_too_short_with_diagnostics():
    reader = Reader(bytes([0x01, 0x05, 0xAA]))
    with pytest.raises(BufferTooShortError) as excinfo:
        next(reader)
    error = excinfo.value
    assert error.code == 1
    assert error.operation == "value"
    assert error.offset == 2
    assert isinstance(error, OpenTLVError)


def test_invalid_length_form_raises_invalid_length_error():
    reader = Reader(bytes([0x01, 0x83]))
    with pytest.raises(InvalidLengthError):
        next(reader)


def test_stops_after_the_first_error_instead_of_retrying():
    reader = Reader(bytes([0x01, 0x05, 0xAA]))
    with pytest.raises(BufferTooShortError):
        next(reader)
    with pytest.raises(StopIteration):
        next(reader)
    assert reader.at_end is False


def test_is_reusable_as_a_plain_iterator():
    reader = Reader(bytes([0x01, 0x00]))
    assert iter(reader) is reader
