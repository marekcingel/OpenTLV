import pytest

from opentlv import Entry, Format, InvalidTagSizeError, Reader, Tag, Writer, encoded_size


def test_write_produces_the_same_bytes_as_the_default_format_example():
    writer = Writer()
    writer.write(Tag(b"\x01"), b"\xaa\xbb")
    writer.write(Tag(b"\x02"), b"")
    assert writer.bytes() == bytes([0x01, 0x02, 0xAA, 0xBB, 0x02, 0x00])


def test_write_accepts_raw_bytes_as_a_tag():
    writer = Writer()
    writer.write(b"\x01", b"\xaa")
    assert writer.bytes() == bytes([0x01, 0x01, 0xAA])


def test_position_and_len_track_bytes_written():
    writer = Writer()
    assert writer.position == 0
    assert len(writer) == 0
    writer.write(Tag(b"\x01"), b"\xaa\xbb")
    assert writer.position == 4
    assert len(writer) == 4


def test_grows_past_the_initial_capacity_without_error():
    writer = Writer()
    value = bytes(500)
    writer.write(Tag(b"\x01"), value)
    # 500 needs the default format's 2-byte long-form length (0x82 0x01 0xF4).
    assert writer.bytes() == bytes([0x01, 0x82, 0x01, 0xF4]) + value


def test_write_entry_round_trips_a_reader_entry():
    (entry,) = list(Reader(bytes([0x01, 0x02, 0xAA, 0xBB])))
    writer = Writer()
    writer.write_entry(entry)
    assert writer.bytes() == bytes([0x01, 0x02, 0xAA, 0xBB])


def test_default_format_rejects_a_multi_byte_tag():
    writer = Writer()
    with pytest.raises(InvalidTagSizeError):
        writer.write(Tag(b"\x9f\x02"), b"")


def test_writes_other_formats():
    writer = Writer(Format.BER)
    writer.write(Tag(b"\x9f\x02"), b"\xaa")
    reader = Reader(writer.bytes(), Format.BER)
    (entry,) = list(reader)
    assert entry == Entry(Tag(b"\x9f\x02"), memoryview(b"\xaa"))


def test_repr_shows_format_and_position():
    writer = Writer()
    writer.write(Tag(b"\x01"), b"\xaa")
    assert repr(writer) == "Writer(format=<Format.DEFAULT: 0>, position=3)"


def test_encoded_size_matches_what_write_produces():
    tag = Tag(b"\x01")
    size = encoded_size(tag, 3)
    writer = Writer()
    writer.write(tag, b"\xaa\xbb\xcc")
    assert size == len(writer)


def test_encoded_size_accepts_raw_bytes_as_a_tag():
    assert encoded_size(b"\x01", 3) == 5
