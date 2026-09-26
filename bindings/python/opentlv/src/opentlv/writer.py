"""Sequential writer over a self-managed, growable buffer."""

from __future__ import annotations

from typing import Union

import opentlv_native as _native

from opentlv.entry import Entry
from opentlv.error import BufferTooShortError, _from_native
from opentlv.fixed_format import FixedFormat
from opentlv.format import Format
from opentlv.tag import Tag

Value = Union[bytes, bytearray, memoryview]
AnyFormat = Union[Format, FixedFormat]

_INITIAL_CAPACITY = 64


class Writer:
    """A sequential writer that encodes TLV entries into a growable buffer.

    Unlike the C library's `tlv_writer_t`, which fills a caller-provided
    fixed-capacity buffer, `Writer` owns a `bytearray` that grows as needed:
    `write` never fails for lack of space, only for an error the format
    itself reports (for example an unsupported tag size).

    >>> writer = Writer()
    >>> writer.write(Tag(b"\\x01"), b"\\xaa\\xbb")
    >>> writer.write(Tag(b"\\x02"), b"")
    >>> writer.bytes()
    b'\\x01\\x02\\xaa\\xbb\\x02\\x00'
    """

    __slots__ = ("_buffer", "_pos", "_format")

    def __init__(self, format: AnyFormat = Format.DEFAULT) -> None:
        self._buffer = bytearray(_INITIAL_CAPACITY)
        self._pos = 0
        self._format = format

    @property
    def format(self) -> AnyFormat:
        """The wire format this writer encodes."""
        return self._format

    @property
    def position(self) -> int:
        """The number of bytes written so far."""
        return self._pos

    def _write_native(self, offset: int, tag_bytes: bytes, value: Value) -> int:
        if isinstance(self._format, FixedFormat):
            return _native.write_fixed(self._buffer, offset, tag_bytes, value,
                                       self._format.tag_size, self._format.length_size,
                                       self._format.big_endian)
        return _native.write(self._buffer, offset, tag_bytes, value, self._format)

    def write(self, tag: Union[Tag, bytes], value: Value) -> None:
        """Appends one entry with `tag` and `value`."""
        tag_bytes = tag.data if isinstance(tag, Tag) else tag
        try:
            written = self._write_native(self._pos, tag_bytes, value)
        except _native.Error as native_error:
            error = _from_native(native_error)
            if not (isinstance(error, BufferTooShortError) and error.required is not None):
                raise error from None
            self._grow(self._pos + error.required)
            try:
                written = self._write_native(self._pos, tag_bytes, value)
            except _native.Error as retry_error:
                raise _from_native(retry_error) from None
        self._pos += written

    def write_entry(self, entry: Entry) -> None:
        """Appends a decoded `Entry`, for example one produced by a `Reader`."""
        self.write(entry.tag, entry.value)

    def _grow(self, min_capacity: int) -> None:
        capacity = len(self._buffer)
        while capacity < min_capacity:
            capacity *= 2
        self._buffer.extend(bytes(capacity - len(self._buffer)))

    def bytes(self) -> bytes:
        """Returns the bytes written so far, as a new `bytes` object."""
        return bytes(self._buffer[:self._pos])

    def __len__(self) -> int:
        return self._pos

    def __repr__(self) -> str:
        return f"Writer(format={self._format!r}, position={self._pos})"


def encoded_size(tag: Union[Tag, bytes], value_length: int,
                 format: AnyFormat = Format.DEFAULT) -> int:
    """Returns the encoded size of an element with `tag` and a value of
    `value_length` bytes in `format`, without writing anything.

    >>> encoded_size(Tag(b"\\x01"), 3)
    5
    """
    tag_bytes = tag.data if isinstance(tag, Tag) else tag
    try:
        if isinstance(format, FixedFormat):
            return _native.encoded_size_fixed(tag_bytes, value_length, format.tag_size,
                                              format.length_size, format.big_endian)
        return _native.encoded_size(tag_bytes, value_length, format)
    except _native.Error as native_error:
        raise _from_native(native_error) from None
