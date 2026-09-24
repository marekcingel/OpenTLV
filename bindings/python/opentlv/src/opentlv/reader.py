"""Sequential reader over a caller-owned buffer."""

from __future__ import annotations

from typing import Iterator, Union

import opentlv_native as _native

from opentlv.entry import Entry
from opentlv.error import _from_native
from opentlv.format import Format
from opentlv.tag import Tag

Buffer = Union[bytes, bytearray, memoryview]


class Reader:
    """A sequential, one-pass reader that parses TLV entries from a buffer.

    `Reader` is a Python iterator over `Entry` values. `data` may be
    `bytes`, `bytearray`, `memoryview`, or any other buffer-protocol object;
    the reader does not copy it, and the entries it yields borrow it, so it
    must stay valid and unchanged for as long as the reader or its entries
    are used.

    After the first error, iteration ends instead of retrying: the
    underlying C reader does not advance past malformed input.

    >>> data = bytes([0x01, 0x02, 0xAA, 0xBB, 0x02, 0x00])
    >>> [(entry.tag.data, bytes(entry.value)) for entry in Reader(data)]
    [(b'\\x01', b'\\xaa\\xbb'), (b'\\x02', b'')]
    """

    __slots__ = ("_data", "_format", "_pos", "_failed")

    def __init__(self, data: Buffer, format: Format = Format.DEFAULT) -> None:
        self._data = data if isinstance(data, memoryview) else memoryview(data)
        self._format = format
        self._pos = 0
        self._failed = False

    @property
    def format(self) -> Format:
        """The wire format this reader parses."""
        return self._format

    @property
    def position(self) -> int:
        """The offset in `data` of the next element to read."""
        return self._pos

    @property
    def at_end(self) -> bool:
        """`True` once all input has been consumed."""
        return self._pos >= len(self._data)

    def __iter__(self) -> Iterator[Entry]:
        return self

    def __next__(self) -> Entry:
        if self._failed or self.at_end:
            raise StopIteration
        try:
            tag_data, value_offset, value_length, consumed = _native.read(
                self._data, self._pos, self._format)
        except _native.Error as native_error:
            self._failed = True
            raise _from_native(native_error) from None
        self._pos += consumed
        value = self._data[value_offset:value_offset + value_length]
        return Entry(Tag(tag_data), value)
