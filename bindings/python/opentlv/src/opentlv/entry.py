"""The decoded TLV element type."""

from __future__ import annotations

from opentlv.tag import Tag


class Entry:
    """A decoded TLV element: a tag and a value.

    `value` is a ``memoryview`` onto the buffer the owning `Reader` was
    created from, so reading it is zero-copy; it becomes unusable once that
    buffer is released or, for a mutable buffer, resized.
    """

    __slots__ = ("_tag", "_value")

    def __init__(self, tag: Tag, value: memoryview) -> None:
        self._tag = tag
        self._value = value

    @property
    def tag(self) -> Tag:
        """The element's tag."""
        return self._tag

    @property
    def value(self) -> memoryview:
        """The element's value, as a zero-copy view onto the input buffer."""
        return self._value

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Entry):
            return self._tag == other._tag and self._value == other._value
        return NotImplemented

    def __repr__(self) -> str:
        return f"Entry(tag={self._tag!r}, value={bytes(self._value)!r})"
