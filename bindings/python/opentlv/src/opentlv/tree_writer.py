"""Bounded owned buffers around the canonical C Tree Writer."""
import opentlv_native as _native
from opentlv.error import _from_native
from opentlv.fixed_format import FixedFormat
from opentlv.format import _resolve_format
from opentlv.tag import Tag


class TreeWriter:
    """Own output, scratch and frame storage; all encoding is performed by C.

    Capacity never grows implicitly. Open tags remain alive until end(). bytes()
    returns only the finalized prefix; finish() rejects unclosed parents.
    """
    __slots__ = ("_capsule",)

    def __init__(self, capacity, format=None, *, scratch_capacity=None,
                 frame_capacity=64, max_depth=64, max_elements=65536):
        format = _resolve_format(format)
        fixed = isinstance(format, FixedFormat)
        if scratch_capacity is None:
            scratch_capacity = capacity
        try:
            self._capsule = _native.tree_writer_create(
                -1 if fixed else format, capacity, scratch_capacity, frame_capacity,
                max_depth, max_elements, format.tag_size if fixed else 0,
                format.length_size if fixed else 0, format.big_endian if fixed else True)
        except _native.Error as error:
            raise _from_native(error) from None

    def _action(self, operation, *args):
        try:
            return _native.tree_writer_action(self._capsule, operation, *args)
        except _native.Error as error:
            raise _from_native(error) from None

    def begin(self, tag: Tag | bytes) -> None:
        """Open a constructed item, retaining immutable tag bytes until successful end."""
        self._action(0, tag.data if isinstance(tag, Tag) else bytes(memoryview(tag)))

    def write(self, element) -> None:
        """Append a semantic Element through C; no tag/value input is retained."""
        self._action(1, element.tag.data, bytes(element.value))

    def end(self) -> None:
        """Close the innermost parent; failure preserves state and output."""
        self._action(2)

    def bytes(self) -> bytes:
        """Copy finalized output; open roots are excluded."""
        return self._action(4)

    def finish(self) -> bytes:
        """Require all parents closed and copy finalized output; does not seal the writer."""
        return self._action(3)

    @classmethod
    def measure(cls, items, capacity, format=None, *, scratch_capacity=None,
                frame_capacity=64, max_depth=64, max_elements=65536) -> bytes:
        """Measure and stage preorder ``(Element, depth, constructed)`` records.

        Returns the staged encoding; its length is the exact measured size.
        C owns parent closure and validates preorder depth and classification.
        The source is consumed even on failure. Workspace exhaustion exceptions
        expose required_data and required_scratch lower bounds; retry with a
        fresh source. Those fields are zero for other native failures.
        """
        writer = cls(capacity, format, scratch_capacity=scratch_capacity,
                     frame_capacity=frame_capacity, max_depth=max_depth,
                     max_elements=max_elements)
        records = ((element.tag.data, bytes(element.value), depth, constructed)
                   for element, depth, constructed in items)
        try:
            return _native.tree_writer_measure(writer._capsule, records)
        except _native.Error as native_error:
            error = _from_native(native_error)
            error.required_data = getattr(native_error, "required_data", 0)
            error.required_scratch = getattr(native_error, "required_scratch", 0)
            raise error from None
