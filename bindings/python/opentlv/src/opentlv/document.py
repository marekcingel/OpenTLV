"""Optional mutable TLV document that owns its data and can be modified and encoded again."""

from __future__ import annotations

from typing import Iterator, Optional, Union

import opentlv_native as _native

from opentlv.error import _from_native
from opentlv.format import Format
from opentlv.tag import Tag

_DEFAULT_MAX_DEPTH = 64
"""TLV_WALK_MAX_DEPTH."""

_DEFAULT_MAX_ELEMENTS = 65536
"""TLV_DOCUMENT_DEFAULT_MAX_ELEMENTS."""


class Node:
    """One element of a `Document`; owned by it.

    A node stays valid until it is erased, its value is replaced, or its
    document is freed or closed; using it afterwards is the same
    use-after-free hazard the C API itself has, not something this binding
    guards against. `Node` holds a reference to its owning `Document`, so
    the document is not freed by garbage collection while a node from it is
    reachable.
    """

    __slots__ = ("_document", "_ptr")

    def __init__(self, document: "Document", ptr: int) -> None:
        self._document = document
        self._ptr = ptr

    @property
    def tag(self) -> Tag:
        """The node's tag."""
        return Tag(_native.node_tag(self._ptr))

    @property
    def is_constructed(self) -> bool:
        """`True` if the node's value holds nested elements."""
        return _native.node_is_constructed(self._ptr)

    @property
    def value(self) -> bytes:
        """The node's value bytes; empty for a constructed node (read its
        children instead)."""
        return _native.node_value(self._ptr)

    @value.setter
    def value(self, value: bytes) -> None:
        """Replaces the value. For a constructed node, `value` is parsed as
        nested elements with the document's reader format, replacing every
        child."""
        try:
            _native.node_set_value(self._ptr, value)
        except _native.Error as native_error:
            raise _from_native(native_error) from None

    @property
    def parent(self) -> Optional["Node"]:
        """The parent node, or `None` for a top-level node."""
        return self._document._wrap(_native.node_parent(self._ptr))

    @property
    def first_child(self) -> Optional["Node"]:
        """The first child of a constructed node, or `None`."""
        return self._document._wrap(_native.node_first_child(self._ptr))

    @property
    def next(self) -> Optional["Node"]:
        """The next sibling, or `None`."""
        return self._document._wrap(_native.node_next(self._ptr))

    def next_same_tag(self) -> Optional["Node"]:
        """The next sibling with the same tag as this node, or `None`."""
        return self._document._wrap(_native.node_next_same_tag(self._ptr))

    def __iter__(self) -> Iterator["Node"]:
        """Iterates this node's direct children, in encoding order."""
        child = self.first_child
        while child is not None:
            yield child
            child = child.next

    def find(self, tag: Union[Tag, bytes]) -> Optional["Node"]:
        """Finds the first direct child with `tag`."""
        return self._document.find(tag, parent=self)

    def insert(self, tag: Union[Tag, bytes], value: bytes = b"",
               before: Optional["Node"] = None) -> "Node":
        """Inserts a new child element; see `Document.insert`."""
        return self._document.insert(tag, value, parent=self, before=before)

    def erase(self) -> None:
        """Removes this node and all of its descendants from its document."""
        _native.node_erase(self._ptr)

    @property
    def encoded_size(self) -> int:
        """The encoded size of this element with its descendants."""
        try:
            return _native.node_encoded_size(self._ptr)
        except _native.Error as native_error:
            raise _from_native(native_error) from None

    def encode(self) -> bytes:
        """Encodes this element with its descendants."""
        try:
            return _native.node_encode(self._ptr)
        except _native.Error as native_error:
            raise _from_native(native_error) from None

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Node):
            return self._ptr == other._ptr and self._document is other._document
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self._ptr)

    def __repr__(self) -> str:
        kind = "constructed" if self.is_constructed else "primitive"
        return f"Node(tag={self.tag!r}, {kind})"


class Document:
    """An owned, mutable TLV document: parses input into a tree of nodes that
    can be searched, changed, extended and shortened, then encoded again.

    Unlike `Reader`/`Writer`, a document copies every tag and value into its
    own storage, so it is the only part of OpenTLV that allocates beyond a
    Python object's own memory. Close it deterministically with `close()` or
    a `with` block instead of waiting for garbage collection when that
    matters, for example for a large document.

    >>> document = Document(bytes([0x01, 0x02, 0xAA, 0xBB]))
    >>> node = document.first
    >>> node.tag.data, node.value
    (b'\\x01', b'\\xaa\\xbb')
    >>> node.value = b"\\xcc"
    >>> document.encode()
    b'\\x01\\x01\\xcc'
    """

    __slots__ = ("_capsule",)

    def __init__(self, data: Optional[bytes] = None, format: Format = Format.DEFAULT, *,
                 reader_format: Optional[Format] = None, writer_format: Optional[Format] = None,
                 max_depth: int = _DEFAULT_MAX_DEPTH,
                 max_elements: int = _DEFAULT_MAX_ELEMENTS) -> None:
        """Creates a document, empty or parsed from `data`.

        `format` sets both the reader format (used to parse `data` and any
        constructed value later assigned to a node) and the writer format
        (used to `encode()`); pass `reader_format`/`writer_format`
        separately to use different formats for parsing and encoding.
        """
        reader_format = format if reader_format is None else reader_format
        writer_format = format if writer_format is None else writer_format
        try:
            if data is None:
                self._capsule = _native.document_create(reader_format, writer_format, max_depth,
                                                         max_elements)
            else:
                self._capsule = _native.document_parse(data, reader_format, writer_format,
                                                        max_depth, max_elements)
        except _native.Error as native_error:
            raise _from_native(native_error) from None

    def _wrap(self, ptr: Optional[int]) -> Optional[Node]:
        return None if ptr is None else Node(self, ptr)

    def __len__(self) -> int:
        """The number of elements in the document, including nested ones."""
        return _native.document_count(self._capsule)

    @property
    def first(self) -> Optional[Node]:
        """The first top-level node, or `None` for an empty document."""
        return self._wrap(_native.document_first(self._capsule))

    def __iter__(self) -> Iterator[Node]:
        """Iterates the top-level nodes, in encoding order."""
        node = self.first
        while node is not None:
            yield node
            node = node.next

    def find(self, tag: Union[Tag, bytes], parent: Optional[Node] = None) -> Optional[Node]:
        """Finds the first direct child of `parent` (or the top level) with `tag`."""
        tag_bytes = tag.data if isinstance(tag, Tag) else tag
        parent_ptr = parent._ptr if parent is not None else None
        return self._wrap(_native.document_find(self._capsule, parent_ptr, tag_bytes))

    def find_path(self, query: str) -> Optional[Node]:
        """Finds the first element addressed by a path query, for example `"6F/A5/50"`."""
        try:
            return self._wrap(_native.document_find_path(self._capsule, query))
        except _native.Error as native_error:
            raise _from_native(native_error) from None

    def insert(self, tag: Union[Tag, bytes], value: bytes = b"", parent: Optional[Node] = None,
               before: Optional[Node] = None) -> Node:
        """Inserts a new element with `tag` and `value`.

        `parent` is the constructed node that receives the element, or
        `None` for the top level; `before` is an existing child of `parent`
        the new node precedes, or `None` to append at the end. As for
        `Node.value`, a value of a tag the document's reader format treats
        as constructed is parsed as nested elements.
        """
        tag_bytes = tag.data if isinstance(tag, Tag) else tag
        parent_ptr = parent._ptr if parent is not None else None
        before_ptr = before._ptr if before is not None else None
        try:
            ptr = _native.document_insert(self._capsule, parent_ptr, before_ptr, tag_bytes, value)
        except _native.Error as native_error:
            raise _from_native(native_error) from None
        return Node(self, ptr)

    @property
    def encoded_size(self) -> int:
        """The encoded size of the whole document."""
        try:
            return _native.document_encoded_size(self._capsule)
        except _native.Error as native_error:
            raise _from_native(native_error) from None

    def encode(self) -> bytes:
        """Encodes the whole document."""
        try:
            return _native.document_encode(self._capsule)
        except _native.Error as native_error:
            raise _from_native(native_error) from None

    def close(self) -> None:
        """Frees the document immediately instead of waiting for garbage collection.

        Every node from this document, and the document itself, must not be
        used afterwards.
        """
        self._capsule = None

    def __enter__(self) -> "Document":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"Document(count={len(self)})"
