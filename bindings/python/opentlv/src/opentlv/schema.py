"""Length schemas and structural schemas for validating TLV data."""

from __future__ import annotations

import enum
from typing import Dict, Iterable, Optional, Union

import opentlv_native as _native

from opentlv.error import InvalidLengthError, SchemaError, _from_native
from opentlv.format import Format
from opentlv.tag import Tag

UNRESTRICTED = 2**64 - 1
"""Sentinel for an unrestricted upper bound, matching the C library's `SIZE_MAX`."""


class LengthRule:
    """Length rule for one tag of a `LengthSchema`.

    Bounds are inclusive; equal bounds specify an exact length.
    """

    __slots__ = ("tag", "min_length", "max_length")

    def __init__(self, tag: Union[Tag, bytes], min_length: int = 0,
                 max_length: int = UNRESTRICTED) -> None:
        self.tag = tag if isinstance(tag, Tag) else Tag(tag)
        self.min_length = min_length
        self.max_length = max_length

    @staticmethod
    def exact(tag: Union[Tag, bytes], length: int) -> "LengthRule":
        """Creates a rule permitting exactly `length` bytes."""
        return LengthRule(tag, length, length)

    def __repr__(self) -> str:
        return f"LengthRule({self.tag!r}, {self.min_length}, {self.max_length})"


class LengthSchema:
    """A table of per-tag value-length rules.

    A pure Python lookup table: `find`/`validate_length` are a dict lookup
    and a bounds check, so this does not call into the C library. Earlier
    rules win for a repeated tag.

    >>> tag = Tag(b"\\x01")
    >>> schema = LengthSchema([LengthRule(tag, 2, 4)])
    >>> schema.validate_length(tag, 3)
    >>> schema.validate_length(tag, 5)
    Traceback (most recent call last):
        ...
    opentlv.error.InvalidLengthError: invalid length encoding
    """

    __slots__ = ("_rules",)

    def __init__(self, rules: Iterable[LengthRule] = ()) -> None:
        table: Dict[bytes, LengthRule] = {}
        for rule in rules:
            table.setdefault(rule.tag.data, rule)
        self._rules = table

    def __len__(self) -> int:
        return len(self._rules)

    def find(self, tag: Union[Tag, bytes]) -> Optional[LengthRule]:
        """Returns the rule for `tag`, or `None` if the schema does not know it."""
        tag_bytes = tag.data if isinstance(tag, Tag) else bytes(tag)
        return self._rules.get(tag_bytes)

    def validate_length(self, tag: Union[Tag, bytes], length: int) -> None:
        """Checks that a value of `length` bytes is permitted for `tag`.

        Raises `SchemaError` if the schema has no rule for `tag`, or
        `InvalidLengthError` if `length` is out of the rule's bounds.
        """
        rule = self.find(tag)
        if rule is None:
            raise SchemaError(9)
        if not (rule.min_length <= length <= rule.max_length):
            raise InvalidLengthError(2)


class Kind(enum.IntEnum):
    """Expected form of a value described by a `StructureRule`."""

    ANY = 0
    """The element may be primitive or constructed."""

    PRIMITIVE = 1
    """The element must be primitive."""

    CONSTRUCTED = 2
    """The element must be constructed."""


class StructureRule:
    """Structural rule for one tag within a single parent scope of a `StructureSchema`.

    A new rule is optional (0 to unrestricted occurrences), accepts any
    length and any `Kind`, and leaves its children unrestricted; pass
    keyword arguments to refine it.

    >>> rule = StructureRule(Tag(b"\\x84"), min_length=5, max_length=16,
    ...                       min_occurs=1, max_occurs=1, kind=Kind.PRIMITIVE)
    """

    __slots__ = ("tag", "min_length", "max_length", "min_occurs", "max_occurs", "kind", "children")

    def __init__(self, tag: Union[Tag, bytes], *, min_length: int = 0,
                 max_length: int = UNRESTRICTED, min_occurs: int = 0,
                 max_occurs: int = UNRESTRICTED, kind: Kind = Kind.ANY,
                 children: Optional["StructureSchema"] = None) -> None:
        self.tag = tag if isinstance(tag, Tag) else Tag(tag)
        self.min_length = min_length
        self.max_length = max_length
        self.min_occurs = min_occurs
        self.max_occurs = max_occurs
        self.kind = Kind.CONSTRUCTED if children is not None else kind
        self.children = children

    def _to_native(self):
        children = self.children._to_native() if self.children is not None else None
        return (self.tag.data, self.min_length, self.max_length, self.min_occurs,
                self.max_occurs, int(self.kind), children)

    def __repr__(self) -> str:
        return (f"StructureRule({self.tag!r}, min_length={self.min_length}, "
                f"max_length={self.max_length}, min_occurs={self.min_occurs}, "
                f"max_occurs={self.max_occurs}, kind={self.kind!r})")


class StructureSchema:
    """A structural schema: per-tag length, kind, occurrence and membership
    rules for one parent scope, with optional nested schemas for children.

    `validate()` runs the C library's validator; values are never decoded.
    Tags must be unique among `rules`; a duplicate is reported by
    `validate()` as a `SchemaError`. Unknown tags are rejected unless
    `allow_unknown` is `True`.

    >>> tag = Tag(b"\\x01")
    >>> schema = StructureSchema([StructureRule(tag, min_occurs=1, max_occurs=1)])
    >>> schema.validate(bytes([0x01, 0x00]))
    >>> schema.validate(b"")
    Traceback (most recent call last):
        ...
    opentlv.error.SchemaMissingError: required schema field missing
    """

    __slots__ = ("rules", "allow_unknown")

    def __init__(self, rules: Iterable[StructureRule] = (), allow_unknown: bool = False) -> None:
        self.rules = list(rules)
        self.allow_unknown = allow_unknown

    def _to_native(self):
        return (self.allow_unknown, [rule._to_native() for rule in self.rules])

    def validate(self, data, format: Format = Format.DEFAULT, max_depth: int = 32,
                 max_elements: int = 100_000) -> None:
        """Validates framing, nesting, lengths, occurrence counts and child
        membership of `data` against this schema.

        Which tags are constructed is decided by `format`: BER, CER and DER
        nest by their constructed bit, while the default and fixed-1-byte
        formats have no nesting, so every value is opaque. `max_depth` and
        `max_elements` bound traversal the same way `Reader` does not need
        to, since validation may recurse into nested elements.

        Raises `SchemaMissingError` for an absent required field,
        `SchemaError` for other rule violations, `InvalidLengthError` for a
        length failure, or a reading error such as `LimitError`.
        """
        try:
            _native.structure_validate(data, format, self._to_native(), max_depth, max_elements)
        except _native.Error as native_error:
            raise _from_native(native_error) from None

    def __len__(self) -> int:
        return len(self.rules)

    def __repr__(self) -> str:
        return f"StructureSchema(rules={self.rules!r}, allow_unknown={self.allow_unknown})"
