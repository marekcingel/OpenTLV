# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

"""Python exceptions mapped from OpenTLV result codes."""

from __future__ import annotations

from typing import Optional

import _opentlv as _native


class OpenTLVError(Exception):
    """Base class for every OpenTLV error.

    Mirrors a non-zero ``tlv_result_t`` from the OpenTLV C API. `code` is the
    raw result code; the rest carry the structured diagnostic detail the C
    API reports for a failed operation, when available, and are `None`
    otherwise. `offset`, `expected`, `actual`, `operation` and `tag` apply to
    both reading and writing failures; `length`, `required` and `available`
    describe buffer bounds (`length` is writer-only). Reader `required` is the
    required extent of the failing region. Field offsets and enclosing_end
    preserve the Reader's absolute source coordinates.
    `raw_length` and `declared_length` preserve reader length diagnostics
    without narrowing the decoded value. For writer failures, `required` is
    the exact encoded size needed to grow the output buffer.
    """

    def __init__(self, code: int, offset: Optional[int] = None, expected: Optional[str] = None,
                 actual: Optional[str] = None, operation: Optional[str] = None,
                 tag: Optional[bytes] = None, length: Optional[int] = None,
                 required: Optional[int] = None, available: Optional[int] = None,
                 raw_length: Optional[bytes] = None, declared_length: Optional[int] = None,
                 tag_offset: Optional[int] = None, length_offset: Optional[int] = None,
                 value_offset: Optional[int] = None, enclosing_end: Optional[int] = None) -> None:
        super().__init__(_native.strerror(code))
        self.code = code
        self.offset = offset
        self.expected = expected
        self.actual = actual
        self.operation = operation
        self.tag = tag
        self.length = length
        self.required = required
        self.available = available
        self.raw_length = raw_length
        self.declared_length = declared_length
        self.tag_offset = tag_offset
        self.length_offset = length_offset
        self.value_offset = value_offset
        self.enclosing_end = enclosing_end


class BufferTooShortError(OpenTLVError):
    """A supplied buffer is too small for the data or output required."""


class InvalidLengthError(OpenTLVError):
    """A length is malformed, out of range, or not representable natively."""


class NullArgError(OpenTLVError):
    """A required argument is missing."""


class OutOfMemoryError(OpenTLVError):
    """An allocation failed."""


class EndOfBufferError(OpenTLVError):
    """No further element exists, or the input is empty."""


class InvalidTagError(OpenTLVError):
    """A tag is malformed or invalid for the format or standard."""


class VisitorError(OpenTLVError):
    """A visitor callback requested an error stop."""


class LimitError(OpenTLVError):
    """A configured depth, size, or element-count limit was exceeded."""


class SchemaError(OpenTLVError):
    """Input violates a schema rule."""


class InvalidArgError(OpenTLVError):
    """An argument has an invalid value that no more specific error describes."""


class InvalidTagSizeError(OpenTLVError):
    """Tag size violates the range supported by the operation."""


class InvalidByteOrderError(OpenTLVError):
    """Byte order is unknown or unsupported."""


class ValueOverflowError(OpenTLVError):
    """An unsigned value cannot fit the requested numeric width."""


class InvalidValueError(OpenTLVError):
    """Universal primitive content is malformed or fails a canonical DER rule."""


class UnsupportedTypeError(OpenTLVError):
    """A universal tag number has no implemented canonical validation."""


class SchemaMissingError(OpenTLVError):
    """A required schema field is absent."""


class NativeSizeError(OpenTLVError):
    """A logical size exceeds the native address space."""


class NeedMoreDataError(OpenTLVError):
    """Non-final input is exhausted or incomplete; supply more data or EOF."""


# Keyed by tlv_result_t; mirrors tlv/include/tlv/error.h.
_ERROR_TYPES = {
    1: BufferTooShortError,
    2: InvalidLengthError,
    3: NullArgError,
    4: OutOfMemoryError,
    5: EndOfBufferError,
    6: InvalidTagError,
    7: VisitorError,
    8: LimitError,
    9: SchemaError,
    10: InvalidArgError,
    11: InvalidTagSizeError,
    12: InvalidByteOrderError,
    13: ValueOverflowError,
    14: InvalidValueError,
    15: UnsupportedTypeError,
    16: SchemaMissingError,
    17: NativeSizeError,
    18: NeedMoreDataError,
}


def _from_native(error: "_native.Error") -> OpenTLVError:
    """Translates a native `_opentlv.Error` into a typed `OpenTLVError`.

    `error.args[0]` is a dict with a "code" key and whichever diagnostic keys
    the failing native call supports; a missing key means the same as an
    explicit `None`.
    """
    fields = error.args[0]
    code = fields["code"]
    error_type = _ERROR_TYPES.get(code, OpenTLVError)
    result = error_type(code, offset=fields.get("offset"), expected=fields.get("expected"),
                       actual=fields.get("actual"), operation=fields.get("operation"),
                       tag=fields.get("tag"), length=fields.get("length"),
                       required=fields.get("required"), available=fields.get("available"),
                       raw_length=fields.get("raw_length"), declared_length=fields.get("declared_length"),
                       tag_offset=fields.get("tag_offset"), length_offset=fields.get("length_offset"),
                       value_offset=fields.get("value_offset"), enclosing_end=fields.get("enclosing_end"))
    # Preserve every Query field alongside the original typed Reader/status error.
    result.query = {key: fields.get(key) for key in (
        "query_kind", "begin", "end", "source_offset", "query_expected",
        "limit", "configured", "codec")} if "query_kind" in fields else None
    return result
