"""Python bindings for OpenTLV.

This package wraps ``opentlv_native``, the native extension that registers
the public OpenTLV C API as Python callables, into an idiomatic API that
follows the OpenTLV conceptual model: see [Language
bindings](https://github.com/marekcingel/OpenTLV/blob/main/docs/concepts/bindings.md).

Currently bound: `Reader`, `Writer`, `Document`/`Node`, `Entry`, `Tag`,
`Format`, `FixedFormat`, `LengthSchema`/`StructureSchema` and the
`OpenTLVError` exception hierarchy. The `codec` submodule binds the one
concrete value codec the C API exports publicly (EMV amounts); the general
Codec concept is otherwise not bound.
"""

from opentlv_native import version_string

from opentlv import codec
from opentlv.document import Document, Node
from opentlv.entry import Entry
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
)
from opentlv.fixed_format import FixedFormat
from opentlv.format import Format
from opentlv.reader import Reader
from opentlv.schema import Kind, LengthRule, LengthSchema, StructureRule, StructureSchema
from opentlv.tag import Tag
from opentlv.writer import Writer, encoded_size

__version__ = version_string()

__all__ = [
    "__version__",
    "BufferTooShortError",
    "Document",
    "Entry",
    "Node",
    "codec",
    "EndOfBufferError",
    "FixedFormat",
    "Format",
    "InvalidArgError",
    "InvalidByteOrderError",
    "InvalidLengthError",
    "InvalidTagError",
    "InvalidTagSizeError",
    "InvalidValueError",
    "Kind",
    "LengthRule",
    "LengthSchema",
    "LimitError",
    "NullArgError",
    "OpenTLVError",
    "OutOfMemoryError",
    "Reader",
    "SchemaError",
    "SchemaMissingError",
    "StructureRule",
    "StructureSchema",
    "Tag",
    "UnsupportedTypeError",
    "ValueOverflowError",
    "VisitorError",
    "Writer",
    "encoded_size",
]
