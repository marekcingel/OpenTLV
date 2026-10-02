# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

"""Python bindings for OpenTLV.

This package wraps ``opentlv_native``, the native extension that registers
the public OpenTLV C API as Python callables, into an idiomatic API that
follows the OpenTLV conceptual model: see [Language
bindings](https://github.com/marekcingel/OpenTLV/blob/main/docs/concepts/bindings.md).

Currently bound: `Reader`, `TreeReader`, `Query`/`QueryMatcher`, Visitors,
`Writer`, `TreeWriter`, `Document`/`Node`, `DocumentBuilder`, `Element`, `Tag`,
`Format`, `FixedFormat`, `LengthSchema`/`StructureSchema` and the
`OpenTLVError` exception hierarchy. The `codec` submodule exposes configured numeric codecs and EMV amounts.
Other public C codecs remain a capability gap.
"""

from opentlv_native import version_string

from opentlv.definition import Definition, DefinitionRegistry
from opentlv import codec
from opentlv.codec import CodecError, NumberCodec, NumberEncoding
from opentlv.document import Document, DocumentBuilder, Node
from opentlv.element import Element
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
    NativeSizeError,
    NeedMoreDataError,
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
from opentlv.reader import Reader, read
from opentlv.cursor import Decoded, Layout, TreeItem, TreeEvent, TreeEventKind, TreeReader, Visit
from opentlv.query import Query, QueryMatcher
from opentlv.tree_writer import TreeWriter
from opentlv.schema import SchemaBounds, SchemaDiagnostic, SchemaDiagnosticReport, Kind, LengthRule, LengthSchema, SchemaOrder, UnknownPolicy, StructureGroup, StructureRule, StructureSchema
from opentlv.tag import Tag
from opentlv.writer import Writer, element_encoded_size, encoded_size

__version__ = version_string()

__all__ = [
    "__version__",
    "BufferTooShortError",
    "Document",
    "DocumentBuilder",
    "Element",
    "Node",
    "codec",
    "Definition",
    "DefinitionRegistry",
    "CodecError",
    "NumberCodec",
    "NumberEncoding",
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
    "NativeSizeError",
    "NeedMoreDataError",
    "OpenTLVError",
    "OutOfMemoryError",
    "Reader",
    "read",
    "Decoded",
    "Layout",
    "TreeItem",
    "TreeEvent",
    "TreeEventKind",
    "TreeReader",
    "TreeWriter",
    "Visit",
    "Query",
    "QueryMatcher",
    "SchemaError",
    "SchemaMissingError",
    "StructureRule",
    "SchemaOrder",
    "SchemaBounds",
    "SchemaDiagnostic",
    "SchemaDiagnosticReport",
    "UnknownPolicy",
    "StructureGroup",
    "StructureSchema",
    "Tag",
    "UnsupportedTypeError",
    "ValueOverflowError",
    "VisitorError",
    "Writer",
    "encoded_size",
    "element_encoded_size",
]
