# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

"""Typed C diagnostic categories; unknown values retain their numeric identity."""
from enum import IntEnum
import _opentlv as _native


class _Category(IntEnum):
    @classmethod
    def _missing_(cls, value):
        if not isinstance(value, int):
            return None
        item = int.__new__(cls, value)
        item._name_ = f"UNKNOWN_{value}"
        item._value_ = value
        return item


class ReaderOperation(_Category):
    """Canonical ReaderOperation category."""
    TAG = 0
    LENGTH = 1
    VALUE = 2
    TRAILER = 3
    HEADER = 4

    @property
    def label(self):
        """Canonical C spelling, including unknown values."""
        return _native.diagnostic_name("reader_operation", self.value)


class WriterOperation(_Category):
    """Canonical WriterOperation category."""
    TAG = 0
    LENGTH = 1
    VALUE = 2
    HEADER = 3
    TRAILER = 4
    COPY = 5
    PRESERVE = 6
    BEGIN = 7
    END = 8

    @property
    def label(self):
        """Canonical C spelling, including unknown values."""
        return _native.diagnostic_name("writer_operation", self.value)


class QueryErrorKind(_Category):
    """Canonical QueryErrorKind category."""
    NONE = 0
    SYNTAX = 1
    CAPABILITY = 2
    LIMIT = 3
    STORAGE = 4
    EVENTS = 5
    SOURCE = 6
    READER = 7
    BINDING = 8
    CARDINALITY = 9
    CODEC = 10
    IMAGE_VERSION = 11
    STATE = 12
    CALLBACK = 13
    TYPE = 14
    IMAGE = 15

    @property
    def label(self):
        """Canonical C spelling, including unknown values."""
        return _native.diagnostic_name("query_error_kind", self.value)


class SchemaIssue(_Category):
    """Canonical SchemaIssue category."""
    NONE = 0
    MISSING = 1
    DUPLICATE = 2
    UNEXPECTED = 3
    KIND = 4
    LENGTH = 5
    ORDER = 6
    ASSERTION = 7
    VALUE = 8
    DEFINITION = 9

    @property
    def label(self):
        """Canonical C spelling, including unknown values."""
        return _native.diagnostic_name("schema_issue_kind", self.value)


class SchemaDefinitionKind(_Category):
    """Canonical SchemaDefinitionKind category."""
    UNKNOWN = 0
    TABLE = 1
    RULE = 2
    GROUP = 3
    TYPE = 4
    COMPONENT = 5

    @property
    def label(self):
        """Canonical C spelling, including unknown values."""
        return _native.diagnostic_name("schema_definition_kind", self.value)


class CodecOperation(_Category):
    """Canonical CodecOperation category."""
    DECODE = 0
    ENCODE = 1
    MEASURE = 2

    @property
    def label(self):
        """Canonical C spelling, including unknown values."""
        return _native.diagnostic_name("codec_operation", self.value)


class CodecCause(_Category):
    """Canonical CodecCause category."""
    NONE = 0
    READER = 1
    SCHEMA = 2

    @property
    def label(self):
        """Canonical C spelling, including unknown values."""
        return _native.diagnostic_name("codec_cause", self.value)


class CodecViolation(_Category):
    """Canonical CodecViolation category."""
    NONE = 0
    RESULT = 1
    SIZE = 2
    TYPE = 3
    UTF8 = 4

    @property
    def label(self):
        """Canonical C spelling, including unknown values."""
        return _native.diagnostic_name("codec_violation", self.value)


class Severity(_Category):
    """Canonical Severity category."""
    ERROR = 0
    WARNING = 1
    INFO = 2

    @property
    def label(self):
        """Canonical C spelling, including unknown values."""
        return _native.diagnostic_name("diagnostic_severity", self.value)
