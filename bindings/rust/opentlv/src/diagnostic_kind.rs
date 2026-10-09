// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

//! Typed diagnostic vocabulary with canonical C names and lossless unknown values.
use opentlv_sys as native;
use std::{ffi::CStr, fmt};

/// Canonical ReaderOperation diagnostic category.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReaderOperation {
    /// C tag category.
    Tag,
    /// C length category.
    Length,
    /// C value category.
    Value,
    /// C trailer category.
    Trailer,
    /// C header category.
    Header,
    /// Unrecognized native value, retained without loss.
    UnknownRaw(i32),
}
impl ReaderOperation {
    /// Preserve a native category, including future values.
    pub fn from_raw(value: i32) -> Self {
        match value {
            0 => Self::Tag,
            1 => Self::Length,
            2 => Self::Value,
            3 => Self::Trailer,
            4 => Self::Header,
            other => Self::UnknownRaw(other),
        }
    }
    /// Original C category value.
    pub fn as_raw(self) -> i32 {
        match self {
            Self::Tag => 0,
            Self::Length => 1,
            Self::Value => 2,
            Self::Trailer => 3,
            Self::Header => 4,
            Self::UnknownRaw(value) => value,
        }
    }
    /// Program-lifetime canonical C spelling.
    pub fn name(self) -> &'static str {
        // SAFETY: every integer maps to a static NUL-terminated ASCII string.
        unsafe { CStr::from_ptr(native::tlv_reader_operation_string(self.as_raw())) }
            .to_str()
            .expect("ASCII diagnostic label")
    }
}
impl Default for ReaderOperation {
    fn default() -> Self {
        Self::from_raw(0)
    }
}
impl fmt::Display for ReaderOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Canonical WriterOperation diagnostic category.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WriterOperation {
    /// C tag category.
    Tag,
    /// C length category.
    Length,
    /// C value category.
    Value,
    /// C header category.
    Header,
    /// C trailer category.
    Trailer,
    /// C copy category.
    Copy,
    /// C preserve category.
    Preserve,
    /// C begin category.
    Begin,
    /// C end category.
    End,
    /// Unrecognized native value, retained without loss.
    UnknownRaw(i32),
}
impl WriterOperation {
    /// Preserve a native category, including future values.
    pub fn from_raw(value: i32) -> Self {
        match value {
            0 => Self::Tag,
            1 => Self::Length,
            2 => Self::Value,
            3 => Self::Header,
            4 => Self::Trailer,
            5 => Self::Copy,
            6 => Self::Preserve,
            7 => Self::Begin,
            8 => Self::End,
            other => Self::UnknownRaw(other),
        }
    }
    /// Original C category value.
    pub fn as_raw(self) -> i32 {
        match self {
            Self::Tag => 0,
            Self::Length => 1,
            Self::Value => 2,
            Self::Header => 3,
            Self::Trailer => 4,
            Self::Copy => 5,
            Self::Preserve => 6,
            Self::Begin => 7,
            Self::End => 8,
            Self::UnknownRaw(value) => value,
        }
    }
    /// Program-lifetime canonical C spelling.
    pub fn name(self) -> &'static str {
        // SAFETY: every integer maps to a static NUL-terminated ASCII string.
        unsafe { CStr::from_ptr(native::tlv_writer_operation_string(self.as_raw())) }
            .to_str()
            .expect("ASCII diagnostic label")
    }
}
impl Default for WriterOperation {
    fn default() -> Self {
        Self::from_raw(0)
    }
}
impl fmt::Display for WriterOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Canonical QueryErrorKind diagnostic category.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum QueryErrorKind {
    /// C none category.
    None,
    /// C syntax category.
    Syntax,
    /// C capability category.
    Capability,
    /// C limit category.
    Limit,
    /// C storage category.
    Storage,
    /// C events category.
    Events,
    /// C source category.
    Source,
    /// C reader category.
    Reader,
    /// C binding category.
    Binding,
    /// C cardinality category.
    Cardinality,
    /// C codec category.
    Codec,
    /// C image_version category.
    ImageVersion,
    /// C state category.
    State,
    /// C callback category.
    Callback,
    /// C type category.
    Type,
    /// C image category.
    Image,
    /// Unrecognized native value, retained without loss.
    UnknownRaw(i32),
}
impl QueryErrorKind {
    /// Preserve a native category, including future values.
    pub fn from_raw(value: i32) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Syntax,
            2 => Self::Capability,
            3 => Self::Limit,
            4 => Self::Storage,
            5 => Self::Events,
            6 => Self::Source,
            7 => Self::Reader,
            8 => Self::Binding,
            9 => Self::Cardinality,
            10 => Self::Codec,
            11 => Self::ImageVersion,
            12 => Self::State,
            13 => Self::Callback,
            14 => Self::Type,
            15 => Self::Image,
            other => Self::UnknownRaw(other),
        }
    }
    /// Original C category value.
    pub fn as_raw(self) -> i32 {
        match self {
            Self::None => 0,
            Self::Syntax => 1,
            Self::Capability => 2,
            Self::Limit => 3,
            Self::Storage => 4,
            Self::Events => 5,
            Self::Source => 6,
            Self::Reader => 7,
            Self::Binding => 8,
            Self::Cardinality => 9,
            Self::Codec => 10,
            Self::ImageVersion => 11,
            Self::State => 12,
            Self::Callback => 13,
            Self::Type => 14,
            Self::Image => 15,
            Self::UnknownRaw(value) => value,
        }
    }
    /// Program-lifetime canonical C spelling.
    pub fn name(self) -> &'static str {
        // SAFETY: every integer maps to a static NUL-terminated ASCII string.
        unsafe { CStr::from_ptr(native::tlv_query_error_kind_string(self.as_raw())) }
            .to_str()
            .expect("ASCII diagnostic label")
    }
}
impl Default for QueryErrorKind {
    fn default() -> Self {
        Self::from_raw(0)
    }
}
impl fmt::Display for QueryErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Canonical SchemaIssue diagnostic category.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SchemaIssue {
    /// C none category.
    None,
    /// C missing category.
    Missing,
    /// C duplicate category.
    Duplicate,
    /// C unexpected category.
    Unexpected,
    /// C kind category.
    Kind,
    /// C length category.
    Length,
    /// C order category.
    Order,
    /// C assertion category.
    Assertion,
    /// C value category.
    Value,
    /// C definition category.
    Definition,
    /// Unrecognized native value, retained without loss.
    UnknownRaw(i32),
}
impl SchemaIssue {
    /// Preserve a native category, including future values.
    pub fn from_raw(value: i32) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Missing,
            2 => Self::Duplicate,
            3 => Self::Unexpected,
            4 => Self::Kind,
            5 => Self::Length,
            6 => Self::Order,
            7 => Self::Assertion,
            8 => Self::Value,
            9 => Self::Definition,
            other => Self::UnknownRaw(other),
        }
    }
    /// Original C category value.
    pub fn as_raw(self) -> i32 {
        match self {
            Self::None => 0,
            Self::Missing => 1,
            Self::Duplicate => 2,
            Self::Unexpected => 3,
            Self::Kind => 4,
            Self::Length => 5,
            Self::Order => 6,
            Self::Assertion => 7,
            Self::Value => 8,
            Self::Definition => 9,
            Self::UnknownRaw(value) => value,
        }
    }
    /// Program-lifetime canonical C spelling.
    pub fn name(self) -> &'static str {
        // SAFETY: every integer maps to a static NUL-terminated ASCII string.
        unsafe { CStr::from_ptr(native::tlv_schema_issue_kind_string(self.as_raw())) }
            .to_str()
            .expect("ASCII diagnostic label")
    }
}
impl Default for SchemaIssue {
    fn default() -> Self {
        Self::from_raw(0)
    }
}
impl fmt::Display for SchemaIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Canonical SchemaDefinitionKind diagnostic category.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SchemaDefinitionKind {
    /// C unknown category.
    Unknown,
    /// C table category.
    Table,
    /// C rule category.
    Rule,
    /// C group category.
    Group,
    /// C type category.
    Type,
    /// C component category.
    Component,
    /// Unrecognized native value, retained without loss.
    UnknownRaw(i32),
}
impl SchemaDefinitionKind {
    /// Preserve a native category, including future values.
    pub fn from_raw(value: i32) -> Self {
        match value {
            0 => Self::Unknown,
            1 => Self::Table,
            2 => Self::Rule,
            3 => Self::Group,
            4 => Self::Type,
            5 => Self::Component,
            other => Self::UnknownRaw(other),
        }
    }
    /// Original C category value.
    pub fn as_raw(self) -> i32 {
        match self {
            Self::Unknown => 0,
            Self::Table => 1,
            Self::Rule => 2,
            Self::Group => 3,
            Self::Type => 4,
            Self::Component => 5,
            Self::UnknownRaw(value) => value,
        }
    }
    /// Program-lifetime canonical C spelling.
    pub fn name(self) -> &'static str {
        // SAFETY: every integer maps to a static NUL-terminated ASCII string.
        unsafe { CStr::from_ptr(native::tlv_schema_definition_kind_string(self.as_raw())) }
            .to_str()
            .expect("ASCII diagnostic label")
    }
}
impl Default for SchemaDefinitionKind {
    fn default() -> Self {
        Self::from_raw(0)
    }
}
impl fmt::Display for SchemaDefinitionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Canonical CodecOperation diagnostic category.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CodecOperation {
    /// C decode category.
    Decode,
    /// C encode category.
    Encode,
    /// C measure category.
    Measure,
    /// Unrecognized native value, retained without loss.
    UnknownRaw(i32),
}
impl CodecOperation {
    /// Preserve a native category, including future values.
    pub fn from_raw(value: i32) -> Self {
        match value {
            0 => Self::Decode,
            1 => Self::Encode,
            2 => Self::Measure,
            other => Self::UnknownRaw(other),
        }
    }
    /// Original C category value.
    pub fn as_raw(self) -> i32 {
        match self {
            Self::Decode => 0,
            Self::Encode => 1,
            Self::Measure => 2,
            Self::UnknownRaw(value) => value,
        }
    }
    /// Program-lifetime canonical C spelling.
    pub fn name(self) -> &'static str {
        // SAFETY: every integer maps to a static NUL-terminated ASCII string.
        unsafe { CStr::from_ptr(native::tlv_codec_operation_string(self.as_raw())) }
            .to_str()
            .expect("ASCII diagnostic label")
    }
}
impl Default for CodecOperation {
    fn default() -> Self {
        Self::from_raw(0)
    }
}
impl fmt::Display for CodecOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Canonical CodecCause diagnostic category.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CodecCause {
    /// C none category.
    None,
    /// C reader category.
    Reader,
    /// C schema category.
    Schema,
    /// Unrecognized native value, retained without loss.
    UnknownRaw(i32),
}
impl CodecCause {
    /// Preserve a native category, including future values.
    pub fn from_raw(value: i32) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Reader,
            2 => Self::Schema,
            other => Self::UnknownRaw(other),
        }
    }
    /// Original C category value.
    pub fn as_raw(self) -> i32 {
        match self {
            Self::None => 0,
            Self::Reader => 1,
            Self::Schema => 2,
            Self::UnknownRaw(value) => value,
        }
    }
    /// Program-lifetime canonical C spelling.
    pub fn name(self) -> &'static str {
        // SAFETY: every integer maps to a static NUL-terminated ASCII string.
        unsafe { CStr::from_ptr(native::tlv_codec_cause_string(self.as_raw())) }
            .to_str()
            .expect("ASCII diagnostic label")
    }
}
impl Default for CodecCause {
    fn default() -> Self {
        Self::from_raw(0)
    }
}
impl fmt::Display for CodecCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Canonical CodecViolation diagnostic category.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CodecViolation {
    /// C none category.
    None,
    /// C result category.
    Result,
    /// C size category.
    Size,
    /// C type category.
    Type,
    /// C utf8 category.
    Utf8,
    /// Unrecognized native value, retained without loss.
    UnknownRaw(i32),
}
impl CodecViolation {
    /// Preserve a native category, including future values.
    pub fn from_raw(value: i32) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Result,
            2 => Self::Size,
            3 => Self::Type,
            4 => Self::Utf8,
            other => Self::UnknownRaw(other),
        }
    }
    /// Original C category value.
    pub fn as_raw(self) -> i32 {
        match self {
            Self::None => 0,
            Self::Result => 1,
            Self::Size => 2,
            Self::Type => 3,
            Self::Utf8 => 4,
            Self::UnknownRaw(value) => value,
        }
    }
    /// Program-lifetime canonical C spelling.
    pub fn name(self) -> &'static str {
        // SAFETY: every integer maps to a static NUL-terminated ASCII string.
        unsafe { CStr::from_ptr(native::tlv_codec_violation_string(self.as_raw())) }
            .to_str()
            .expect("ASCII diagnostic label")
    }
}
impl Default for CodecViolation {
    fn default() -> Self {
        Self::from_raw(0)
    }
}
impl fmt::Display for CodecViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Canonical Severity diagnostic category.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Severity {
    /// C error category.
    Error,
    /// C warning category.
    Warning,
    /// C info category.
    Info,
    /// Unrecognized native value, retained without loss.
    UnknownRaw(i32),
}
impl Severity {
    /// Preserve a native category, including future values.
    pub fn from_raw(value: i32) -> Self {
        match value {
            0 => Self::Error,
            1 => Self::Warning,
            2 => Self::Info,
            other => Self::UnknownRaw(other),
        }
    }
    /// Original C category value.
    pub fn as_raw(self) -> i32 {
        match self {
            Self::Error => 0,
            Self::Warning => 1,
            Self::Info => 2,
            Self::UnknownRaw(value) => value,
        }
    }
    /// Program-lifetime canonical C spelling.
    pub fn name(self) -> &'static str {
        // SAFETY: every integer maps to a static NUL-terminated ASCII string.
        unsafe { CStr::from_ptr(native::tlv_diagnostic_severity_string(self.as_raw())) }
            .to_str()
            .expect("ASCII diagnostic label")
    }
}
impl Default for Severity {
    fn default() -> Self {
        Self::from_raw(0)
    }
}
impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}
