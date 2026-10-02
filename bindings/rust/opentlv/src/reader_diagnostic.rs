// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

//! Owned Reader diagnostics: no native borrowed pointer escapes.
use opentlv_sys as native;
use std::{ffi::CStr, slice};

/// Structured detail from the canonical Reader, safe to retain after input replacement.
#[derive(Clone, Debug, Default)]
pub struct ReaderDiagnostic {
    /// Absolute failing field offset.
    pub offset: Option<usize>,
    /// C Reader operation code (tag, length, value, trailer or header).
    pub operation: i32,
    /// Raw wire identifier, when reported.
    pub tag: Option<Vec<u8>>,
    /// Original available length-field bytes.
    pub raw_length: Option<Vec<u8>>,
    /// Absolute tag field offset.
    pub tag_offset: Option<usize>,
    /// Absolute length field offset.
    pub length_offset: Option<usize>,
    /// Absolute value field offset.
    pub value_offset: Option<usize>,
    /// Declared logical length.
    pub declared_length: Option<u64>,
    /// Required failing region extent.
    pub required: Option<u64>,
    /// Available bytes at the failure.
    pub available: Option<usize>,
    /// Absolute enclosing boundary.
    pub enclosing_end: Option<usize>,
    /// Expected description, when supplied by C.
    pub expected: Option<String>,
    /// Actual description, when supplied by C.
    pub actual: Option<String>,
}

impl ReaderDiagnostic {
    pub(crate) unsafe fn from_raw(raw: &native::tlv_reader_diagnostic_t) -> Self {
        unsafe fn bytes(ptr: *const u8, size: usize) -> Vec<u8> {
            if size == 0 {
                Vec::new()
            } else {
                // SAFETY: the caller retains the input backing the C diagnostic.
                unsafe { slice::from_raw_parts(ptr, size) }.to_vec()
            }
        }
        unsafe fn text(ptr: *const std::os::raw::c_char) -> Option<String> {
            if ptr.is_null() {
                None
            } else {
                // SAFETY: C diagnostic descriptions are live NUL-terminated strings.
                Some(
                    unsafe { CStr::from_ptr(ptr) }
                        .to_string_lossy()
                        .into_owned(),
                )
            }
        }
        Self {
            offset: (raw.diagnostic.has_offset != 0).then_some(raw.diagnostic.offset),
            operation: raw.operation,
            // SAFETY: the caller keeps diagnostic buffers alive for these copies.
            tag: (raw.has_tag != 0).then(|| unsafe { bytes(raw.tag.data, raw.tag.size) }),
            raw_length: (raw.has_raw_length != 0)
                .then(|| unsafe { bytes(raw.raw_length.data, raw.raw_length.size) }),
            tag_offset: (raw.has_tag_offset != 0).then_some(raw.tag_offset),
            length_offset: (raw.has_length_offset != 0).then_some(raw.length_offset),
            value_offset: (raw.has_value_offset != 0).then_some(raw.value_offset),
            declared_length: (raw.has_declared_length != 0).then_some(raw.declared_length),
            required: (raw.has_required != 0).then_some(raw.required),
            available: (raw.has_available != 0).then_some(raw.available),
            enclosing_end: (raw.has_enclosing_end != 0).then_some(raw.enclosing_end),
            // SAFETY: descriptions remain live until after this conversion.
            expected: unsafe { text(raw.diagnostic.expected) },
            actual: unsafe { text(raw.diagnostic.actual) },
        }
    }
}
