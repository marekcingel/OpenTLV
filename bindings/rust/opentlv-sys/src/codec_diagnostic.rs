// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
//! Shared result-domain Codec diagnostics.
use super::*;
#[repr(C)]
#[derive(Clone, Copy, Debug)]
/// Native diagnostic record.
pub struct tlv_codec_schema_detail_t {
    /// Native field.
    pub kind: c_int,
    /// Native field.
    pub tag: tlv_tag_t,
    /// Native field.
    pub definition: tlv_schema_definition_location_t,
    /// Native field.
    pub field: *const c_char,
    /// Native field.
    pub is_group: c_int,
    /// Native field.
    pub has_occurs: c_int,
    /// Native field.
    pub min_occurs: usize,
    /// Native field.
    pub max_occurs: usize,
    /// Native field.
    pub occurs: usize,
    /// Native field.
    pub has_length: c_int,
    /// Native field.
    pub min_length: usize,
    /// Native field.
    pub max_length: usize,
    /// Native field.
    pub actual_length: usize,
    /// Native field.
    pub has_form: c_int,
    /// Native field.
    pub expected_form: c_int,
    /// Native field.
    pub actual_constructed: c_int,
    /// Native field.
    pub length_multiple: usize,
    /// Native field.
    pub length_flags: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Debug)]
/// Native diagnostic record.
pub struct tlv_codec_detail_t {
    /// Native field.
    pub operation: c_int,
    /// Native field.
    pub reported: i32,
    /// Native field.
    pub violation: c_int,
    /// Native field.
    pub representation: *const c_char,
    /// Native field.
    pub cause: c_int,
    /// Native field.
    pub detail: tlv_codec_cause_detail_t,
}
#[repr(C)]
#[derive(Clone, Copy, Debug)]
/// Native diagnostic record.
pub struct tlv_codec_diagnostic_t {
    /// Native field.
    pub diagnostic: tlv_diagnostic_t,
    /// Native field.
    pub codec: tlv_codec_detail_t,
}
#[repr(C)]
#[derive(Clone, Copy)]
/// Only the member selected by `cause` is active.
pub union tlv_codec_cause_detail_t {
    pub reader: tlv_reader_detail_t,
    pub schema: tlv_codec_schema_detail_t,
}
impl std::fmt::Debug for tlv_codec_cause_detail_t {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CodecCause")
    }
}
extern "C" {
    pub fn tlv_codec_diagnostic_init(diagnostic: *mut tlv_codec_diagnostic_t, operation: c_int);
}
