//! Canonical Schema report ABI.
use super::*;
/// Native enclosing scope path.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct tlv_diagnostic_path_t {
    /// Borrowed scope Tags.
    pub tags: [tlv_tag_t; 32],
    /// Valid prefix length.
    pub length: usize,
}
/// Detailed native Schema violation.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct tlv_schema_diagnostic_t {
    /// Corresponding C field.
    pub diagnostic: tlv_diagnostic_t,
    /// Corresponding C field.
    pub kind: c_int,
    /// Corresponding C field.
    pub tag: tlv_tag_t,
    /// Corresponding C field.
    pub path: tlv_diagnostic_path_t,
    /// Corresponding C field.
    pub field: *const c_char,
    /// Corresponding C field.
    pub is_group: c_int,
    /// Corresponding C field.
    pub has_occurs: c_int,
    /// Corresponding C field.
    pub min_occurs: usize,
    /// Corresponding C field.
    pub max_occurs: usize,
    /// Corresponding C field.
    pub occurs: usize,
    /// Corresponding C field.
    pub has_length: c_int,
    /// Corresponding C field.
    pub min_length: usize,
    /// Corresponding C field.
    pub max_length: usize,
    /// Corresponding C field.
    pub actual_length: usize,
    /// Corresponding C field.
    pub has_form: c_int,
    /// Corresponding C field.
    pub expected_form: c_int,
    /// Corresponding C field.
    pub actual_constructed: c_int,
    /// Corresponding C field.
    pub length_multiple: usize,
    /// Corresponding C field.
    pub length_flags: u32,
}
/// Caller-owned detailed report storage.
#[repr(C)]
pub struct tlv_schema_diagnostic_report_t {
    /// Diagnostic buffer.
    pub diagnostics: *mut tlv_schema_diagnostic_t,
    /// Buffer capacity.
    pub capacity: usize,
    /// Total violation count.
    pub count: usize,
}
extern "C" {
    pub fn tlv_schema_issue_kind_string(kind: c_int) -> *const c_char;
    pub fn tlv_schema_validate_all_diag(
        data: *const u8,
        size: usize,
        format: *const tlv_format_t,
        schema: *const tlv_structure_schema_t,
        max_depth: usize,
        max_elements: usize,
        unknown: c_int,
        report: *mut tlv_schema_diagnostic_report_t,
        error_offset: *mut usize,
    ) -> tlv_result_t;
}
