//! Raw, unsafe FFI bindings to the OpenTLV C API.
//!
//! This crate is the only place in the Rust bindings that declares `extern "C"`
//! items. Prefer the safe `opentlv` crate unless you need the C API directly.
//! Only the part of the C API needed by the safe crate is declared so far.

#![allow(non_camel_case_types)]

use std::os::raw::{c_char, c_int, c_void};

/// Logical TLV value length (`tlv_length_t`), always 64 bits wide.
pub type tlv_length_t = u64;

/// Result code returned by fallible OpenTLV functions (`tlv_result_t`).
/// Zero is success.
pub type tlv_result_t = c_int;

/// The operation succeeded (`TLV_OK`).
pub const TLV_OK: tlv_result_t = 0;
/// A supplied buffer is too small (`TLV_ERR_BUFFER_TOO_SHORT`).
pub const TLV_ERR_BUFFER_TOO_SHORT: tlv_result_t = 1;
/// A length is malformed or out of range (`TLV_ERR_INVALID_LENGTH`).
pub const TLV_ERR_INVALID_LENGTH: tlv_result_t = 2;
/// A required pointer argument is `NULL` (`TLV_ERR_NULL_ARG`).
pub const TLV_ERR_NULL_ARG: tlv_result_t = 3;
/// An allocation failed (`TLV_ERR_OUT_OF_MEMORY`).
pub const TLV_ERR_OUT_OF_MEMORY: tlv_result_t = 4;
/// No further element exists, or the input is empty (`TLV_ERR_END_OF_BUFFER`).
pub const TLV_ERR_END_OF_BUFFER: tlv_result_t = 5;
/// A tag is malformed or invalid (`TLV_ERR_INVALID_TAG`).
pub const TLV_ERR_INVALID_TAG: tlv_result_t = 6;
/// A visitor callback requested an error stop (`TLV_ERR_VISITOR`).
pub const TLV_ERR_VISITOR: tlv_result_t = 7;
/// A configured limit was exceeded (`TLV_ERR_LIMIT`).
pub const TLV_ERR_LIMIT: tlv_result_t = 8;
/// Input violates a schema rule (`TLV_ERR_SCHEMA`).
pub const TLV_ERR_SCHEMA: tlv_result_t = 9;
/// An argument has an invalid value (`TLV_ERR_INVALID_ARG`).
pub const TLV_ERR_INVALID_ARG: tlv_result_t = 10;
/// Tag size is outside the supported range (`TLV_ERR_INVALID_TAG_SIZE`).
pub const TLV_ERR_INVALID_TAG_SIZE: tlv_result_t = 11;
/// Byte order is unknown or unsupported (`TLV_ERR_INVALID_BYTE_ORDER`).
pub const TLV_ERR_INVALID_BYTE_ORDER: tlv_result_t = 12;
/// A value does not fit the requested width (`TLV_ERR_OVERFLOW`).
pub const TLV_ERR_OVERFLOW: tlv_result_t = 13;
/// Primitive content is malformed (`TLV_ERR_INVALID_VALUE`).
pub const TLV_ERR_INVALID_VALUE: tlv_result_t = 14;
/// A universal tag has no implemented validation (`TLV_ERR_UNSUPPORTED_TYPE`).
pub const TLV_ERR_UNSUPPORTED_TYPE: tlv_result_t = 15;
/// A required schema field is absent (`TLV_ERR_SCHEMA_MISSING`).
pub const TLV_ERR_SCHEMA_MISSING: tlv_result_t = 16;

/// Byte order of a multi-byte integer (`tlv_byte_order_t`).
pub type tlv_byte_order_t = c_int;
/// Unknown byte order, rejected by the library (`TLV_BYTE_ORDER_UNKNOWN`).
pub const TLV_BYTE_ORDER_UNKNOWN: tlv_byte_order_t = 0;
/// Most significant byte first (`TLV_BYTE_ORDER_BIG_ENDIAN`).
pub const TLV_BYTE_ORDER_BIG_ENDIAN: tlv_byte_order_t = 1;
/// Least significant byte first (`TLV_BYTE_ORDER_LITTLE_ENDIAN`).
pub const TLV_BYTE_ORDER_LITTLE_ENDIAN: tlv_byte_order_t = 2;

/// A borrowed raw TLV tag (`tlv_tag_t`): a pointer to bytes and their count.
///
/// The type does not own the bytes and has no length limit. The layout does
/// not depend on any C build configuration.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct tlv_tag_t {
    /// Tag bytes in wire order; may be null only when `size` is zero.
    pub data: *const u8,
    /// Number of bytes in `data`.
    pub size: usize,
}

/// A non-owning view of a TLV value (`tlv_value_t`).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct tlv_value_t {
    /// Borrowed value bytes; may be null only when `length` is zero.
    pub data: *const u8,
    /// Value length in bytes.
    pub length: tlv_length_t,
}

/// A decoded TLV element: a borrowed tag and a borrowed value (`tlv_view_t`).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct tlv_view_t {
    /// Element tag.
    pub tag: tlv_tag_t,
    /// Element value.
    pub value: tlv_value_t,
}

/// Tag decoder callback (`tlv_read_tag_fn`).
pub type tlv_read_tag_fn = unsafe extern "C" fn(
    context: *const c_void,
    data: *const u8,
    size: usize,
    tag: *mut tlv_tag_t,
    consumed: *mut usize,
) -> tlv_result_t;

/// Length decoder callback (`tlv_read_length_fn`).
pub type tlv_read_length_fn = unsafe extern "C" fn(
    context: *const c_void,
    data: *const u8,
    size: usize,
    length: *mut usize,
    consumed: *mut usize,
) -> tlv_result_t;

/// Optional value-bounds callback (`tlv_read_value_bounds_fn`).
pub type tlv_read_value_bounds_fn = unsafe extern "C" fn(
    context: *const c_void,
    tag: *const tlv_tag_t,
    data: *const u8,
    size: usize,
    length_size: *mut usize,
    value_size: *mut usize,
    trailer_size: *mut usize,
) -> tlv_result_t;

/// Whole-element parser callback (`tlv_read_element_fn`).
pub type tlv_read_element_fn = unsafe extern "C" fn(
    context: *const c_void,
    data: *const u8,
    size: usize,
    tag: *mut tlv_tag_t,
    header_size: *mut usize,
    value_size: *mut usize,
    trailer_size: *mut usize,
) -> tlv_result_t;

/// Stateless reading format (`tlv_reader_format_t`).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct tlv_reader_format_t {
    /// Borrowed, immutable configuration passed to every callback; may be null.
    pub context: *const c_void,
    /// Tag decoder. Required.
    pub read_tag: Option<tlv_read_tag_fn>,
    /// Length decoder. Required.
    pub read_length: Option<tlv_read_length_fn>,
    /// Optional replacement for `read_length`.
    pub read_value_bounds: Option<tlv_read_value_bounds_fn>,
    /// Optional whole-element parser that replaces the three callbacks above.
    pub read_element: Option<tlv_read_element_fn>,
}

/// Tag encoder callback (`tlv_write_tag_fn`).
pub type tlv_write_tag_fn = unsafe extern "C" fn(
    context: *const c_void,
    data: *mut u8,
    capacity: usize,
    tag: *const tlv_tag_t,
    written: *mut usize,
) -> tlv_result_t;

/// Length encoder callback (`tlv_write_length_fn`).
pub type tlv_write_length_fn = unsafe extern "C" fn(
    context: *const c_void,
    data: *mut u8,
    capacity: usize,
    length: usize,
    written: *mut usize,
) -> tlv_result_t;

/// Length size callback (`tlv_length_size_fn`).
pub type tlv_length_size_fn =
    unsafe extern "C" fn(context: *const c_void, length: usize, size: *mut usize) -> tlv_result_t;

/// Whole-header encoder callback (`tlv_write_header_fn`).
pub type tlv_write_header_fn = unsafe extern "C" fn(
    context: *const c_void,
    data: *mut u8,
    capacity: usize,
    tag: *const tlv_tag_t,
    length: usize,
    written: *mut usize,
) -> tlv_result_t;

/// Stateless writing format (`tlv_writer_format_t`).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct tlv_writer_format_t {
    /// Borrowed, immutable configuration passed to every callback; may be null.
    pub context: *const c_void,
    /// Tag encoder. Required.
    pub write_tag: Option<tlv_write_tag_fn>,
    /// Length encoder. Required.
    pub write_length: Option<tlv_write_length_fn>,
    /// Length size query. Required.
    pub length_size: Option<tlv_length_size_fn>,
    /// Optional whole-header encoder that replaces the three callbacks above.
    pub write_header: Option<tlv_write_header_fn>,
}

/// Sequential writer over a caller-owned buffer (`tlv_writer_t`).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct tlv_writer_t {
    /// Borrowed writer format.
    pub format: *const tlv_writer_format_t,
    /// Borrowed output buffer.
    pub buf: *mut u8,
    /// Capacity of `buf` in bytes.
    pub capacity: usize,
    /// Number of bytes written so far.
    pub pos: usize,
}

/// Sequential reader over a caller-owned buffer (`tlv_reader_t`).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct tlv_reader_t {
    /// Borrowed reader format.
    pub format: *const tlv_reader_format_t,
    /// Borrowed input buffer.
    pub data: *const u8,
    /// Input size in bytes.
    pub size: usize,
    /// Offset of the next element to read.
    pub pos: usize,
}

extern "C" {
    /// Default format: one-byte tag, definite BER length.
    pub static tlv_reader_format_default: tlv_reader_format_t;
    /// BER-TLV format.
    pub static tlv_reader_format_ber: tlv_reader_format_t;
    /// CER format.
    pub static tlv_reader_format_cer: tlv_reader_format_t;
    /// DER format.
    pub static tlv_reader_format_der: tlv_reader_format_t;
    /// Fixed one-byte tag and one-byte length format.
    pub static tlv_reader_format_fixed_1byte: tlv_reader_format_t;

    /// Default writer format: one-byte tag, definite BER length.
    pub static tlv_writer_format_default: tlv_writer_format_t;
    /// BER-TLV writer format.
    pub static tlv_writer_format_ber: tlv_writer_format_t;
    /// CER writer format.
    pub static tlv_writer_format_cer: tlv_writer_format_t;
    /// DER writer format.
    pub static tlv_writer_format_der: tlv_writer_format_t;
    /// Fixed one-byte tag and one-byte length writer format.
    pub static tlv_writer_format_fixed_1byte: tlv_writer_format_t;

    /// Computes the encoded size of an element without accessing value bytes.
    pub fn tlv_encoded_size(
        tag: tlv_tag_t,
        length: usize,
        format: *const tlv_writer_format_t,
        size: *mut usize,
    ) -> tlv_result_t;
    /// Initializes a sequential writer over `buf`; both `buf` and `format` are borrowed.
    pub fn tlv_writer_init(
        writer: *mut tlv_writer_t,
        buf: *mut u8,
        capacity: usize,
        format: *const tlv_writer_format_t,
    ) -> tlv_result_t;
    /// Writes one element at the writer's current position.
    pub fn tlv_writer_write(
        writer: *mut tlv_writer_t,
        tag: tlv_tag_t,
        value: *const u8,
        length: usize,
    ) -> tlv_result_t;
    /// Returns the number of bytes written so far.
    pub fn tlv_writer_size(writer: *const tlv_writer_t) -> usize;

    /// Initializes a sequential reader over `data`; both `data` and `format` are borrowed.
    pub fn tlv_reader_init(
        reader: *mut tlv_reader_t,
        data: *const u8,
        size: usize,
        format: *const tlv_reader_format_t,
    ) -> tlv_result_t;
    /// Returns 1 if the reader has consumed all input, otherwise 0.
    pub fn tlv_reader_at_end(reader: *const tlv_reader_t) -> c_int;
    /// Reads the next element and advances the reader.
    pub fn tlv_reader_next(reader: *mut tlv_reader_t, out_entry: *mut tlv_view_t) -> tlv_result_t;

    /// Returns the library version as a NUL-terminated static string, for example `"0.6.0"`.
    pub fn tlv_version_string() -> *const c_char;
    /// Returns the major version number.
    pub fn tlv_version_major() -> u32;
    /// Returns the minor version number.
    pub fn tlv_version_minor() -> u32;
    /// Returns the patch version number.
    pub fn tlv_version_patch() -> u32;
    /// Returns a NUL-terminated static description of a result code.
    pub fn tlv_strerror(result: tlv_result_t) -> *const c_char;
    /// Narrows a length to the native `size_t`.
    pub fn tlv_length_to_size(length: tlv_length_t, size: *mut usize) -> tlv_result_t;
    /// Tests whether two tags have the same size and bytes.
    pub fn tlv_tag_equal(lhs: tlv_tag_t, rhs: tlv_tag_t) -> bool;
    /// Orders two tags lexicographically by their bytes.
    pub fn tlv_tag_compare(lhs: tlv_tag_t, rhs: tlv_tag_t) -> c_int;
}

/// Nesting predicate passed to schema validation (`tlv_is_constructed_fn`).
pub type tlv_is_constructed_fn =
    unsafe extern "C" fn(context: *const c_void, tag: *const tlv_tag_t) -> c_int;

/// Length rule for one tag (`tlv_schema_entry_t`).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct tlv_schema_entry_t {
    /// Tag this entry describes.
    pub tag: tlv_tag_t,
    /// Minimum permitted value length, inclusive.
    pub min_length: usize,
    /// Maximum permitted value length, inclusive; `usize::MAX` is unrestricted.
    pub max_length: usize,
    /// Reserved; currently ignored.
    pub flags: u32,
    /// Borrowed name of the field this entry describes, or null if unnamed.
    pub name: *const c_char,
}

/// Borrowed table of per-tag length rules (`tlv_schema_t`).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct tlv_schema_t {
    /// Borrowed entries; may be null only when `count` is zero.
    pub entries: *const tlv_schema_entry_t,
    /// Number of entries.
    pub count: usize,
}

/// Expected form of a value (`tlv_schema_kind_t`).
pub type tlv_schema_kind_t = c_int;
/// The element may be primitive or constructed (`TLV_SCHEMA_ANY`).
pub const TLV_SCHEMA_ANY: tlv_schema_kind_t = 0;
/// The element must be primitive (`TLV_SCHEMA_PRIMITIVE`).
pub const TLV_SCHEMA_PRIMITIVE: tlv_schema_kind_t = 1;
/// The element must be constructed (`TLV_SCHEMA_CONSTRUCTED`).
pub const TLV_SCHEMA_CONSTRUCTED: tlv_schema_kind_t = 2;

/// Structural rule for one tag within a single parent (`tlv_structure_rule_t`).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct tlv_structure_rule_t {
    /// Tag and permitted value-length bounds.
    pub entry: tlv_schema_entry_t,
    /// Minimum occurrences within the parent.
    pub min_occurs: usize,
    /// Maximum occurrences within the parent; `usize::MAX` is unrestricted.
    pub max_occurs: usize,
    /// Required form of the value.
    pub kind: tlv_schema_kind_t,
    /// Schema for the value's children, or null.
    pub children: *const tlv_structure_schema_t,
}

/// Borrowed set of structural rules for one parent scope (`tlv_structure_schema_t`).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct tlv_structure_schema_t {
    /// Borrowed rules; tags must be unique.
    pub rules: *const tlv_structure_rule_t,
    /// Number of rules.
    pub count: usize,
    /// Nonzero accepts tags that match no rule.
    pub allow_unknown: c_int,
}

/// Result code of a value conversion (`tlv_codec_result_t`).
pub type tlv_codec_result_t = c_int;
/// The conversion succeeded (`TLV_CODEC_OK`).
pub const TLV_CODEC_OK: tlv_codec_result_t = 0;
/// A required pointer argument is null (`TLV_CODEC_ERR_NULL_ARG`).
pub const TLV_CODEC_ERR_NULL_ARG: tlv_codec_result_t = 1;
/// A supplied buffer is too small (`TLV_CODEC_ERR_BUFFER_TOO_SHORT`).
pub const TLV_CODEC_ERR_BUFFER_TOO_SHORT: tlv_codec_result_t = 2;
/// The value or its representation is invalid (`TLV_CODEC_ERR_INVALID_VALUE`).
pub const TLV_CODEC_ERR_INVALID_VALUE: tlv_codec_result_t = 3;
/// The operation is not supported by the codec (`TLV_CODEC_ERR_UNSUPPORTED`).
pub const TLV_CODEC_ERR_UNSUPPORTED: tlv_codec_result_t = 4;
/// A structure is malformed or violates its schema (`TLV_CODEC_ERR_INVALID_STRUCTURE`).
pub const TLV_CODEC_ERR_INVALID_STRUCTURE: tlv_codec_result_t = 5;

/// Value decoder callback of a codec.
pub type tlv_codec_decode_fn = unsafe extern "C" fn(
    context: *const c_void,
    data: *const u8,
    size: usize,
    value: *mut c_void,
    capacity: usize,
) -> tlv_codec_result_t;

/// Value encoder callback of a codec.
pub type tlv_codec_encode_fn = unsafe extern "C" fn(
    context: *const c_void,
    value: *const c_void,
    size: usize,
    data: *mut u8,
    capacity: usize,
    written: *mut usize,
) -> tlv_codec_result_t;

/// Borrowed codec descriptor (`tlv_codec_t`).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct tlv_codec_t {
    /// Immutable context passed to both callbacks; may be null.
    pub context: *const c_void,
    /// Decoder; `None` if unsupported.
    pub decode: Option<tlv_codec_decode_fn>,
    /// Encoder; `None` if unsupported.
    pub encode: Option<tlv_codec_encode_fn>,
}

/// Dictionary context of an EMV tag (`tlv_emv_context_t`).
pub type tlv_emv_context_t = c_int;
/// Ordinary application data (`TLV_EMV_CONTEXT_BASE`).
pub const TLV_EMV_CONTEXT_BASE: tlv_emv_context_t = 0;
/// Inside 7F60 (`TLV_EMV_CONTEXT_BIT`).
pub const TLV_EMV_CONTEXT_BIT: tlv_emv_context_t = 1;
/// Inside A1 within 7F60 (`TLV_EMV_CONTEXT_BHT`).
pub const TLV_EMV_CONTEXT_BHT: tlv_emv_context_t = 2;
/// Inside level-2 A1/A2 within BHT (`TLV_EMV_CONTEXT_BHT_FORMAT`).
pub const TLV_EMV_CONTEXT_BHT_FORMAT: tlv_emv_context_t = 3;
/// Inside BF4A/BF4B or a terminal group (`TLV_EMV_CONTEXT_BIT_GROUP`).
pub const TLV_EMV_CONTEXT_BIT_GROUP: tlv_emv_context_t = 4;
/// Inside BF4C (`TLV_EMV_CONTEXT_BIOMETRIC_COUNTERS`).
pub const TLV_EMV_CONTEXT_BIOMETRIC_COUNTERS: tlv_emv_context_t = 5;
/// Inside BF4D (`TLV_EMV_CONTEXT_BIOMETRIC_ATTEMPTS`).
pub const TLV_EMV_CONTEXT_BIOMETRIC_ATTEMPTS: tlv_emv_context_t = 6;
/// Inside BF4E (`TLV_EMV_CONTEXT_BIOMETRIC_VERIFICATION`).
pub const TLV_EMV_CONTEXT_BIOMETRIC_VERIFICATION: tlv_emv_context_t = 7;
/// Number of contexts, and the "no new context" result (`TLV_EMV_CONTEXT_COUNT`).
pub const TLV_EMV_CONTEXT_COUNT: tlv_emv_context_t = 8;

/// C representation of an EMV value (`tlv_emv_value_kind_t`).
pub type tlv_emv_value_kind_t = c_int;
/// Opaque bytes (`TLV_EMV_VALUE_BYTES`).
pub const TLV_EMV_VALUE_BYTES: tlv_emv_value_kind_t = 0;
/// Text bytes (`TLV_EMV_VALUE_TEXT`).
pub const TLV_EMV_VALUE_TEXT: tlv_emv_value_kind_t = 1;
/// Constructed template (`TLV_EMV_VALUE_TEMPLATE`).
pub const TLV_EMV_VALUE_TEMPLATE: tlv_emv_value_kind_t = 2;
/// `u64` number (`TLV_EMV_VALUE_NUMBER`).
pub const TLV_EMV_VALUE_NUMBER: tlv_emv_value_kind_t = 3;
/// `u64` bit flags (`TLV_EMV_VALUE_FLAGS`).
pub const TLV_EMV_VALUE_FLAGS: tlv_emv_value_kind_t = 4;
/// NUL-terminated decimal digits (`TLV_EMV_VALUE_DIGITS`).
pub const TLV_EMV_VALUE_DIGITS: tlv_emv_value_kind_t = 5;
/// [`tlv_emv_date_t`] (`TLV_EMV_VALUE_DATE`).
pub const TLV_EMV_VALUE_DATE: tlv_emv_value_kind_t = 6;
/// [`tlv_emv_time_t`] (`TLV_EMV_VALUE_TIME`).
pub const TLV_EMV_VALUE_TIME: tlv_emv_value_kind_t = 7;
/// Account type (`TLV_EMV_VALUE_ACCOUNT`).
pub const TLV_EMV_VALUE_ACCOUNT: tlv_emv_value_kind_t = 8;
/// [`tlv_emv_cryptogram_info_t`] (`TLV_EMV_VALUE_CRYPTOGRAM`).
pub const TLV_EMV_VALUE_CRYPTOGRAM: tlv_emv_value_kind_t = 9;
/// Biometric type (`TLV_EMV_VALUE_BIOMETRIC`).
pub const TLV_EMV_VALUE_BIOMETRIC: tlv_emv_value_kind_t = 10;
/// [`tlv_emv_number_list_t`] (`TLV_EMV_VALUE_NUMBER_LIST`).
pub const TLV_EMV_VALUE_NUMBER_LIST: tlv_emv_value_kind_t = 11;
/// [`tlv_emv_afl_t`] (`TLV_EMV_VALUE_AFL`).
pub const TLV_EMV_VALUE_AFL: tlv_emv_value_kind_t = 12;
/// [`tlv_emv_cvm_result_t`] (`TLV_EMV_VALUE_CVM_RESULT`).
pub const TLV_EMV_VALUE_CVM_RESULT: tlv_emv_value_kind_t = 13;
/// [`tlv_emv_track2_t`] (`TLV_EMV_VALUE_TRACK2`).
pub const TLV_EMV_VALUE_TRACK2: tlv_emv_value_kind_t = 14;

/// Decoded EMV date (`tlv_emv_date_t`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct tlv_emv_date_t {
    /// Two-digit year.
    pub year: u8,
    /// Month, 1..12.
    pub month: u8,
    /// Day of month.
    pub day: u8,
}

/// Decoded EMV time (`tlv_emv_time_t`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct tlv_emv_time_t {
    /// Hour.
    pub hour: u8,
    /// Minute.
    pub minute: u8,
    /// Second.
    pub second: u8,
}

/// Account type (`tlv_emv_account_type_t`), a C `enum`.
pub type tlv_emv_account_type_t = c_int;
/// Default account (`TLV_EMV_ACCOUNT_DEFAULT`).
pub const TLV_EMV_ACCOUNT_DEFAULT: tlv_emv_account_type_t = 0;
/// Savings account (`TLV_EMV_ACCOUNT_SAVINGS`).
pub const TLV_EMV_ACCOUNT_SAVINGS: tlv_emv_account_type_t = 10;
/// Cheque or debit account (`TLV_EMV_ACCOUNT_CHEQUE_DEBIT`).
pub const TLV_EMV_ACCOUNT_CHEQUE_DEBIT: tlv_emv_account_type_t = 20;
/// Credit account (`TLV_EMV_ACCOUNT_CREDIT`).
pub const TLV_EMV_ACCOUNT_CREDIT: tlv_emv_account_type_t = 30;

/// Cryptogram type (`tlv_emv_cryptogram_type_t`), a C `enum`; values 0..=3.
pub type tlv_emv_cryptogram_type_t = c_int;

/// Decoded Cryptogram Information Data (`tlv_emv_cryptogram_info_t`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct tlv_emv_cryptogram_info_t {
    /// Cryptogram type, from wire bits b8-b7.
    pub type_: tlv_emv_cryptogram_type_t,
    /// Remaining six bits.
    pub flags: u8,
}

/// Biometric type (`tlv_emv_biometric_type_t`), a C `enum`.
pub type tlv_emv_biometric_type_t = c_int;
/// Facial biometric (`TLV_EMV_BIOMETRIC_FACIAL`).
pub const TLV_EMV_BIOMETRIC_FACIAL: tlv_emv_biometric_type_t = 0x02;
/// Voice biometric (`TLV_EMV_BIOMETRIC_VOICE`).
pub const TLV_EMV_BIOMETRIC_VOICE: tlv_emv_biometric_type_t = 0x04;
/// Fingerprint biometric (`TLV_EMV_BIOMETRIC_FINGER`).
pub const TLV_EMV_BIOMETRIC_FINGER: tlv_emv_biometric_type_t = 0x08;
/// Iris biometric (`TLV_EMV_BIOMETRIC_IRIS`).
pub const TLV_EMV_BIOMETRIC_IRIS: tlv_emv_biometric_type_t = 0x10;
/// Palm biometric (`TLV_EMV_BIOMETRIC_PALM`).
pub const TLV_EMV_BIOMETRIC_PALM: tlv_emv_biometric_type_t = 0x020000;

/// Decoded list of up to four numbers (`tlv_emv_number_list_t`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct tlv_emv_number_list_t {
    /// List values; only the first `count` are populated.
    pub values: [u64; 4],
    /// Number of populated entries.
    pub count: usize,
}

/// One Application File Locator entry (`tlv_emv_afl_entry_t`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct tlv_emv_afl_entry_t {
    /// Short file identifier, 1-30.
    pub sfi: u8,
    /// First record, nonzero.
    pub first_record: u8,
    /// Last record, not below `first_record`.
    pub last_record: u8,
    /// Leading records used for offline data authentication.
    pub offline_auth_record_count: u8,
}

/// Maximum number of AFL entries (`TLV_EMV_AFL_MAX_ENTRIES`).
pub const TLV_EMV_AFL_MAX_ENTRIES: usize = 63;

/// Decoded Application File Locator (`tlv_emv_afl_t`).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct tlv_emv_afl_t {
    /// Entries in wire order; only the first `count` are populated.
    pub entries: [tlv_emv_afl_entry_t; TLV_EMV_AFL_MAX_ENTRIES],
    /// Number of populated entries.
    pub count: usize,
}

/// CVM Results, preserved raw (`tlv_emv_cvm_result_t`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct tlv_emv_cvm_result_t {
    /// CVM method code.
    pub method: u8,
    /// CVM condition code.
    pub condition: u8,
    /// CVM outcome.
    pub result: u8,
}

/// Maximum PAN digits in Track 2 data (`TLV_EMV_TRACK2_PAN_MAX_DIGITS`).
pub const TLV_EMV_TRACK2_PAN_MAX_DIGITS: usize = 19;
/// Maximum discretionary digits (`TLV_EMV_TRACK2_DISCRETIONARY_MAX_DIGITS`).
pub const TLV_EMV_TRACK2_DISCRETIONARY_MAX_DIGITS: usize = 30;

/// Decoded Track 2 Equivalent Data (`tlv_emv_track2_t`).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct tlv_emv_track2_t {
    /// PAN digits, NUL-terminated.
    pub pan: [c_char; TLV_EMV_TRACK2_PAN_MAX_DIGITS + 1],
    /// Expiration year, YY.
    pub expiration_year: u8,
    /// Expiration month, 1-12.
    pub expiration_month: u8,
    /// Three-digit service code.
    pub service_code: u16,
    /// Discretionary data digits, NUL-terminated.
    pub discretionary_data: [c_char; TLV_EMV_TRACK2_DISCRETIONARY_MAX_DIGITS + 1],
}

/// One entry of the EMV data dictionary (`tlv_emv_definition_t`).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct tlv_emv_definition_t {
    /// Tag and length bounds; borrowed from static tables.
    pub schema: *const tlv_schema_entry_t,
    /// Stable symbolic name.
    pub name: *const c_char,
    /// C representation of the value.
    pub value_kind: tlv_emv_value_kind_t,
    /// Semantic codec; null when no conversion is provided.
    pub codec: *const tlv_codec_t,
    /// Permitted lengths: `min + n * step`.
    pub length_step: usize,
}

/// Inclusive resource limits for DER validation and writing (`tlv_der_limits_t`).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct tlv_der_limits_t {
    /// Maximum number of constructed ancestors.
    pub max_depth: usize,
    /// Bounds the input, or the complete output when writing.
    pub max_input_size: usize,
    /// Bounds each value.
    pub max_value_size: usize,
    /// Bounds the total visited elements.
    pub max_elements: usize,
}

/// Inclusive resource limits for CER validation and writing (`tlv_cer_limits_t`).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct tlv_cer_limits_t {
    /// Maximum number of constructed ancestors.
    pub max_depth: usize,
    /// Bounds the input, or the complete output when writing.
    pub max_input_size: usize,
    /// Bounds each element's content.
    pub max_value_size: usize,
    /// Bounds the total visited elements.
    pub max_elements: usize,
}

/// Preorder DER traversal callback (`tlv_der_visitor_t`); the safe crate passes `None`.
pub type tlv_der_visitor_t = unsafe extern "C" fn(
    view: *const tlv_view_t,
    depth: usize,
    offset: usize,
    context: *mut c_void,
) -> c_int;

/// Preorder CER traversal callback (`tlv_cer_visitor_t`); the safe crate passes `None`.
pub type tlv_cer_visitor_t = tlv_der_visitor_t;

extern "C" {
    /// Nesting predicate for BER.
    pub fn tlv_ber_is_constructed(context: *const c_void, tag: *const tlv_tag_t) -> c_int;
    /// Nesting predicate for CER.
    pub fn tlv_cer_is_constructed(context: *const c_void, tag: *const tlv_tag_t) -> c_int;
    /// Nesting predicate for DER.
    pub fn tlv_der_is_constructed(context: *const c_void, tag: *const tlv_tag_t) -> c_int;

    /// Looks up a tag's entry by linear search.
    pub fn tlv_schema_find(
        schema: *const tlv_schema_t,
        tag: *const tlv_tag_t,
    ) -> *const tlv_schema_entry_t;
    /// Validates a value length against an entry's bounds.
    pub fn tlv_schema_validate_length(
        entry: *const tlv_schema_entry_t,
        length: usize,
    ) -> tlv_result_t;
    /// Validates framing, nesting, lengths, occurrences and membership.
    pub fn tlv_schema_validate(
        data: *const u8,
        size: usize,
        format: *const tlv_reader_format_t,
        is_constructed: Option<tlv_is_constructed_fn>,
        schema: *const tlv_structure_schema_t,
        max_depth: usize,
        max_elements: usize,
        error_offset: *mut usize,
    ) -> tlv_result_t;

    /// Structural schema for common EMV top-level data objects.
    pub static tlv_emv_structure_schema: tlv_structure_schema_t;
    /// EMV dictionary length schema for the base context.
    pub static tlv_emv_schema: tlv_schema_t;
    /// Returns the EMV dictionary schema for a context, or null.
    pub fn tlv_emv_schema_for(context: tlv_emv_context_t) -> *const tlv_schema_t;
    /// Looks up a tag's definition in a context, or null.
    pub fn tlv_emv_find(
        context: tlv_emv_context_t,
        tag: *const tlv_tag_t,
    ) -> *const tlv_emv_definition_t;
    /// Returns the context for a tag's children.
    pub fn tlv_emv_child_context(
        context: tlv_emv_context_t,
        tag: *const tlv_tag_t,
    ) -> tlv_emv_context_t;
    /// Validates a length against a definition.
    pub fn tlv_emv_validate_length(
        definition: *const tlv_emv_definition_t,
        length: usize,
    ) -> tlv_result_t;
    /// Returns a curated label for a dictionary symbol, or null.
    pub fn tlv_emv_display_label(name: *const c_char) -> *const c_char;
    /// Describes an EMV value kind.
    pub fn tlv_emv_value_kind_description(kind: tlv_emv_value_kind_t) -> *const c_char;
    /// Codec for amounts (format n12).
    pub static tlv_emv_codec_amount: tlv_codec_t;

    /// Decodes a raw value with a codec.
    pub fn tlv_codec_decode(
        codec: *const tlv_codec_t,
        data: *const u8,
        size: usize,
        value: *mut c_void,
        capacity: usize,
    ) -> tlv_codec_result_t;
    /// Encodes a C representation into raw value bytes with a codec.
    pub fn tlv_codec_encode(
        codec: *const tlv_codec_t,
        value: *const c_void,
        size: usize,
        data: *mut u8,
        capacity: usize,
        written: *mut usize,
    ) -> tlv_codec_result_t;
    /// Describes a codec result.
    pub fn tlv_codec_strerror(result: tlv_codec_result_t) -> *const c_char;

    /// Default DER limits.
    pub static tlv_der_default_limits: tlv_der_limits_t;
    /// Validates one complete DER element.
    pub fn tlv_der_read(
        data: *const u8,
        size: usize,
        limits: *const tlv_der_limits_t,
        view: *mut tlv_view_t,
        consumed: *mut usize,
        error_offset: *mut usize,
    ) -> tlv_result_t;
    /// Strict counterpart of [`tlv_der_read`].
    pub fn tlv_der_read_strict(
        data: *const u8,
        size: usize,
        limits: *const tlv_der_limits_t,
        view: *mut tlv_view_t,
        consumed: *mut usize,
        error_offset: *mut usize,
    ) -> tlv_result_t;
    /// Validates all concatenated DER elements recursively.
    pub fn tlv_der_walk(
        data: *const u8,
        size: usize,
        limits: *const tlv_der_limits_t,
        visitor: Option<tlv_der_visitor_t>,
        context: *mut c_void,
        error_offset: *mut usize,
    ) -> tlv_result_t;
    /// Strict counterpart of [`tlv_der_walk`].
    pub fn tlv_der_walk_strict(
        data: *const u8,
        size: usize,
        limits: *const tlv_der_limits_t,
        visitor: Option<tlv_der_visitor_t>,
        context: *mut c_void,
        error_offset: *mut usize,
    ) -> tlv_result_t;
    /// Writes a canonical DER element.
    pub fn tlv_der_write(
        data: *mut u8,
        capacity: usize,
        tag: tlv_tag_t,
        value: *const u8,
        length: usize,
        limits: *const tlv_der_limits_t,
        written: *mut usize,
        error_offset: *mut usize,
    ) -> tlv_result_t;
    /// Strict counterpart of [`tlv_der_write`].
    pub fn tlv_der_write_strict(
        data: *mut u8,
        capacity: usize,
        tag: tlv_tag_t,
        value: *const u8,
        length: usize,
        limits: *const tlv_der_limits_t,
        written: *mut usize,
        error_offset: *mut usize,
    ) -> tlv_result_t;

    /// Default CER limits.
    pub static tlv_cer_default_limits: tlv_cer_limits_t;
    /// Validates one complete CER element.
    pub fn tlv_cer_read(
        data: *const u8,
        size: usize,
        limits: *const tlv_cer_limits_t,
        view: *mut tlv_view_t,
        consumed: *mut usize,
        error_offset: *mut usize,
    ) -> tlv_result_t;
    /// Strict counterpart of [`tlv_cer_read`].
    pub fn tlv_cer_read_strict(
        data: *const u8,
        size: usize,
        limits: *const tlv_cer_limits_t,
        view: *mut tlv_view_t,
        consumed: *mut usize,
        error_offset: *mut usize,
    ) -> tlv_result_t;
    /// Validates all concatenated CER elements recursively.
    pub fn tlv_cer_walk(
        data: *const u8,
        size: usize,
        limits: *const tlv_cer_limits_t,
        visitor: Option<tlv_cer_visitor_t>,
        context: *mut c_void,
        error_offset: *mut usize,
    ) -> tlv_result_t;
    /// Strict counterpart of [`tlv_cer_walk`].
    pub fn tlv_cer_walk_strict(
        data: *const u8,
        size: usize,
        limits: *const tlv_cer_limits_t,
        visitor: Option<tlv_cer_visitor_t>,
        context: *mut c_void,
        error_offset: *mut usize,
    ) -> tlv_result_t;
    /// Writes a canonical CER element.
    pub fn tlv_cer_write(
        data: *mut u8,
        capacity: usize,
        tag: tlv_tag_t,
        value: *const u8,
        length: usize,
        limits: *const tlv_cer_limits_t,
        written: *mut usize,
        error_offset: *mut usize,
    ) -> tlv_result_t;
    /// Strict counterpart of [`tlv_cer_write`].
    pub fn tlv_cer_write_strict(
        data: *mut u8,
        capacity: usize,
        tag: tlv_tag_t,
        value: *const u8,
        length: usize,
        limits: *const tlv_cer_limits_t,
        written: *mut usize,
        error_offset: *mut usize,
    ) -> tlv_result_t;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[test]
    fn links_and_reports_version() {
        let version = unsafe { CStr::from_ptr(tlv_version_string()) }
            .to_str()
            .unwrap();
        let expected = unsafe {
            format!(
                "{}.{}.{}",
                tlv_version_major(),
                tlv_version_minor(),
                tlv_version_patch()
            )
        };
        assert!(version.starts_with(&expected), "{version} vs {expected}");
    }

    #[test]
    fn strerror_describes_ok() {
        let message = unsafe { CStr::from_ptr(tlv_strerror(TLV_OK)) };
        assert!(!message.to_bytes().is_empty());
    }
}
