//! Value codecs: conversion between raw TLV values and typed Rust values.
//!
//! The conversions run in the C library's codecs. This module owns the
//! correctly sized and aligned C objects the codecs read and write and maps
//! them to Rust types. Codecs are obtained from the EMV dictionary, see
//! [`Definition::codec`](crate::emv::Definition::codec), or from
//! [`Codec::amount`].

use std::error;
use std::ffi::{c_void, CStr};
use std::fmt;
use std::mem::{self, MaybeUninit};
use std::os::raw::c_char;
use std::ptr;

use opentlv_native as native;

/// An error of a value conversion, mapped from a `tlv_codec_result_t`.
///
/// Value-conversion errors are independent of TLV framing errors, which use
/// [`Error`](crate::Error).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CodecError {
    /// A required pointer argument is `NULL`.
    NullArg,
    /// A supplied buffer is too small for the data or representation.
    BufferTooShort,
    /// The value or its representation is invalid for the codec.
    InvalidValue,
    /// The requested direction or operation is not supported by the codec.
    Unsupported,
    /// A complete structure is malformed, or violates its schema or limits.
    InvalidStructure,
    /// A result code not known to this crate; carries the raw code.
    Unknown(i32),
}

/// Result type of value conversions.
pub type CodecResult<T> = std::result::Result<T, CodecError>;

impl CodecError {
    /// Maps a raw `tlv_codec_result_t` to an error, or `None` for success.
    pub fn from_code(code: i32) -> Option<CodecError> {
        Some(match code {
            native::TLV_CODEC_OK => return None,
            native::TLV_CODEC_ERR_NULL_ARG => CodecError::NullArg,
            native::TLV_CODEC_ERR_BUFFER_TOO_SHORT => CodecError::BufferTooShort,
            native::TLV_CODEC_ERR_INVALID_VALUE => CodecError::InvalidValue,
            native::TLV_CODEC_ERR_UNSUPPORTED => CodecError::Unsupported,
            native::TLV_CODEC_ERR_INVALID_STRUCTURE => CodecError::InvalidStructure,
            other => CodecError::Unknown(other),
        })
    }

    /// Returns the raw `tlv_codec_result_t` code of the error.
    pub fn code(self) -> i32 {
        match self {
            CodecError::NullArg => native::TLV_CODEC_ERR_NULL_ARG,
            CodecError::BufferTooShort => native::TLV_CODEC_ERR_BUFFER_TOO_SHORT,
            CodecError::InvalidValue => native::TLV_CODEC_ERR_INVALID_VALUE,
            CodecError::Unsupported => native::TLV_CODEC_ERR_UNSUPPORTED,
            CodecError::InvalidStructure => native::TLV_CODEC_ERR_INVALID_STRUCTURE,
            CodecError::Unknown(code) => code,
        }
    }

    fn check(code: native::tlv_codec_result_t) -> CodecResult<()> {
        match CodecError::from_code(code) {
            None => Ok(()),
            Some(err) => Err(err),
        }
    }
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // SAFETY: `tlv_codec_strerror` returns a static NUL-terminated string
        // for every code.
        let message = unsafe { CStr::from_ptr(native::tlv_codec_strerror(self.code())) };
        f.write_str(&message.to_string_lossy())
    }
}

impl error::Error for CodecError {}

/// The representation a semantic codec converts a raw value to and from.
///
/// [`ValueKind::Bytes`], [`ValueKind::Text`] and [`ValueKind::Template`] have
/// no codec: use the borrowed value of the reader directly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ValueKind {
    /// Opaque bytes; no codec.
    Bytes,
    /// Text bytes, not necessarily UTF-8; no codec.
    Text,
    /// Constructed template of nested data objects; no codec.
    Template,
    /// [`Value::Number`]: a binary or decimal BCD number.
    Number,
    /// [`Value::Flags`]: bit flags, every wire bit preserved.
    Flags,
    /// [`Value::Digits`]: decimal digits.
    Digits,
    /// [`Value::Date`].
    Date,
    /// [`Value::Time`].
    Time,
    /// [`Value::Account`].
    Account,
    /// [`Value::Cryptogram`].
    Cryptogram,
    /// [`Value::Biometric`].
    Biometric,
    /// [`Value::NumberList`].
    NumberList,
    /// [`Value::Afl`].
    Afl,
    /// [`Value::CvmResult`].
    CvmResult,
    /// [`Value::Track2`].
    Track2,
}

impl ValueKind {
    pub(crate) fn from_raw(raw: native::tlv_emv_value_kind_t) -> Option<ValueKind> {
        Some(match raw {
            native::TLV_EMV_VALUE_BYTES => ValueKind::Bytes,
            native::TLV_EMV_VALUE_TEXT => ValueKind::Text,
            native::TLV_EMV_VALUE_TEMPLATE => ValueKind::Template,
            native::TLV_EMV_VALUE_NUMBER => ValueKind::Number,
            native::TLV_EMV_VALUE_FLAGS => ValueKind::Flags,
            native::TLV_EMV_VALUE_DIGITS => ValueKind::Digits,
            native::TLV_EMV_VALUE_DATE => ValueKind::Date,
            native::TLV_EMV_VALUE_TIME => ValueKind::Time,
            native::TLV_EMV_VALUE_ACCOUNT => ValueKind::Account,
            native::TLV_EMV_VALUE_CRYPTOGRAM => ValueKind::Cryptogram,
            native::TLV_EMV_VALUE_BIOMETRIC => ValueKind::Biometric,
            native::TLV_EMV_VALUE_NUMBER_LIST => ValueKind::NumberList,
            native::TLV_EMV_VALUE_AFL => ValueKind::Afl,
            native::TLV_EMV_VALUE_CVM_RESULT => ValueKind::CvmResult,
            native::TLV_EMV_VALUE_TRACK2 => ValueKind::Track2,
            _ => return None,
        })
    }

    fn raw(self) -> native::tlv_emv_value_kind_t {
        match self {
            ValueKind::Bytes => native::TLV_EMV_VALUE_BYTES,
            ValueKind::Text => native::TLV_EMV_VALUE_TEXT,
            ValueKind::Template => native::TLV_EMV_VALUE_TEMPLATE,
            ValueKind::Number => native::TLV_EMV_VALUE_NUMBER,
            ValueKind::Flags => native::TLV_EMV_VALUE_FLAGS,
            ValueKind::Digits => native::TLV_EMV_VALUE_DIGITS,
            ValueKind::Date => native::TLV_EMV_VALUE_DATE,
            ValueKind::Time => native::TLV_EMV_VALUE_TIME,
            ValueKind::Account => native::TLV_EMV_VALUE_ACCOUNT,
            ValueKind::Cryptogram => native::TLV_EMV_VALUE_CRYPTOGRAM,
            ValueKind::Biometric => native::TLV_EMV_VALUE_BIOMETRIC,
            ValueKind::NumberList => native::TLV_EMV_VALUE_NUMBER_LIST,
            ValueKind::Afl => native::TLV_EMV_VALUE_AFL,
            ValueKind::CvmResult => native::TLV_EMV_VALUE_CVM_RESULT,
            ValueKind::Track2 => native::TLV_EMV_VALUE_TRACK2,
        }
    }

    /// Returns `true` if a codec exists for this kind.
    pub fn has_codec(self) -> bool {
        !matches!(
            self,
            ValueKind::Bytes | ValueKind::Text | ValueKind::Template
        )
    }

    /// Describes the kind's representation and wire meaning, for example
    /// `"Bit flags"` for [`ValueKind::Flags`].
    pub fn description(self) -> &'static str {
        // SAFETY: the function returns a static NUL-terminated ASCII string.
        unsafe { CStr::from_ptr(native::tlv_emv_value_kind_description(self.raw())) }
            .to_str()
            .expect("description is ASCII")
    }
}

/// A decoded EMV date; `year` is YY (0..99) with no century inferred.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Date {
    /// Two-digit year, 0..99.
    pub year: u8,
    /// Month, 1..12.
    pub month: u8,
    /// Day of month.
    pub day: u8,
}

/// A decoded EMV time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Time {
    /// Hour.
    pub hour: u8,
    /// Minute.
    pub minute: u8,
    /// Second.
    pub second: u8,
}

/// EMV account type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AccountType {
    /// Default (unspecified) account.
    Default,
    /// Savings account.
    Savings,
    /// Cheque or debit account.
    ChequeDebit,
    /// Credit account.
    Credit,
}

/// Cryptogram type carried in the two most significant bits of the CID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CryptogramType {
    /// Application Authentication Cryptogram (AAC).
    Aac,
    /// Transaction Certificate (TC).
    Tc,
    /// Authorisation Request Cryptogram (ARQC).
    Arqc,
    /// Reserved for future use.
    Rfu,
}

/// A decoded Cryptogram Information Data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CryptogramInfo {
    /// Cryptogram type, from wire bits b8-b7.
    pub kind: CryptogramType,
    /// Remaining six bits, preserved without interpretation.
    pub flags: u8,
}

/// EMV biometric type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BiometricType {
    /// Facial biometric.
    Facial,
    /// Voice biometric.
    Voice,
    /// Fingerprint biometric.
    Finger,
    /// Iris biometric.
    Iris,
    /// Palm biometric.
    Palm,
}

/// One Application File Locator entry.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct AflEntry {
    /// Short file identifier, 1-30.
    pub sfi: u8,
    /// First record of the inclusive range; nonzero.
    pub first_record: u8,
    /// Last record of the inclusive range; not below `first_record`.
    pub last_record: u8,
    /// Leading records of the range used for offline data authentication.
    pub offline_auth_record_count: u8,
}

/// CVM Results, preserved raw.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct CvmResult {
    /// CVM method code.
    pub method: u8,
    /// CVM condition code.
    pub condition: u8,
    /// CVM outcome: 0 unknown, 1 failed, 2 successful.
    pub result: u8,
}

/// Decoded Track 2 Equivalent Data.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Track2 {
    /// Primary account number: 1-19 decimal digits.
    pub pan: String,
    /// Expiration year, YY, 0-99.
    pub expiration_year: u8,
    /// Expiration month, 1-12.
    pub expiration_month: u8,
    /// Three-digit service code, 0-999.
    pub service_code: u16,
    /// Discretionary data: up to 30 decimal digits; may be empty.
    pub discretionary_data: String,
}

/// A typed value a [`Codec`] converts a raw TLV value to and from.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Value {
    /// A binary or BCD number.
    Number(u64),
    /// Bit flags, every wire bit preserved.
    Flags(u64),
    /// Decimal digits, for example a PAN without padding.
    Digits(String),
    /// A date.
    Date(Date),
    /// A time.
    Time(Time),
    /// An account type.
    Account(AccountType),
    /// Cryptogram Information Data.
    Cryptogram(CryptogramInfo),
    /// A biometric type.
    Biometric(BiometricType),
    /// A list of up to four numbers.
    NumberList(Vec<u64>),
    /// An Application File Locator of up to 63 entries.
    Afl(Vec<AflEntry>),
    /// CVM Results.
    CvmResult(CvmResult),
    /// Track 2 Equivalent Data.
    Track2(Track2),
}

impl Value {
    /// Returns the [`ValueKind`] this value belongs to.
    pub fn kind(&self) -> ValueKind {
        match self {
            Value::Number(_) => ValueKind::Number,
            Value::Flags(_) => ValueKind::Flags,
            Value::Digits(_) => ValueKind::Digits,
            Value::Date(_) => ValueKind::Date,
            Value::Time(_) => ValueKind::Time,
            Value::Account(_) => ValueKind::Account,
            Value::Cryptogram(_) => ValueKind::Cryptogram,
            Value::Biometric(_) => ValueKind::Biometric,
            Value::NumberList(_) => ValueKind::NumberList,
            Value::Afl(_) => ValueKind::Afl,
            Value::CvmResult(_) => ValueKind::CvmResult,
            Value::Track2(_) => ValueKind::Track2,
        }
    }
}

/// A value codec: converts a raw TLV value to a typed [`Value`] and back.
///
/// All validation (lengths, BCD digits, calendar ranges, enum membership) is
/// done by the C library. A codec is a cheap, `Copy` handle to an immutable
/// C descriptor.
///
/// ```
/// use opentlv::{Codec, Value};
///
/// let amount = Codec::amount();
/// let raw = [0x00, 0x00, 0x00, 0x00, 0x12, 0x34];
/// assert_eq!(amount.decode(&raw).unwrap(), Value::Number(1234));
/// assert_eq!(amount.encode(&Value::Number(1234)).unwrap(), raw);
/// ```
#[derive(Clone, Copy)]
pub struct Codec {
    raw: &'static native::tlv_codec_t,
    kind: ValueKind,
}

// SAFETY: the descriptor is immutable static data; its callbacks are pure.
unsafe impl Send for Codec {}
unsafe impl Sync for Codec {}

impl fmt::Debug for Codec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Codec").field("kind", &self.kind).finish()
    }
}

/// Copies the bytes of `text` into a zeroed, NUL-terminated C array, or fails
/// if it does not fit.
fn fill_cstr<const N: usize>(text: &str) -> CodecResult<[c_char; N]> {
    let bytes = text.as_bytes();
    if bytes.len() >= N {
        return Err(CodecError::InvalidValue);
    }
    let mut out = [0 as c_char; N];
    for (dst, src) in out.iter_mut().zip(bytes) {
        *dst = *src as c_char;
    }
    Ok(out)
}

/// Reads a NUL-terminated C array; an unterminated array is read in full.
fn read_cstr(chars: &[c_char]) -> CodecResult<String> {
    let bytes: Vec<u8> = chars
        .iter()
        .take_while(|c| **c != 0)
        .map(|c| *c as u8)
        .collect();
    String::from_utf8(bytes).map_err(|_| CodecError::InvalidValue)
}

impl Codec {
    /// # Safety
    ///
    /// `raw` must point to a valid codec descriptor with static lifetime whose
    /// representation is described by `kind`.
    pub(crate) unsafe fn from_raw(
        raw: *const native::tlv_codec_t,
        kind: ValueKind,
    ) -> Option<Codec> {
        Some(Codec {
            raw: raw.as_ref()?,
            kind,
        })
    }

    /// Returns the codec for amounts (format n12): six bytes of BCD to and
    /// from a [`Value::Number`] in unscaled minor units.
    pub fn amount() -> Codec {
        // SAFETY: only the address of an immutable static is taken; it lives
        // for the whole program and its representation is a `u64`.
        unsafe {
            Codec::from_raw(
                ptr::addr_of!(native::tlv_emv_codec_amount),
                ValueKind::Number,
            )
        }
        .expect("the address of a static is not null")
    }

    /// Returns the representation this codec converts to and from.
    pub fn kind(&self) -> ValueKind {
        self.kind
    }

    /// Calls the C decoder into `out`, a zero-initialized `T`.
    fn decode_into<T>(&self, data: &[u8], out: &mut T) -> CodecResult<()> {
        // SAFETY: `data` is a valid slice; `out` is a valid, writable object of
        // the size passed as capacity, and it has the C type this codec kind
        // decodes into. The codec descriptor is immutable and static.
        CodecError::check(unsafe {
            native::tlv_codec_decode(
                self.raw,
                data.as_ptr(),
                data.len(),
                (out as *mut T).cast::<c_void>(),
                mem::size_of::<T>(),
            )
        })
    }

    /// Decodes a raw value, for example the value of an [`Entry`](crate::Entry).
    ///
    /// # Errors
    ///
    /// [`CodecError::InvalidValue`] if the bytes are not a valid value of this
    /// codec's kind (wrong length, bad BCD digit, out-of-range field, …).
    pub fn decode(&self, data: &[u8]) -> CodecResult<Value> {
        // SAFETY (all `zeroed` uses below): the C types are plain integers,
        // arrays and structs of them, for which all-zero bytes are valid.
        Ok(match self.kind {
            ValueKind::Number | ValueKind::Flags => {
                let mut number = 0u64;
                self.decode_into(data, &mut number)?;
                if self.kind == ValueKind::Number {
                    Value::Number(number)
                } else {
                    Value::Flags(number)
                }
            }
            ValueKind::Digits => {
                // At most two digits per byte, plus the terminating NUL.
                let mut digits = vec![0u8; data.len() * 2 + 1];
                // SAFETY: `digits` is a valid writable buffer of its length;
                // the digits codec writes a NUL-terminated string into it.
                CodecError::check(unsafe {
                    native::tlv_codec_decode(
                        self.raw,
                        data.as_ptr(),
                        data.len(),
                        digits.as_mut_ptr().cast::<c_void>(),
                        digits.len(),
                    )
                })?;
                let end = digits.iter().position(|b| *b == 0).unwrap_or(digits.len());
                digits.truncate(end);
                Value::Digits(String::from_utf8(digits).map_err(|_| CodecError::InvalidValue)?)
            }
            ValueKind::Date => {
                let mut date = native::tlv_emv_date_t::default();
                self.decode_into(data, &mut date)?;
                Value::Date(Date {
                    year: date.year,
                    month: date.month,
                    day: date.day,
                })
            }
            ValueKind::Time => {
                let mut time = native::tlv_emv_time_t::default();
                self.decode_into(data, &mut time)?;
                Value::Time(Time {
                    hour: time.hour,
                    minute: time.minute,
                    second: time.second,
                })
            }
            ValueKind::Account => {
                let mut account: native::tlv_emv_account_type_t = 0;
                self.decode_into(data, &mut account)?;
                Value::Account(match account {
                    native::TLV_EMV_ACCOUNT_DEFAULT => AccountType::Default,
                    native::TLV_EMV_ACCOUNT_SAVINGS => AccountType::Savings,
                    native::TLV_EMV_ACCOUNT_CHEQUE_DEBIT => AccountType::ChequeDebit,
                    native::TLV_EMV_ACCOUNT_CREDIT => AccountType::Credit,
                    _ => return Err(CodecError::InvalidValue),
                })
            }
            ValueKind::Cryptogram => {
                let mut info = native::tlv_emv_cryptogram_info_t::default();
                self.decode_into(data, &mut info)?;
                Value::Cryptogram(CryptogramInfo {
                    kind: match info.type_ {
                        0 => CryptogramType::Aac,
                        1 => CryptogramType::Tc,
                        2 => CryptogramType::Arqc,
                        3 => CryptogramType::Rfu,
                        _ => return Err(CodecError::InvalidValue),
                    },
                    flags: info.flags,
                })
            }
            ValueKind::Biometric => {
                let mut biometric: native::tlv_emv_biometric_type_t = 0;
                self.decode_into(data, &mut biometric)?;
                Value::Biometric(match biometric {
                    native::TLV_EMV_BIOMETRIC_FACIAL => BiometricType::Facial,
                    native::TLV_EMV_BIOMETRIC_VOICE => BiometricType::Voice,
                    native::TLV_EMV_BIOMETRIC_FINGER => BiometricType::Finger,
                    native::TLV_EMV_BIOMETRIC_IRIS => BiometricType::Iris,
                    native::TLV_EMV_BIOMETRIC_PALM => BiometricType::Palm,
                    _ => return Err(CodecError::InvalidValue),
                })
            }
            ValueKind::NumberList => {
                let mut list = native::tlv_emv_number_list_t::default();
                self.decode_into(data, &mut list)?;
                let count = list.count.min(list.values.len());
                Value::NumberList(list.values[..count].to_vec())
            }
            ValueKind::Afl => {
                let mut afl = MaybeUninit::<native::tlv_emv_afl_t>::zeroed();
                // SAFETY: zeroed is a valid `tlv_emv_afl_t`.
                let afl = unsafe { &mut *afl.as_mut_ptr() };
                self.decode_into(data, afl)?;
                let count = afl.count.min(afl.entries.len());
                Value::Afl(
                    afl.entries[..count]
                        .iter()
                        .map(|e| AflEntry {
                            sfi: e.sfi,
                            first_record: e.first_record,
                            last_record: e.last_record,
                            offline_auth_record_count: e.offline_auth_record_count,
                        })
                        .collect(),
                )
            }
            ValueKind::CvmResult => {
                let mut result = native::tlv_emv_cvm_result_t::default();
                self.decode_into(data, &mut result)?;
                Value::CvmResult(CvmResult {
                    method: result.method,
                    condition: result.condition,
                    result: result.result,
                })
            }
            ValueKind::Track2 => {
                let mut track2 = MaybeUninit::<native::tlv_emv_track2_t>::zeroed();
                // SAFETY: zeroed is a valid `tlv_emv_track2_t`.
                let track2 = unsafe { &mut *track2.as_mut_ptr() };
                self.decode_into(data, track2)?;
                Value::Track2(Track2 {
                    pan: read_cstr(&track2.pan)?,
                    expiration_year: track2.expiration_year,
                    expiration_month: track2.expiration_month,
                    service_code: track2.service_code,
                    discretionary_data: read_cstr(&track2.discretionary_data)?,
                })
            }
            ValueKind::Bytes | ValueKind::Text | ValueKind::Template => {
                return Err(CodecError::Unsupported)
            }
        })
    }

    /// Calls the C encoder for the object `value`. With a null `data` and
    /// zero `capacity` this is a size query.
    fn encode_object<T>(&self, value: &T, data: *mut u8, capacity: usize) -> CodecResult<usize> {
        self.encode_raw(
            (value as *const T).cast::<c_void>(),
            mem::size_of::<T>(),
            data,
            capacity,
        )
    }

    fn encode_raw(
        &self,
        value: *const c_void,
        size: usize,
        data: *mut u8,
        capacity: usize,
    ) -> CodecResult<usize> {
        let mut written = 0usize;
        // SAFETY: `value` points to `size` readable bytes of the C type of this
        // codec kind; `data` is either null with zero capacity or a writable
        // buffer of `capacity` bytes; `written` is a writable `usize` that
        // aliases neither.
        CodecError::check(unsafe {
            native::tlv_codec_encode(self.raw, value, size, data, capacity, &mut written)
        })?;
        Ok(written)
    }

    fn encode_value(&self, value: &Value, data: *mut u8, capacity: usize) -> CodecResult<usize> {
        if value.kind() != self.kind {
            return Err(CodecError::InvalidValue);
        }
        match value {
            Value::Number(n) | Value::Flags(n) => self.encode_object(n, data, capacity),
            Value::Digits(digits) => {
                self.encode_raw(digits.as_ptr().cast(), digits.len(), data, capacity)
            }
            Value::Date(d) => self.encode_object(
                &native::tlv_emv_date_t {
                    year: d.year,
                    month: d.month,
                    day: d.day,
                },
                data,
                capacity,
            ),
            Value::Time(t) => self.encode_object(
                &native::tlv_emv_time_t {
                    hour: t.hour,
                    minute: t.minute,
                    second: t.second,
                },
                data,
                capacity,
            ),
            Value::Account(account) => {
                let raw: native::tlv_emv_account_type_t = match account {
                    AccountType::Default => native::TLV_EMV_ACCOUNT_DEFAULT,
                    AccountType::Savings => native::TLV_EMV_ACCOUNT_SAVINGS,
                    AccountType::ChequeDebit => native::TLV_EMV_ACCOUNT_CHEQUE_DEBIT,
                    AccountType::Credit => native::TLV_EMV_ACCOUNT_CREDIT,
                };
                self.encode_object(&raw, data, capacity)
            }
            Value::Cryptogram(info) => self.encode_object(
                &native::tlv_emv_cryptogram_info_t {
                    type_: match info.kind {
                        CryptogramType::Aac => 0,
                        CryptogramType::Tc => 1,
                        CryptogramType::Arqc => 2,
                        CryptogramType::Rfu => 3,
                    },
                    flags: info.flags,
                },
                data,
                capacity,
            ),
            Value::Biometric(biometric) => {
                let raw: native::tlv_emv_biometric_type_t = match biometric {
                    BiometricType::Facial => native::TLV_EMV_BIOMETRIC_FACIAL,
                    BiometricType::Voice => native::TLV_EMV_BIOMETRIC_VOICE,
                    BiometricType::Finger => native::TLV_EMV_BIOMETRIC_FINGER,
                    BiometricType::Iris => native::TLV_EMV_BIOMETRIC_IRIS,
                    BiometricType::Palm => native::TLV_EMV_BIOMETRIC_PALM,
                };
                self.encode_object(&raw, data, capacity)
            }
            Value::NumberList(numbers) => {
                let mut list = native::tlv_emv_number_list_t::default();
                if numbers.len() > list.values.len() {
                    return Err(CodecError::InvalidValue);
                }
                list.values[..numbers.len()].copy_from_slice(numbers);
                list.count = numbers.len();
                self.encode_object(&list, data, capacity)
            }
            Value::Afl(entries) => {
                if entries.len() > native::TLV_EMV_AFL_MAX_ENTRIES {
                    return Err(CodecError::InvalidValue);
                }
                let mut afl = native::tlv_emv_afl_t {
                    entries: [native::tlv_emv_afl_entry_t::default();
                        native::TLV_EMV_AFL_MAX_ENTRIES],
                    count: entries.len(),
                };
                for (dst, src) in afl.entries.iter_mut().zip(entries) {
                    *dst = native::tlv_emv_afl_entry_t {
                        sfi: src.sfi,
                        first_record: src.first_record,
                        last_record: src.last_record,
                        offline_auth_record_count: src.offline_auth_record_count,
                    };
                }
                self.encode_object(&afl, data, capacity)
            }
            Value::CvmResult(result) => self.encode_object(
                &native::tlv_emv_cvm_result_t {
                    method: result.method,
                    condition: result.condition,
                    result: result.result,
                },
                data,
                capacity,
            ),
            Value::Track2(track2) => self.encode_object(
                &native::tlv_emv_track2_t {
                    pan: fill_cstr(&track2.pan)?,
                    expiration_year: track2.expiration_year,
                    expiration_month: track2.expiration_month,
                    service_code: track2.service_code,
                    discretionary_data: fill_cstr(&track2.discretionary_data)?,
                },
                data,
                capacity,
            ),
        }
    }

    /// Validates `value` and returns the size of its encoding without writing.
    ///
    /// # Errors
    ///
    /// [`CodecError::InvalidValue`] if `value` is of another kind than the
    /// codec's or invalid for it.
    pub fn encoded_size(&self, value: &Value) -> CodecResult<usize> {
        self.encode_value(value, ptr::null_mut(), 0)
    }

    /// Encodes `value` into `out` and returns the number of bytes written.
    ///
    /// # Errors
    ///
    /// [`CodecError::BufferTooShort`] if `out` is too small, or the errors of
    /// [`Codec::encoded_size`]. On error `out` may have been modified.
    pub fn encode_into(&self, value: &Value, out: &mut [u8]) -> CodecResult<usize> {
        self.encode_value(value, out.as_mut_ptr(), out.len())
    }

    /// Encodes `value` into a new vector.
    ///
    /// # Errors
    ///
    /// Same as [`Codec::encoded_size`].
    pub fn encode(&self, value: &Value) -> CodecResult<Vec<u8>> {
        let mut out = vec![0u8; self.encoded_size(value)?];
        let written = self.encode_into(value, &mut out)?;
        out.truncate(written);
        Ok(out)
    }
}
