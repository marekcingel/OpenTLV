#ifndef OPENTLV_CODEC_EMV_H
#define OPENTLV_CODEC_EMV_H
#include "tlv/codec/codec.h"
#include "tlv/export.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file emv.h
 * @brief Semantic codecs and C representations for EMV data element values.
 *
 * Use tlv_codec_decode() and tlv_codec_encode() with these codecs or with the
 * profile codec descriptors. Semantic codecs enforce the tag's length and
 * value representation and report errors as `TLV_CODEC_ERR_*`.
 *
 * Rules shared by all semantic codecs:
 * - Decode requires a destination of at least `sizeof` the documented C
 *   type; encode requires exactly that size. Unaligned storage is supported.
 *   Buffers must not overlap.
 * - DIGITS is the exception: decode needs `digit_count + 1` bytes and writes
 *   a NUL; encode takes the digit count (excluding the NUL). CN padding
 *   `F` is removed and leading zeroes are preserved. Empty or all-padding
 *   PANs are invalid.
 * - Variable-width numbers encode in the shortest permitted width. Size
 *   queries validate identically to writes.
 * - ACCOUNT and BIOMETRIC reject undefined enum values; the cryptogram RFU
 *   value is represented explicitly. DATE and TIME check BCD and
 *   calendar/clock ranges.
 * - AFL rejects an `sfi` outside 1-30, a `first_record` of 0, a
 *   `last_record` below `first_record`, and an `offline_auth_record_count`
 *   above the entry's record range.
 * - TRACK2 rejects a missing or misplaced field separator, a PAN outside
 *   1-19 digits, a non-decimal expiry, service-code or discretionary digit,
 *   and an `expiration_month` outside 1-12. Encode rejects a `discretionary_data`
 *   or `pan` string without a NUL within its documented array size.
 * - CVM_RESULT stores its three bytes without further validation, like FLAGS.
 */

/**
 * @brief C representation a semantic EMV codec converts a value to and from.
 *
 * #TLV_EMV_VALUE_BYTES, #TLV_EMV_VALUE_TEXT and #TLV_EMV_VALUE_TEMPLATE have
 * no codec: callers retain the reader's borrowed value. Text does not imply
 * UTF-8 or a terminating NUL. #TLV_EMV_VALUE_FLAGS preserves every wire bit,
 * including RFU bits, in a big-endian integer.
 *
 * @see tlv_emv_value_kind_description
 */
typedef enum {
    /** Opaque bytes; no codec. */
    TLV_EMV_VALUE_BYTES,
    /** Text bytes, not necessarily UTF-8 or NUL-terminated; no codec. */
    TLV_EMV_VALUE_TEXT,
    /** Constructed template of nested data objects; no codec. */
    TLV_EMV_VALUE_TEMPLATE,
    /** `uint64_t`: binary or decimal BCD number. */
    TLV_EMV_VALUE_NUMBER,
    /** `uint64_t`: bit flags, every wire bit preserved. */
    TLV_EMV_VALUE_FLAGS,
    /** `char[]`: NUL-terminated decimal digits. */
    TLV_EMV_VALUE_DIGITS,
    /** #tlv_emv_date_t. */
    TLV_EMV_VALUE_DATE,
    /** #tlv_emv_time_t. */
    TLV_EMV_VALUE_TIME,
    /** #tlv_emv_account_type_t. */
    TLV_EMV_VALUE_ACCOUNT,
    /** #tlv_emv_cryptogram_info_t. */
    TLV_EMV_VALUE_CRYPTOGRAM,
    /** #tlv_emv_biometric_type_t. */
    TLV_EMV_VALUE_BIOMETRIC,
    /** #tlv_emv_number_list_t. */
    TLV_EMV_VALUE_NUMBER_LIST,
    /** #tlv_emv_afl_t. */
    TLV_EMV_VALUE_AFL,
    /** #tlv_emv_cvm_result_t. */
    TLV_EMV_VALUE_CVM_RESULT,
    /** #tlv_emv_track2_t. */
    TLV_EMV_VALUE_TRACK2
} tlv_emv_value_kind_t;

/**
 * @brief Decoded EMV date (BCD `YYMMDD` on the wire).
 *
 * `year` is YY (0..99); no century is inferred. February 29 is accepted for
 * years divisible by four; the caller resolves century-dependent validity.
 */
typedef struct {
    /** Two-digit year, 0..99. */
    uint8_t year;
    /** Month, 1..12. */
    uint8_t month;
    /** Day of month. */
    uint8_t day;
} tlv_emv_date_t;

/** @brief Decoded EMV time (BCD `HHMMSS` on the wire). */
typedef struct {
    /** Hour. */
    uint8_t hour;
    /** Minute. */
    uint8_t minute;
    /** Second. */
    uint8_t second;
} tlv_emv_time_t;

/** @brief EMV account type; undefined values are rejected by the codec. */
typedef enum {
    /** Default (unspecified) account. */
    TLV_EMV_ACCOUNT_DEFAULT = 0,
    /** Savings account. */
    TLV_EMV_ACCOUNT_SAVINGS = 10,
    /** Cheque or debit account. */
    TLV_EMV_ACCOUNT_CHEQUE_DEBIT = 20,
    /** Credit account. */
    TLV_EMV_ACCOUNT_CREDIT = 30
} tlv_emv_account_type_t;

/** @brief Cryptogram type carried in the two most significant bits of the CID. */
typedef enum {
    /** Application Authentication Cryptogram (AAC). */
    TLV_EMV_CRYPTOGRAM_AAC = 0,
    /** Transaction Certificate (TC). */
    TLV_EMV_CRYPTOGRAM_TC = 1,
    /** Authorisation Request Cryptogram (ARQC). */
    TLV_EMV_CRYPTOGRAM_ARQC = 2,
    /** Reserved for future use; represented explicitly rather than rejected. */
    TLV_EMV_CRYPTOGRAM_RFU = 3
} tlv_emv_cryptogram_type_t;

/** @brief Decoded Cryptogram Information Data. */
typedef struct {
    /** Cryptogram type, from wire bits b8-b7. */
    tlv_emv_cryptogram_type_t type;
    /** Remaining six bits, preserved without interpretation. */
    uint8_t flags;
} tlv_emv_cryptogram_info_t;

/** @brief Biometric type; undefined values are rejected by the codec. */
typedef enum {
    /** Facial biometric. */
    TLV_EMV_BIOMETRIC_FACIAL = 0x02,
    /** Voice biometric. */
    TLV_EMV_BIOMETRIC_VOICE = 0x04,
    /** Fingerprint biometric. */
    TLV_EMV_BIOMETRIC_FINGER = 0x08,
    /** Iris biometric. */
    TLV_EMV_BIOMETRIC_IRIS = 0x10,
    /** Palm biometric. */
    TLV_EMV_BIOMETRIC_PALM = 0x020000
} tlv_emv_biometric_type_t;

/** @brief Decoded list of up to four numbers. */
typedef struct {
    /** List values; only the first `count` entries are populated. */
    uint64_t values[4];
    /** Number of populated entries in `values`. */
    size_t count;
} tlv_emv_number_list_t;

/**
 * @brief One Application File Locator entry (Book 3 section 10.2).
 *
 * Identifies the short file identifier of a record-oriented EF and the
 * inclusive record range read from it.
 */
typedef struct {
    /** Short file identifier, 1-30; 0 and 31 are reserved. */
    uint8_t sfi;
    /** First record of the inclusive range; nonzero. */
    uint8_t first_record;
    /** Last record of the inclusive range; not below `first_record`. */
    uint8_t last_record;
    /**
     * Leading subset of the range (starting at `first_record`) used for
     * offline data authentication; never exceeds
     * `last_record - first_record + 1`.
     */
    uint8_t offline_auth_record_count;
} tlv_emv_afl_entry_t;

/**
 * @brief Maximum number of AFL entries: 252 / 4.
 *
 * The largest AFL value permitted by the Book 3 dictionary (afl, tag 94)
 * divided by the fixed four-byte entry size.
 */
enum { TLV_EMV_AFL_MAX_ENTRIES = 63 };

/** @brief Decoded Application File Locator. */
typedef struct {
    /** Entries in wire order; only the first `count` are populated. */
    tlv_emv_afl_entry_t entries[TLV_EMV_AFL_MAX_ENTRIES];
    /** Number of entries populated in `entries`. */
    size_t count;
} tlv_emv_afl_t;

/**
 * @brief CVM Results (Book 3 Annex C6), preserved raw.
 *
 * Holds the last-applied CVM's method, applied condition and outcome bytes.
 * Book 3 Annex A Tables 39 and 40 enumerate the method and condition code
 * points; Table 41 defines the result values (see #TLV_EMV_CVM_RESULT_UNKNOWN,
 * #TLV_EMV_CVM_RESULT_FAILED and #TLV_EMV_CVM_RESULT_SUCCESSFUL). The codec
 * stores the three bytes without further validation, like FLAGS.
 */
typedef struct {
    /** CVM method code. */
    uint8_t method;
    /** CVM condition code. */
    uint8_t condition;
    /** CVM outcome: 00 unknown, 01 failed, 02 successful. */
    uint8_t result;
} tlv_emv_cvm_result_t;

/** @brief Maximum number of PAN digits in Track 2 Equivalent Data, and of discretionary digits. */
enum { TLV_EMV_TRACK2_PAN_MAX_DIGITS = 19, TLV_EMV_TRACK2_DISCRETIONARY_MAX_DIGITS = 30 };

/**
 * @brief Decoded Track 2 Equivalent Data (Book 3 Annex III, ISO 7813).
 *
 * Parsed from the field-separator (hex D) delimited BCD digit string and its
 * optional trailing hex-F pad nibble.
 */
typedef struct {
    /** Primary account number: 1-19 decimal digits, NUL-terminated. */
    char pan[TLV_EMV_TRACK2_PAN_MAX_DIGITS + 1];
    /** Expiration year, YY, 0-99. */
    uint8_t expiration_year;
    /** Expiration month, MM, 1-12; there is no expiration day. */
    uint8_t expiration_month;
    /** Three-digit service code, 0-999. */
    uint16_t service_code;
    /** Discretionary data: decimal digits, NUL-terminated; may be empty. */
    char discretionary_data[TLV_EMV_TRACK2_DISCRETIONARY_MAX_DIGITS + 1];
} tlv_emv_track2_t;

/**
 * @brief Codec for amounts (format n12): six bytes of BCD to and from `uint64_t`.
 *
 * Use with tlv_codec_decode() and tlv_codec_encode(). Currency amounts are
 * unscaled minor units. The general semantic-codec rules in the file
 * documentation apply.
 */
extern TLV_API const tlv_codec_t tlv_emv_codec_amount;

/**
 * @brief Describes a value kind's C representation and wire meaning.
 *
 * Intended for diagnostics or tooling, for example `"Bit flags"` for
 * #TLV_EMV_VALUE_FLAGS.
 *
 * @param kind Value kind to describe.
 *
 * @return A static, NUL-terminated description, never `NULL`. Every declared
 *         kind has one; any other value returns `"Unspecified representation"`.
 */
TLV_API const char* tlv_emv_value_kind_description(tlv_emv_value_kind_t kind);

#ifdef __cplusplus
}
#endif
#endif
