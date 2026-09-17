#ifndef OPENTLV_CODEC_EMV_H
#define OPENTLV_CODEC_EMV_H
#include "tlv/codec/codec.h"
#include "tlv/export.h"

#ifdef __cplusplus
extern "C" {
#endif

/* C representations for semantic codecs. BYTES/TEXT/TEMPLATE have no codec:
 * retain the reader's borrowed value; TEXT does not imply UTF-8 or a NUL.
 * FLAGS preserves every wire bit, including RFU bits, in a big-endian integer.
 */
typedef enum {
    TLV_EMV_VALUE_BYTES,
    TLV_EMV_VALUE_TEXT,
    TLV_EMV_VALUE_TEMPLATE,
    TLV_EMV_VALUE_NUMBER,      /* uint64_t: binary or decimal BCD */
    TLV_EMV_VALUE_FLAGS,       /* uint64_t */
    TLV_EMV_VALUE_DIGITS,      /* char[]: NUL-terminated decimal digits */
    TLV_EMV_VALUE_DATE,        /* tlv_emv_date_t */
    TLV_EMV_VALUE_TIME,        /* tlv_emv_time_t */
    TLV_EMV_VALUE_ACCOUNT,     /* tlv_emv_account_type_t */
    TLV_EMV_VALUE_CRYPTOGRAM,  /* tlv_emv_cryptogram_info_t */
    TLV_EMV_VALUE_BIOMETRIC,   /* tlv_emv_biometric_type_t */
    TLV_EMV_VALUE_NUMBER_LIST, /* tlv_emv_number_list_t */
    TLV_EMV_VALUE_AFL,         /* tlv_emv_afl_t */
    TLV_EMV_VALUE_CVM_RESULT,  /* tlv_emv_cvm_result_t */
    TLV_EMV_VALUE_TRACK2       /* tlv_emv_track2_t */
} tlv_emv_value_kind_t;

typedef struct {
    uint8_t year, month, day;
} tlv_emv_date_t;
typedef struct {
    uint8_t hour, minute, second;
} tlv_emv_time_t;
/* year is YY (0..99); no century is inferred. February 29 is accepted for
 * years divisible by four; the caller resolves century-dependent validity.
 */
typedef enum {
    TLV_EMV_ACCOUNT_DEFAULT = 0,
    TLV_EMV_ACCOUNT_SAVINGS = 10,
    TLV_EMV_ACCOUNT_CHEQUE_DEBIT = 20,
    TLV_EMV_ACCOUNT_CREDIT = 30
} tlv_emv_account_type_t;

typedef enum {
    TLV_EMV_CRYPTOGRAM_AAC = 0,
    TLV_EMV_CRYPTOGRAM_TC = 1,
    TLV_EMV_CRYPTOGRAM_ARQC = 2,
    TLV_EMV_CRYPTOGRAM_RFU = 3
} tlv_emv_cryptogram_type_t;
typedef struct {
    tlv_emv_cryptogram_type_t type; /* wire bits b8-b7 */
    uint8_t flags;                  /* remaining six bits, preserved without interpretation */
} tlv_emv_cryptogram_info_t;

typedef enum {
    TLV_EMV_BIOMETRIC_FACIAL = 0x02,
    TLV_EMV_BIOMETRIC_VOICE = 0x04,
    TLV_EMV_BIOMETRIC_FINGER = 0x08,
    TLV_EMV_BIOMETRIC_IRIS = 0x10,
    TLV_EMV_BIOMETRIC_PALM = 0x020000
} tlv_emv_biometric_type_t;
typedef struct {
    uint64_t values[4];
    size_t count;
} tlv_emv_number_list_t;

/* One Application File Locator entry (Book 3 section 10.2): the short file
 * identifier of a record-oriented EF and the inclusive record range read
 * from it. offline_auth_record_count is the leading subset of that range
 * (starting at first_record) used for offline data authentication; it never
 * exceeds last_record - first_record + 1. sfi is 1-30; 0 and 31 are reserved.
 */
typedef struct {
    uint8_t sfi;
    uint8_t first_record;
    uint8_t last_record;
    uint8_t offline_auth_record_count;
} tlv_emv_afl_entry_t;

/* TLV_EMV_AFL_MAX_ENTRIES is 252/4: the largest AFL value permitted by the
 * Book 3 dictionary (afl, tag 94) divided by the fixed four-byte entry size.
 */
enum { TLV_EMV_AFL_MAX_ENTRIES = 63 };
typedef struct {
    tlv_emv_afl_entry_t entries[TLV_EMV_AFL_MAX_ENTRIES];
    size_t count; /* number of entries populated in `entries` */
} tlv_emv_afl_t;

/* CVM Results (Book 3 Annex C6): the last-applied CVM's method, applied
 * condition, and outcome bytes, preserved raw. Book 3 Annex A Table 39/40
 * enumerate the method/condition code points; Annex A Table 41 defines
 * result: 00 unknown, 01 failed, 02 successful (see TLV_EMV_CVM_RESULT_*).
 */
typedef struct {
    uint8_t method;
    uint8_t condition;
    uint8_t result;
} tlv_emv_cvm_result_t;

/* Track 2 Equivalent Data (Book 3 Annex III/ISO 7813): PAN, expiration date
 * (YY/MM, no day), three-digit service code, and discretionary data, parsed
 * from the field-separator (hex D) delimited BCD digit string and its
 * optional trailing hex-F pad nibble. discretionary_data may be empty.
 */
enum { TLV_EMV_TRACK2_PAN_MAX_DIGITS = 19, TLV_EMV_TRACK2_DISCRETIONARY_MAX_DIGITS = 30 };
typedef struct {
    char pan[TLV_EMV_TRACK2_PAN_MAX_DIGITS + 1];
    uint8_t expiration_year;  /* YY, 0-99 */
    uint8_t expiration_month; /* MM, 1-12 */
    uint16_t service_code;    /* three decimal digits, 0-999 */
    char discretionary_data[TLV_EMV_TRACK2_DISCRETIONARY_MAX_DIGITS + 1];
} tlv_emv_track2_t;

/* Use tlv_codec_decode/encode with these codecs or profile codec descriptors.
 * Semantic codecs enforce the tag's length and value representation;
 * errors use TLV_CODEC_ERR_*.
 * Decode requires at least sizeof(the documented C type); encode requires
 * exactly that size. Unaligned storage is supported. Buffers must not overlap.
 * DIGITS is the exception: decode needs digit_count+1 bytes and writes a NUL;
 * encode takes the digit count (excluding NUL). CN padding F is removed and
 * leading zeroes preserved. Empty/all-padding PANs are invalid.
 * Variable-width numbers encode in the shortest permitted width. Size queries
 * validate identically to writes. Currency amounts are unscaled minor units.
 * Account/biometric codecs reject undefined enum values; cryptogram RFU is
 * represented explicitly. DATE/TIME check BCD and calendar/clock ranges.
 * AFL rejects an sfi outside 1-30, a first_record of 0, last_record below
 * first_record, and an offline_auth_record_count above the entry's record
 * range. TRACK2 rejects a missing/misplaced field separator, a PAN outside
 * 1-19 digits, a non-decimal expiry/service-code/discretionary digit, and an
 * expiration_month outside 1-12; encode rejects a discretionary_data or pan
 * string without a NUL within its documented array size. CVM_RESULT stores
 * its three bytes without further validation, like FLAGS.
 */
extern TLV_API const tlv_codec_t tlv_emv_codec_amount; /* n12, six bytes <-> uint64_t */

/* Short, human-readable description of a value kind's C representation and
 * wire meaning, for diagnostics or tooling, e.g. "Bit flags" for
 * TLV_EMV_VALUE_FLAGS. Every declared kind has a description; an otherwise
 * unrecognized value returns "Unspecified representation". Never NULL. */
TLV_API const char* tlv_emv_value_kind_description(tlv_emv_value_kind_t kind);

#ifdef __cplusplus
}
#endif
#endif
