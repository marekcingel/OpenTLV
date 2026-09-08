#ifndef OPENTLV_CODEC_EMV_H
#define OPENTLV_CODEC_EMV_H
#include "tlv/codec/codec.h"

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
    TLV_EMV_VALUE_NUMBER_LIST /* tlv_emv_number_list_t */
} tlv_emv_value_kind_t;

typedef struct { uint8_t year, month, day; } tlv_emv_date_t;
typedef struct { uint8_t hour, minute, second; } tlv_emv_time_t;
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
    uint8_t flags; /* remaining six bits, preserved without interpretation */
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
 */
extern const tlv_codec_t tlv_emv_codec_amount; /* n12, six bytes <-> uint64_t */

#ifdef __cplusplus
}
#endif
#endif
