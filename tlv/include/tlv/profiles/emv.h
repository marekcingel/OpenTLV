#ifndef OPENTLV_PROFILES_EMV_H
#define OPENTLV_PROFILES_EMV_H

#include "tlv/format.h"
#include "tlv/schema.h"
#include "tlv/codec.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Scope: EMV Contact Book 3 v4.4, October 2022, Annex A and the nested
 * biometric tags in Annex C. No Contactless kernels, proprietary dictionaries,
 * or subsequent specification bulletins. Untagged data elements are not tags.
 * Use &tlv_format_ber with generic I/O; this profile does not parse TLV.
 * Tag constants that exceed TLV_TAG_MAX_SIZE are omitted from all tables.
 */
#define TLV_EMV_SPECIFICATION "EMV Contact Book 3 v4.4 (October 2022)"

typedef enum {
    TLV_EMV_CONTEXT_BASE = 0,          /* ordinary application data */
    TLV_EMV_CONTEXT_BIT,               /* inside 7F60 */
    TLV_EMV_CONTEXT_BHT,               /* inside A1 within 7F60 */
    TLV_EMV_CONTEXT_BHT_FORMAT,        /* inside level-2 A1/A2 within BHT */
    TLV_EMV_CONTEXT_BIT_GROUP,         /* inside BF4A/BF4B, or terminal group */
    TLV_EMV_CONTEXT_BIOMETRIC_COUNTERS, /* inside BF4C */
    TLV_EMV_CONTEXT_BIOMETRIC_ATTEMPTS, /* inside BF4D */
    TLV_EMV_CONTEXT_BIOMETRIC_VERIFICATION, /* inside BF4E */
    TLV_EMV_CONTEXT_COUNT
} tlv_emv_context_t;

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

/* AIP masks for the uint64_t FLAGS representation (Annex C1). */
#define TLV_EMV_AIP_XDA_SUPPORTED UINT64_C(0x8000)
#define TLV_EMV_AIP_SDA_SUPPORTED UINT64_C(0x4000)
#define TLV_EMV_AIP_DDA_SUPPORTED UINT64_C(0x2000)
#define TLV_EMV_AIP_CARDHOLDER_VERIFICATION_SUPPORTED UINT64_C(0x1000)
#define TLV_EMV_AIP_TERMINAL_RISK_MANAGEMENT_REQUIRED UINT64_C(0x0800)
#define TLV_EMV_AIP_ISSUER_AUTHENTICATION_SUPPORTED UINT64_C(0x0400)
#define TLV_EMV_AIP_CDA_SUPPORTED UINT64_C(0x0100)

/* Public constants are all the same universal tlv_tag_t as generic I/O. */
#define EMV_BEGIN(scope)
#define EMV_TAG(scope, name, size, b1, b2, min, max, step, kind, arg) \
    extern const tlv_tag_t tlv_emv_tag_##name;
#define EMV_END(scope)
#include "tlv/profiles/emv_tags.def"
#undef EMV_BEGIN
#undef EMV_TAG
#undef EMV_END

typedef struct {
    const tlv_schema_entry_t* schema;
    const char* name; /* stable symbolic name from emv_tags.def */
    tlv_emv_value_kind_t value_kind;
    const tlv_codec_t* codec; /* NULL when no conversion is provided */
    size_t length_step; /* permitted lengths: min + n * step */
} tlv_emv_definition_t;

extern const tlv_schema_t tlv_emv_schema; /* BASE context */
/* Immutable static tables; no allocation. Invalid contexts return NULL.
 * Contexts are explicit and never fall back to the base dictionary.
 */
const tlv_schema_t* tlv_emv_schema_for(tlv_emv_context_t context);
const tlv_emv_definition_t* tlv_emv_find(tlv_emv_context_t context,
                                       const tlv_tag_t* tag);
/* Adds length-step checks (AFL, CVM lists, BIC, RSA exponents, etc.) to the
 * generic schema's inclusive bounds. NULL -> TLV_ERR_NULL_ARG.
 * Not a transaction validator: key-dependent lengths, required/duplicate tags,
 * template membership and cryptographic/value semantics are separate checks.
 */
tlv_result_t tlv_emv_validate_length(const tlv_emv_definition_t* definition,
                                    size_t length);

/* Use definition->codec with tlv_codec_decode/encode. Semantic codecs enforce
 * the tag's length and value representation; errors use TLV_CODEC_ERR_*.
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
#endif /* OPENTLV_PROFILES_EMV_H */
