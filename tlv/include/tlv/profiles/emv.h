#ifndef OPENTLV_PROFILES_EMV_H
#define OPENTLV_PROFILES_EMV_H

#include "tlv/schemas/schema.h"
#include "tlv/codec/emv.h"
#include "tlv/export.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Scope: EMV Contact Book 3 v4.4, October 2022, Annex A and the nested
 * biometric tags in Annex C. No Contactless kernels, proprietary dictionaries,
 * or subsequent specification bulletins. Untagged data elements are not tags.
 * Use &tlv_reader_format_ber with generic I/O; this profile does not parse TLV.
 * Tag constants that exceed TLV_TAG_CAPACITY are omitted from all tables.
 */
#define TLV_EMV_SPECIFICATION "EMV Contact Book 3 v4.4 (October 2022)"

typedef enum {
    TLV_EMV_CONTEXT_BASE = 0,               /* ordinary application data */
    TLV_EMV_CONTEXT_BIT,                    /* inside 7F60 */
    TLV_EMV_CONTEXT_BHT,                    /* inside A1 within 7F60 */
    TLV_EMV_CONTEXT_BHT_FORMAT,             /* inside level-2 A1/A2 within BHT */
    TLV_EMV_CONTEXT_BIT_GROUP,              /* inside BF4A/BF4B, or terminal group */
    TLV_EMV_CONTEXT_BIOMETRIC_COUNTERS,     /* inside BF4C */
    TLV_EMV_CONTEXT_BIOMETRIC_ATTEMPTS,     /* inside BF4D */
    TLV_EMV_CONTEXT_BIOMETRIC_VERIFICATION, /* inside BF4E */
    TLV_EMV_CONTEXT_COUNT
} tlv_emv_context_t;

/* AIP masks for the uint64_t FLAGS representation (Annex C1). */
#define TLV_EMV_AIP_XDA_SUPPORTED UINT64_C(0x8000)
#define TLV_EMV_AIP_SDA_SUPPORTED UINT64_C(0x4000)
#define TLV_EMV_AIP_DDA_SUPPORTED UINT64_C(0x2000)
#define TLV_EMV_AIP_CARDHOLDER_VERIFICATION_SUPPORTED UINT64_C(0x1000)
#define TLV_EMV_AIP_TERMINAL_RISK_MANAGEMENT_REQUIRED UINT64_C(0x0800)
#define TLV_EMV_AIP_ISSUER_AUTHENTICATION_SUPPORTED UINT64_C(0x0400)
#define TLV_EMV_AIP_CDA_SUPPORTED UINT64_C(0x0100)

/* TVR masks for the uint64_t FLAGS representation (Annex C5): tag 95, five
 * bytes, byte one in the most significant position. Undocumented bits are RFU. */
#define TLV_EMV_TVR_OFFLINE_DATA_AUTHENTICATION_NOT_PERFORMED (UINT64_C(0x80) << 32)
#define TLV_EMV_TVR_SDA_FAILED (UINT64_C(0x40) << 32)
#define TLV_EMV_TVR_ICC_DATA_MISSING (UINT64_C(0x20) << 32)
#define TLV_EMV_TVR_CARD_ON_EXCEPTION_FILE (UINT64_C(0x10) << 32)
#define TLV_EMV_TVR_DDA_FAILED (UINT64_C(0x08) << 32)
#define TLV_EMV_TVR_CDA_FAILED (UINT64_C(0x04) << 32)
#define TLV_EMV_TVR_ICC_TERMINAL_DIFFERENT_APPLICATION_VERSIONS (UINT64_C(0x80) << 24)
#define TLV_EMV_TVR_EXPIRED_APPLICATION (UINT64_C(0x40) << 24)
#define TLV_EMV_TVR_APPLICATION_NOT_YET_EFFECTIVE (UINT64_C(0x20) << 24)
#define TLV_EMV_TVR_SERVICE_NOT_ALLOWED (UINT64_C(0x10) << 24)
#define TLV_EMV_TVR_NEW_CARD (UINT64_C(0x08) << 24)
#define TLV_EMV_TVR_CARDHOLDER_VERIFICATION_NOT_SUCCESSFUL (UINT64_C(0x80) << 16)
#define TLV_EMV_TVR_UNRECOGNISED_CVM (UINT64_C(0x40) << 16)
#define TLV_EMV_TVR_PIN_TRY_LIMIT_EXCEEDED (UINT64_C(0x20) << 16)
#define TLV_EMV_TVR_PIN_PAD_NOT_PRESENT_OR_NOT_WORKING (UINT64_C(0x10) << 16)
#define TLV_EMV_TVR_PIN_ENTRY_REQUIRED_BUT_NOT_ENTERED (UINT64_C(0x08) << 16)
#define TLV_EMV_TVR_ONLINE_PIN_ENTERED (UINT64_C(0x04) << 16)
#define TLV_EMV_TVR_TRANSACTION_EXCEEDS_FLOOR_LIMIT (UINT64_C(0x80) << 8)
#define TLV_EMV_TVR_LOWER_CONSECUTIVE_OFFLINE_LIMIT_EXCEEDED (UINT64_C(0x40) << 8)
#define TLV_EMV_TVR_UPPER_CONSECUTIVE_OFFLINE_LIMIT_EXCEEDED (UINT64_C(0x20) << 8)
#define TLV_EMV_TVR_SELECTED_RANDOMLY_FOR_ONLINE_PROCESSING (UINT64_C(0x10) << 8)
#define TLV_EMV_TVR_MERCHANT_FORCED_TRANSACTION_ONLINE (UINT64_C(0x08) << 8)
#define TLV_EMV_TVR_DEFAULT_TDOL_USED UINT64_C(0x80)
#define TLV_EMV_TVR_ISSUER_AUTHENTICATION_FAILED UINT64_C(0x40)
#define TLV_EMV_TVR_SCRIPT_PROCESSING_FAILED_BEFORE_FINAL_GENERATE_AC UINT64_C(0x20)
#define TLV_EMV_TVR_SCRIPT_PROCESSING_FAILED_AFTER_FINAL_GENERATE_AC UINT64_C(0x10)

/* TSI masks for the uint64_t FLAGS representation (Annex C6): tag 9B, two
 * bytes; byte two is entirely RFU. */
#define TLV_EMV_TSI_OFFLINE_DATA_AUTHENTICATION_PERFORMED (UINT64_C(0x80) << 8)
#define TLV_EMV_TSI_CARDHOLDER_VERIFICATION_PERFORMED (UINT64_C(0x40) << 8)
#define TLV_EMV_TSI_CARD_RISK_MANAGEMENT_PERFORMED (UINT64_C(0x20) << 8)
#define TLV_EMV_TSI_ISSUER_AUTHENTICATION_PERFORMED (UINT64_C(0x10) << 8)
#define TLV_EMV_TSI_TERMINAL_RISK_MANAGEMENT_PERFORMED (UINT64_C(0x08) << 8)
#define TLV_EMV_TSI_SCRIPT_PROCESSING_PERFORMED (UINT64_C(0x04) << 8)

/* Terminal Capabilities masks for the uint64_t FLAGS representation: tag
 * 9F33, three bytes (card data input, CVM, and security capability). */
#define TLV_EMV_TERMINAL_CAPABILITIES_MANUAL_KEY_ENTRY (UINT64_C(0x80) << 16)
#define TLV_EMV_TERMINAL_CAPABILITIES_MAGNETIC_STRIPE (UINT64_C(0x40) << 16)
#define TLV_EMV_TERMINAL_CAPABILITIES_IC_WITH_CONTACTS (UINT64_C(0x20) << 16)
#define TLV_EMV_TERMINAL_CAPABILITIES_PLAINTEXT_PIN_FOR_ICC (UINT64_C(0x80) << 8)
#define TLV_EMV_TERMINAL_CAPABILITIES_ENCIPHERED_PIN_FOR_ONLINE (UINT64_C(0x40) << 8)
#define TLV_EMV_TERMINAL_CAPABILITIES_SIGNATURE_PAPER (UINT64_C(0x20) << 8)
#define TLV_EMV_TERMINAL_CAPABILITIES_ENCIPHERED_PIN_FOR_OFFLINE (UINT64_C(0x10) << 8)
#define TLV_EMV_TERMINAL_CAPABILITIES_NO_CVM_REQUIRED (UINT64_C(0x08) << 8)
#define TLV_EMV_TERMINAL_CAPABILITIES_SDA UINT64_C(0x80)
#define TLV_EMV_TERMINAL_CAPABILITIES_DDA UINT64_C(0x40)
#define TLV_EMV_TERMINAL_CAPABILITIES_CARD_CAPTURE UINT64_C(0x20)
#define TLV_EMV_TERMINAL_CAPABILITIES_CDA UINT64_C(0x08)

/* Additional Terminal Capabilities masks for the uint64_t FLAGS
 * representation: tag 9F40, five bytes (transaction type capability,
 * terminal data input capability, and terminal data output capability,
 * including ISO/IEC 8859 code table support). */
#define TLV_EMV_ADDITIONAL_TERMINAL_CAPABILITIES_CASH (UINT64_C(0x80) << 32)
#define TLV_EMV_ADDITIONAL_TERMINAL_CAPABILITIES_GOODS (UINT64_C(0x40) << 32)
#define TLV_EMV_ADDITIONAL_TERMINAL_CAPABILITIES_SERVICES (UINT64_C(0x20) << 32)
#define TLV_EMV_ADDITIONAL_TERMINAL_CAPABILITIES_CASHBACK (UINT64_C(0x10) << 32)
#define TLV_EMV_ADDITIONAL_TERMINAL_CAPABILITIES_INQUIRY (UINT64_C(0x08) << 32)
#define TLV_EMV_ADDITIONAL_TERMINAL_CAPABILITIES_TRANSFER (UINT64_C(0x04) << 32)
#define TLV_EMV_ADDITIONAL_TERMINAL_CAPABILITIES_PAYMENT (UINT64_C(0x02) << 32)
#define TLV_EMV_ADDITIONAL_TERMINAL_CAPABILITIES_ADMINISTRATIVE (UINT64_C(0x01) << 32)
#define TLV_EMV_ADDITIONAL_TERMINAL_CAPABILITIES_CASH_DEPOSIT (UINT64_C(0x80) << 24)
#define TLV_EMV_ADDITIONAL_TERMINAL_CAPABILITIES_NUMERIC_KEYS (UINT64_C(0x80) << 16)
#define TLV_EMV_ADDITIONAL_TERMINAL_CAPABILITIES_ALPHABETIC_AND_SPECIAL_CHARACTER_KEYS             \
    (UINT64_C(0x40) << 16)
#define TLV_EMV_ADDITIONAL_TERMINAL_CAPABILITIES_COMMAND_KEYS (UINT64_C(0x20) << 16)
#define TLV_EMV_ADDITIONAL_TERMINAL_CAPABILITIES_FUNCTION_KEYS (UINT64_C(0x10) << 16)
#define TLV_EMV_ADDITIONAL_TERMINAL_CAPABILITIES_PRINT_ATTENDANT (UINT64_C(0x80) << 8)
#define TLV_EMV_ADDITIONAL_TERMINAL_CAPABILITIES_PRINT_CARDHOLDER (UINT64_C(0x40) << 8)
#define TLV_EMV_ADDITIONAL_TERMINAL_CAPABILITIES_DISPLAY_ATTENDANT (UINT64_C(0x20) << 8)
#define TLV_EMV_ADDITIONAL_TERMINAL_CAPABILITIES_DISPLAY_CARDHOLDER (UINT64_C(0x10) << 8)
#define TLV_EMV_ADDITIONAL_TERMINAL_CAPABILITIES_CODE_TABLE_10 (UINT64_C(0x02) << 8)
#define TLV_EMV_ADDITIONAL_TERMINAL_CAPABILITIES_CODE_TABLE_9 (UINT64_C(0x01) << 8)
#define TLV_EMV_ADDITIONAL_TERMINAL_CAPABILITIES_CODE_TABLE_8 UINT64_C(0x80)
#define TLV_EMV_ADDITIONAL_TERMINAL_CAPABILITIES_CODE_TABLE_7 UINT64_C(0x40)
#define TLV_EMV_ADDITIONAL_TERMINAL_CAPABILITIES_CODE_TABLE_6 UINT64_C(0x20)
#define TLV_EMV_ADDITIONAL_TERMINAL_CAPABILITIES_CODE_TABLE_5 UINT64_C(0x10)
#define TLV_EMV_ADDITIONAL_TERMINAL_CAPABILITIES_CODE_TABLE_4 UINT64_C(0x08)
#define TLV_EMV_ADDITIONAL_TERMINAL_CAPABILITIES_CODE_TABLE_3 UINT64_C(0x04)
#define TLV_EMV_ADDITIONAL_TERMINAL_CAPABILITIES_CODE_TABLE_2 UINT64_C(0x02)
#define TLV_EMV_ADDITIONAL_TERMINAL_CAPABILITIES_CODE_TABLE_1 UINT64_C(0x01)

/* CVM Results (Annex A Table 41). */
#define TLV_EMV_CVM_RESULT_UNKNOWN 0x00
#define TLV_EMV_CVM_RESULT_FAILED 0x01
#define TLV_EMV_CVM_RESULT_SUCCESSFUL 0x02

/* Integer constant expressions usable in C and C++ case labels. Names retain
 * the dictionary suffix, e.g. tlv_emv_tag_aip_u64. Capacity filtering matches
 * the raw tag objects. All current dictionary values fit in an int. */
#define EMV_BEGIN(scope)
#define EMV_TAG(scope, name, size, b1, b2, min, max, step, kind, arg)                              \
    enum { tlv_emv_tag_##name##_u64 = ((size) == 1 ? (b1) : ((b1) << 8) | (b2)) };
#define EMV_END(scope)
#include "tlv/profiles/emv_tags.def"
#undef EMV_BEGIN
#undef EMV_TAG
#undef EMV_END

/* Public constants are all the same universal tlv_tag_t as generic I/O. */
#define EMV_BEGIN(scope)
#define EMV_TAG(scope, name, size, b1, b2, min, max, step, kind, arg)                              \
    extern TLV_API const tlv_tag_t tlv_emv_tag_##name;
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
    size_t length_step;       /* permitted lengths: min + n * step */
} tlv_emv_definition_t;

extern TLV_API const tlv_schema_t tlv_emv_schema; /* BASE context */
/* Immutable static tables; no allocation. Invalid contexts return NULL.
 * Contexts are explicit and never fall back to the base dictionary.
 */
TLV_API const tlv_schema_t* tlv_emv_schema_for(tlv_emv_context_t context);
TLV_API const tlv_emv_definition_t* tlv_emv_find(tlv_emv_context_t context, const tlv_tag_t* tag);
/* Adds length-step checks (AFL, CVM lists, BIC, RSA exponents, etc.) to the
 * generic schema's inclusive bounds. NULL -> TLV_ERR_NULL_ARG.
 * Not a transaction validator: key-dependent lengths, required/duplicate tags,
 * template membership and cryptographic/value semantics are separate checks.
 */
TLV_API tlv_result_t tlv_emv_validate_length(const tlv_emv_definition_t* definition, size_t length);

/* Curated human-readable label for a dictionary symbol (tlv_emv_definition_t
 * ::name), e.g. "afl" -> "Application File Locator (AFL)", intended for
 * diagnostics or tooling. Returns NULL if `name` has no curated label,
 * including for a NULL `name`; tlv_emv_titlecase_name derives a generic
 * label from the symbol itself in that case. Coverage is limited to symbols
 * whose title-cased form would be misleading (abbreviations, initialisms). */
TLV_API const char* tlv_emv_display_label(const char* name);
/* Writes a generic human-readable label into `buffer`: `name` with
 * underscores replaced by spaces and the first letter of each word
 * capitalized (e.g. "application_label" -> "Application Label"),
 * NUL-terminated. `capacity` must be at least strlen(name) + 1, else
 * TLV_ERR_BUFFER_TOO_SHORT is returned and `buffer` is left unspecified.
 * `name`/`buffer` NULL -> TLV_ERR_NULL_ARG. */
TLV_API tlv_result_t tlv_emv_titlecase_name(const char* name, char* buffer, size_t capacity);

#ifdef __cplusplus
}
#endif
#endif /* OPENTLV_PROFILES_EMV_H */
