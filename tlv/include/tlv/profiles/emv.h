#ifndef OPENTLV_PROFILES_EMV_H
#define OPENTLV_PROFILES_EMV_H

#include "tlv/schemas/schema.h"
#include "tlv/codec/emv.h"
#include "tlv/export.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup profiles
 * @brief EMV Contact Book 3 data dictionary: tag constants, schemas and lookup.
 *
 * Scope: EMV Contact Book 3 v4.4, October 2022, Annex A and the nested
 * biometric tags in Annex C. No Contactless kernels, proprietary
 * dictionaries, or subsequent specification bulletins. Untagged data
 * elements are not tags.
 *
 * Use #tlv_reader_format_ber with generic I/O; this profile does not parse
 * TLV. Tag constants that exceed #TLV_TAG_CAPACITY are omitted from all
 * tables.
 */

/** @addtogroup profiles
 * @{
 */

/**
 * @brief Specification the EMV dictionary is drawn from.
 *
 * See the file documentation for the covered scope.
 */
#define TLV_EMV_SPECIFICATION "EMV Contact Book 3 v4.4 (October 2022)"

/**
 * @brief Dictionary context a tag is interpreted under.
 *
 * Contexts are explicit and never fall back to the base dictionary.
 */
typedef enum {
    /** Ordinary application data. */
    TLV_EMV_CONTEXT_BASE = 0,
    /** Inside 7F60. */
    TLV_EMV_CONTEXT_BIT,
    /** Inside A1 within 7F60. */
    TLV_EMV_CONTEXT_BHT,
    /** Inside level-2 A1/A2 within BHT. */
    TLV_EMV_CONTEXT_BHT_FORMAT,
    /** Inside BF4A/BF4B, or terminal group. */
    TLV_EMV_CONTEXT_BIT_GROUP,
    /** Inside BF4C. */
    TLV_EMV_CONTEXT_BIOMETRIC_COUNTERS,
    /** Inside BF4D. */
    TLV_EMV_CONTEXT_BIOMETRIC_ATTEMPTS,
    /** Inside BF4E. */
    TLV_EMV_CONTEXT_BIOMETRIC_VERIFICATION,
    /** Number of contexts; also the "no new context" result of tlv_emv_child_context(). */
    TLV_EMV_CONTEXT_COUNT
} tlv_emv_context_t;

/**
 * @brief Determines the context a tag's children should be interpreted under.
 *
 * Given the context that `tag` itself was found in, returns the context for
 * its children. For example, the Biometric Information Template switches its
 * children from #TLV_EMV_CONTEXT_BASE to #TLV_EMV_CONTEXT_BIT.
 *
 * @param context The context `tag` was found in.
 * @param tag     The tag whose children are being interpreted; may be `NULL`.
 *
 * @return The children's context, or #TLV_EMV_CONTEXT_COUNT when `tag` does
 *         not introduce a new context for its children (or is `NULL`). In the
 *         former case callers keep traversing in `context` when `tag` is
 *         otherwise a known template; tlv_emv_find() with `context` and `tag`
 *         resolves it.
 */
TLV_API tlv_emv_context_t tlv_emv_child_context(tlv_emv_context_t context, const tlv_tag_t* tag);

/**
 * @name AIP masks
 * @brief Masks for the `uint64_t` FLAGS representation of the Application
 *        Interchange Profile (Annex C1).
 * @{
 */
#define TLV_EMV_AIP_XDA_SUPPORTED UINT64_C(0x8000)
#define TLV_EMV_AIP_SDA_SUPPORTED UINT64_C(0x4000)
#define TLV_EMV_AIP_DDA_SUPPORTED UINT64_C(0x2000)
#define TLV_EMV_AIP_CARDHOLDER_VERIFICATION_SUPPORTED UINT64_C(0x1000)
#define TLV_EMV_AIP_TERMINAL_RISK_MANAGEMENT_REQUIRED UINT64_C(0x0800)
#define TLV_EMV_AIP_ISSUER_AUTHENTICATION_SUPPORTED UINT64_C(0x0400)
#define TLV_EMV_AIP_CDA_SUPPORTED UINT64_C(0x0100)
/** @} */

/**
 * @name TVR masks
 * @brief Masks for the `uint64_t` FLAGS representation of the Terminal
 *        Verification Results (Annex C5).
 *
 * Tag 95, five bytes, byte one in the most significant position.
 * Undocumented bits are RFU.
 * @{
 */
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
/** @} */

/**
 * @name TSI masks
 * @brief Masks for the `uint64_t` FLAGS representation of the Transaction
 *        Status Information (Annex C6).
 *
 * Tag 9B, two bytes; byte two is entirely RFU.
 * @{
 */
#define TLV_EMV_TSI_OFFLINE_DATA_AUTHENTICATION_PERFORMED (UINT64_C(0x80) << 8)
#define TLV_EMV_TSI_CARDHOLDER_VERIFICATION_PERFORMED (UINT64_C(0x40) << 8)
#define TLV_EMV_TSI_CARD_RISK_MANAGEMENT_PERFORMED (UINT64_C(0x20) << 8)
#define TLV_EMV_TSI_ISSUER_AUTHENTICATION_PERFORMED (UINT64_C(0x10) << 8)
#define TLV_EMV_TSI_TERMINAL_RISK_MANAGEMENT_PERFORMED (UINT64_C(0x08) << 8)
#define TLV_EMV_TSI_SCRIPT_PROCESSING_PERFORMED (UINT64_C(0x04) << 8)
/** @} */

/**
 * @name Terminal Capabilities masks
 * @brief Masks for the `uint64_t` FLAGS representation of the Terminal
 *        Capabilities.
 *
 * Tag 9F33, three bytes (card data input, CVM, and security capability).
 * @{
 */
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
/** @} */

/**
 * @name Additional Terminal Capabilities masks
 * @brief Masks for the `uint64_t` FLAGS representation of the Additional
 *        Terminal Capabilities.
 *
 * Tag 9F40, five bytes (transaction type capability, terminal data input
 * capability, and terminal data output capability, including ISO/IEC 8859
 * code table support).
 * @{
 */
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
/** @} */

/**
 * @name CVM Results values
 * @brief Values of #tlv_emv_cvm_result_t::result (Annex A Table 41).
 * @{
 */
/** The CVM outcome is unknown. */
#define TLV_EMV_CVM_RESULT_UNKNOWN 0x00
/** The CVM failed. */
#define TLV_EMV_CVM_RESULT_FAILED 0x01
/** The CVM was successful. */
#define TLV_EMV_CVM_RESULT_SUCCESSFUL 0x02
/** @} */

/**
 * @name Numeric tag constants
 * @brief Integer constants generated from tlv/profiles/emv_tags.def.
 *
 * Each dictionary entry produces an enumerator `tlv_emv_tag_<name>_u64`, for
 * example `tlv_emv_tag_aip_u64`. These are integer constant expressions
 * usable in C and C++ case labels. Names retain the dictionary suffix.
 * Capacity filtering matches the raw tag objects. All current dictionary
 * values fit in an `int`.
 * @{
 */
#define EMV_BEGIN(scope)
#define EMV_TAG(scope, name, size, b1, b2, min, max, step, kind, arg)                              \
    enum { tlv_emv_tag_##name##_u64 = ((size) == 1 ? (b1) : ((b1) << 8) | (b2)) };
#define EMV_END(scope)
#include "tlv/profiles/emv_tags.def"
#undef EMV_BEGIN
#undef EMV_TAG
#undef EMV_END
/** @} */

/**
 * @name Tag objects
 * @brief Raw tag constants generated from tlv/profiles/emv_tags.def.
 *
 * Each dictionary entry produces a constant `tlv_emv_tag_<name>` of type
 * `const tlv_tag_t`, the same universal tag type used by generic I/O.
 * @{
 */
#define EMV_BEGIN(scope)
#define EMV_TAG(scope, name, size, b1, b2, min, max, step, kind, arg)                              \
    extern TLV_API const tlv_tag_t tlv_emv_tag_##name;
#define EMV_END(scope)
#include "tlv/profiles/emv_tags.def"
#undef EMV_BEGIN
#undef EMV_TAG
#undef EMV_END
/** @} */

/**
 * @brief One entry of the EMV data dictionary.
 *
 * Obtained from tlv_emv_find(). The definition points into immutable static
 * tables owned by the library.
 */
typedef struct {
    /** Tag and inclusive length bounds; borrowed from the static tables. */
    const tlv_schema_entry_t* schema;
    /** Stable symbolic name from `emv_tags.def`. */
    const char* name;
    /** C representation of the value. */
    tlv_emv_value_kind_t value_kind;
    /** Semantic codec for the value; `NULL` when no conversion is provided. */
    const tlv_codec_t* codec;
    /** Permitted lengths: `min + n * step`. */
    size_t length_step;
} tlv_emv_definition_t;

/** @brief The dictionary schema for #TLV_EMV_CONTEXT_BASE; an immutable static table. */
extern TLV_API const tlv_schema_t tlv_emv_schema;

/**
 * @brief Returns the dictionary schema for a context.
 *
 * The tables are immutable and static; no allocation occurs. Contexts are
 * explicit and never fall back to the base dictionary.
 *
 * @param context Dictionary context.
 *
 * @return The context's schema, or `NULL` for an invalid context.
 */
TLV_API const tlv_schema_t* tlv_emv_schema_for(tlv_emv_context_t context);

/**
 * @brief Looks up a tag's definition in a context.
 *
 * Contexts are explicit and never fall back to the base dictionary.
 *
 * @param context Dictionary context.
 * @param tag     Tag to look up.
 *
 * @return The definition, borrowed from the library's static tables, or
 *         `NULL` if the tag is unknown in `context` or an argument is invalid.
 */
TLV_API const tlv_emv_definition_t* tlv_emv_find(tlv_emv_context_t context, const tlv_tag_t* tag);

/**
 * @brief Validates a value length against a definition.
 *
 * Adds length-step checks (AFL, CVM lists, BIC, RSA exponents, and so on) to
 * the generic schema's inclusive bounds.
 *
 * @param definition Definition to validate against.
 * @param length     Value length in bytes.
 *
 * @return #TLV_OK if the length is permitted.
 * @return #TLV_ERR_NULL_ARG if `definition` is `NULL`.
 * @return #TLV_ERR_INVALID_LENGTH if the length is not permitted.
 *
 * @note This is not a transaction validator: key-dependent lengths,
 *       required and duplicate tags, template membership, and cryptographic
 *       or value semantics are separate checks.
 */
TLV_API tlv_result_t tlv_emv_validate_length(const tlv_emv_definition_t* definition, size_t length);

/**
 * @brief Returns a curated human-readable label for a dictionary symbol.
 *
 * For example, `"afl"` maps to `"Application File Locator (AFL)"`. Intended
 * for diagnostics or tooling. Coverage is limited to symbols whose
 * title-cased form would be misleading (abbreviations, initialisms).
 *
 * @param name Symbol from #tlv_emv_definition_t::name; may be `NULL`.
 *
 * @return A static label, or `NULL` if `name` has no curated label
 *         (including for a `NULL` `name`); tlv_emv_titlecase_name() derives
 *         a generic label from the symbol itself in that case.
 */
TLV_API const char* tlv_emv_display_label(const char* name);

/**
 * @brief Writes a generic human-readable label for a dictionary symbol.
 *
 * Replaces underscores with spaces and capitalizes the first letter of each
 * word (for example `"application_label"` becomes `"Application Label"`),
 * then NUL-terminates.
 *
 * @param[in]  name     Dictionary symbol.
 * @param[out] buffer   Destination for the label.
 * @param[in]  capacity Size of `buffer`; must be at least `strlen(name) + 1`.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG if `name` or `buffer` is `NULL`.
 * @return #TLV_ERR_BUFFER_TOO_SHORT if `capacity` is too small.
 *
 * @warning On #TLV_ERR_BUFFER_TOO_SHORT the contents of `buffer` are unspecified.
 */
TLV_API tlv_result_t tlv_emv_titlecase_name(const char* name, char* buffer, size_t capacity);

#ifdef __cplusplus
}
#endif
/** @} */

#endif /* OPENTLV_PROFILES_EMV_H */
