// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_BUILTINS_EMV_H
#define OPENTLV_BUILTINS_EMV_H
#include "tlv/definition.h"

#include "tlv/error.h"
#include "tlv/builtins/emv/format.h"
#include "tlv/schema/schema.h"
#include "tlv/builtins/emv/emv_codec.h"
#include "tlv/export.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup builtins
 * @brief EMV Contact Book 3 data dictionary: tag constants, schemas and lookup.
 *
 * Scope: EMV Contact Book 3 v4.4, October 2022, Annex A and the nested
 * biometric tags in Annex C. No Contactless kernels, proprietary
 * dictionaries, or subsequent specification bulletins. Untagged data
 * elements are not tags.
 *
 * Use #tlv_format_emv with generic I/O for definite EMV framing.
 * Every tag constant borrows constant static bytes and is always
 * available.
 */

/** @addtogroup builtins
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

/** @name Numeric tag constants
 * Integer constant expressions usable in C/C++ switch labels.
 * @{
 */
enum {
    /** iin in BASE: identifier octets as an integer. */
    tlv_emv_tag_iin_u64 = 0x42,
    /** adf_name in BASE: identifier octets as an integer. */
    tlv_emv_tag_adf_name_u64 = 0x4F,
    /** application_label in BASE: identifier octets as an integer. */
    tlv_emv_tag_application_label_u64 = 0x50,
    /** track2_equivalent_data in BASE: identifier octets as an integer. */
    tlv_emv_tag_track2_equivalent_data_u64 = 0x57,
    /** pan in BASE: identifier octets as an integer. */
    tlv_emv_tag_pan_u64 = 0x5A,
    /** application_template in BASE: identifier octets as an integer. */
    tlv_emv_tag_application_template_u64 = 0x61,
    /** fci_template in BASE: identifier octets as an integer. */
    tlv_emv_tag_fci_template_u64 = 0x6F,
    /** read_record_template in BASE: identifier octets as an integer. */
    tlv_emv_tag_read_record_template_u64 = 0x70,
    /** issuer_script_template1 in BASE: identifier octets as an integer. */
    tlv_emv_tag_issuer_script_template1_u64 = 0x71,
    /** issuer_script_template2 in BASE: identifier octets as an integer. */
    tlv_emv_tag_issuer_script_template2_u64 = 0x72,
    /** directory_discretionary_template in BASE: identifier octets as an integer. */
    tlv_emv_tag_directory_discretionary_template_u64 = 0x73,
    /** response_template2 in BASE: identifier octets as an integer. */
    tlv_emv_tag_response_template2_u64 = 0x77,
    /** response_template1 in BASE: identifier octets as an integer. */
    tlv_emv_tag_response_template1_u64 = 0x80,
    /** amount_authorised_binary in BASE: identifier octets as an integer. */
    tlv_emv_tag_amount_authorised_binary_u64 = 0x81,
    /** aip in BASE: identifier octets as an integer. */
    tlv_emv_tag_aip_u64 = 0x82,
    /** command_template in BASE: identifier octets as an integer. */
    tlv_emv_tag_command_template_u64 = 0x83,
    /** df_name in BASE: identifier octets as an integer. */
    tlv_emv_tag_df_name_u64 = 0x84,
    /** issuer_script_command in BASE: identifier octets as an integer. */
    tlv_emv_tag_issuer_script_command_u64 = 0x86,
    /** application_priority_indicator in BASE: identifier octets as an integer. */
    tlv_emv_tag_application_priority_indicator_u64 = 0x87,
    /** sfi in BASE: identifier octets as an integer. */
    tlv_emv_tag_sfi_u64 = 0x88,
    /** authorisation_code in BASE: identifier octets as an integer. */
    tlv_emv_tag_authorisation_code_u64 = 0x89,
    /** authorisation_response_code in BASE: identifier octets as an integer. */
    tlv_emv_tag_authorisation_response_code_u64 = 0x8A,
    /** cdol1 in BASE: identifier octets as an integer. */
    tlv_emv_tag_cdol1_u64 = 0x8C,
    /** cdol2 in BASE: identifier octets as an integer. */
    tlv_emv_tag_cdol2_u64 = 0x8D,
    /** cvm_list in BASE: identifier octets as an integer. */
    tlv_emv_tag_cvm_list_u64 = 0x8E,
    /** ca_public_key_index in BASE: identifier octets as an integer. */
    tlv_emv_tag_ca_public_key_index_u64 = 0x8F,
    /** issuer_public_key_certificate in BASE: identifier octets as an integer. */
    tlv_emv_tag_issuer_public_key_certificate_u64 = 0x90,
    /** issuer_authentication_data in BASE: identifier octets as an integer. */
    tlv_emv_tag_issuer_authentication_data_u64 = 0x91,
    /** issuer_public_key_remainder in BASE: identifier octets as an integer. */
    tlv_emv_tag_issuer_public_key_remainder_u64 = 0x92,
    /** signed_static_application_data in BASE: identifier octets as an integer. */
    tlv_emv_tag_signed_static_application_data_u64 = 0x93,
    /** afl in BASE: identifier octets as an integer. */
    tlv_emv_tag_afl_u64 = 0x94,
    /** tvr in BASE: identifier octets as an integer. */
    tlv_emv_tag_tvr_u64 = 0x95,
    /** tdol in BASE: identifier octets as an integer. */
    tlv_emv_tag_tdol_u64 = 0x97,
    /** tc_hash_value in BASE: identifier octets as an integer. */
    tlv_emv_tag_tc_hash_value_u64 = 0x98,
    /** transaction_pin_data in BASE: identifier octets as an integer. */
    tlv_emv_tag_transaction_pin_data_u64 = 0x99,
    /** transaction_date in BASE: identifier octets as an integer. */
    tlv_emv_tag_transaction_date_u64 = 0x9A,
    /** tsi in BASE: identifier octets as an integer. */
    tlv_emv_tag_tsi_u64 = 0x9B,
    /** transaction_type in BASE: identifier octets as an integer. */
    tlv_emv_tag_transaction_type_u64 = 0x9C,
    /** ddf_name in BASE: identifier octets as an integer. */
    tlv_emv_tag_ddf_name_u64 = 0x9D,
    /** fci_proprietary_template in BASE: identifier octets as an integer. */
    tlv_emv_tag_fci_proprietary_template_u64 = 0xA5,
    /** cardholder_name in BASE: identifier octets as an integer. */
    tlv_emv_tag_cardholder_name_u64 = 0x5F20,
    /** application_expiration_date in BASE: identifier octets as an integer. */
    tlv_emv_tag_application_expiration_date_u64 = 0x5F24,
    /** application_effective_date in BASE: identifier octets as an integer. */
    tlv_emv_tag_application_effective_date_u64 = 0x5F25,
    /** issuer_country_code in BASE: identifier octets as an integer. */
    tlv_emv_tag_issuer_country_code_u64 = 0x5F28,
    /** transaction_currency_code in BASE: identifier octets as an integer. */
    tlv_emv_tag_transaction_currency_code_u64 = 0x5F2A,
    /** language_preference in BASE: identifier octets as an integer. */
    tlv_emv_tag_language_preference_u64 = 0x5F2D,
    /** service_code in BASE: identifier octets as an integer. */
    tlv_emv_tag_service_code_u64 = 0x5F30,
    /** pan_sequence_number in BASE: identifier octets as an integer. */
    tlv_emv_tag_pan_sequence_number_u64 = 0x5F34,
    /** transaction_currency_exponent in BASE: identifier octets as an integer. */
    tlv_emv_tag_transaction_currency_exponent_u64 = 0x5F36,
    /** issuer_url in BASE: identifier octets as an integer. */
    tlv_emv_tag_issuer_url_u64 = 0x5F50,
    /** iban in BASE: identifier octets as an integer. */
    tlv_emv_tag_iban_u64 = 0x5F53,
    /** bic in BASE: identifier octets as an integer. */
    tlv_emv_tag_bic_u64 = 0x5F54,
    /** issuer_country_alpha2 in BASE: identifier octets as an integer. */
    tlv_emv_tag_issuer_country_alpha2_u64 = 0x5F55,
    /** issuer_country_alpha3 in BASE: identifier octets as an integer. */
    tlv_emv_tag_issuer_country_alpha3_u64 = 0x5F56,
    /** account_type in BASE: identifier octets as an integer. */
    tlv_emv_tag_account_type_u64 = 0x5F57,
    /** biometric_information_template in BASE: identifier octets as an integer. */
    tlv_emv_tag_biometric_information_template_u64 = 0x7F60,
    /** acquirer_identifier in BASE: identifier octets as an integer. */
    tlv_emv_tag_acquirer_identifier_u64 = 0x9F01,
    /** amount_authorised in BASE: identifier octets as an integer. */
    tlv_emv_tag_amount_authorised_u64 = 0x9F02,
    /** amount_other in BASE: identifier octets as an integer. */
    tlv_emv_tag_amount_other_u64 = 0x9F03,
    /** amount_other_binary in BASE: identifier octets as an integer. */
    tlv_emv_tag_amount_other_binary_u64 = 0x9F04,
    /** application_discretionary_data in BASE: identifier octets as an integer. */
    tlv_emv_tag_application_discretionary_data_u64 = 0x9F05,
    /** aid_terminal in BASE: identifier octets as an integer. */
    tlv_emv_tag_aid_terminal_u64 = 0x9F06,
    /** application_usage_control in BASE: identifier octets as an integer. */
    tlv_emv_tag_application_usage_control_u64 = 0x9F07,
    /** application_version_card in BASE: identifier octets as an integer. */
    tlv_emv_tag_application_version_card_u64 = 0x9F08,
    /** application_version_terminal in BASE: identifier octets as an integer. */
    tlv_emv_tag_application_version_terminal_u64 = 0x9F09,
    /** asrpd in BASE: identifier octets as an integer. */
    tlv_emv_tag_asrpd_u64 = 0x9F0A,
    /** cardholder_name_extended in BASE: identifier octets as an integer. */
    tlv_emv_tag_cardholder_name_extended_u64 = 0x9F0B,
    /** iin_extended in BASE: identifier octets as an integer. */
    tlv_emv_tag_iin_extended_u64 = 0x9F0C,
    /** issuer_action_code_default in BASE: identifier octets as an integer. */
    tlv_emv_tag_issuer_action_code_default_u64 = 0x9F0D,
    /** issuer_action_code_denial in BASE: identifier octets as an integer. */
    tlv_emv_tag_issuer_action_code_denial_u64 = 0x9F0E,
    /** issuer_action_code_online in BASE: identifier octets as an integer. */
    tlv_emv_tag_issuer_action_code_online_u64 = 0x9F0F,
    /** issuer_application_data in BASE: identifier octets as an integer. */
    tlv_emv_tag_issuer_application_data_u64 = 0x9F10,
    /** issuer_code_table_index in BASE: identifier octets as an integer. */
    tlv_emv_tag_issuer_code_table_index_u64 = 0x9F11,
    /** application_preferred_name in BASE: identifier octets as an integer. */
    tlv_emv_tag_application_preferred_name_u64 = 0x9F12,
    /** last_online_atc in BASE: identifier octets as an integer. */
    tlv_emv_tag_last_online_atc_u64 = 0x9F13,
    /** lower_consecutive_offline_limit in BASE: identifier octets as an integer. */
    tlv_emv_tag_lower_consecutive_offline_limit_u64 = 0x9F14,
    /** merchant_category_code in BASE: identifier octets as an integer. */
    tlv_emv_tag_merchant_category_code_u64 = 0x9F15,
    /** merchant_identifier in BASE: identifier octets as an integer. */
    tlv_emv_tag_merchant_identifier_u64 = 0x9F16,
    /** pin_try_counter in BASE: identifier octets as an integer. */
    tlv_emv_tag_pin_try_counter_u64 = 0x9F17,
    /** issuer_script_identifier in BASE: identifier octets as an integer. */
    tlv_emv_tag_issuer_script_identifier_u64 = 0x9F18,
    /** token_requestor_id in BASE: identifier octets as an integer. */
    tlv_emv_tag_token_requestor_id_u64 = 0x9F19,
    /** terminal_country_code in BASE: identifier octets as an integer. */
    tlv_emv_tag_terminal_country_code_u64 = 0x9F1A,
    /** terminal_floor_limit in BASE: identifier octets as an integer. */
    tlv_emv_tag_terminal_floor_limit_u64 = 0x9F1B,
    /** terminal_identification in BASE: identifier octets as an integer. */
    tlv_emv_tag_terminal_identification_u64 = 0x9F1C,
    /** terminal_risk_management_data in BASE: identifier octets as an integer. */
    tlv_emv_tag_terminal_risk_management_data_u64 = 0x9F1D,
    /** ifd_serial_number in BASE: identifier octets as an integer. */
    tlv_emv_tag_ifd_serial_number_u64 = 0x9F1E,
    /** track1_discretionary_data in BASE: identifier octets as an integer. */
    tlv_emv_tag_track1_discretionary_data_u64 = 0x9F1F,
    /** track2_discretionary_data in BASE: identifier octets as an integer. */
    tlv_emv_tag_track2_discretionary_data_u64 = 0x9F20,
    /** transaction_time in BASE: identifier octets as an integer. */
    tlv_emv_tag_transaction_time_u64 = 0x9F21,
    /** ca_public_key_index_terminal in BASE: identifier octets as an integer. */
    tlv_emv_tag_ca_public_key_index_terminal_u64 = 0x9F22,
    /** upper_consecutive_offline_limit in BASE: identifier octets as an integer. */
    tlv_emv_tag_upper_consecutive_offline_limit_u64 = 0x9F23,
    /** payment_account_reference in BASE: identifier octets as an integer. */
    tlv_emv_tag_payment_account_reference_u64 = 0x9F24,
    /** last4_pan in BASE: identifier octets as an integer. */
    tlv_emv_tag_last4_pan_u64 = 0x9F25,
    /** application_cryptogram in BASE: identifier octets as an integer. */
    tlv_emv_tag_application_cryptogram_u64 = 0x9F26,
    /** cryptogram_information_data in BASE: identifier octets as an integer. */
    tlv_emv_tag_cryptogram_information_data_u64 = 0x9F27,
    /** icc_pin_public_key_certificate in BASE: identifier octets as an integer. */
    tlv_emv_tag_icc_pin_public_key_certificate_u64 = 0x9F2D,
    /** icc_pin_public_key_exponent in BASE: identifier octets as an integer. */
    tlv_emv_tag_icc_pin_public_key_exponent_u64 = 0x9F2E,
    /** icc_pin_public_key_remainder in BASE: identifier octets as an integer. */
    tlv_emv_tag_icc_pin_public_key_remainder_u64 = 0x9F2F,
    /** biometric_terminal_capabilities in BASE: identifier octets as an integer. */
    tlv_emv_tag_biometric_terminal_capabilities_u64 = 0x9F30,
    /** card_bit_group_template in BASE: identifier octets as an integer. */
    tlv_emv_tag_card_bit_group_template_u64 = 0x9F31,
    /** issuer_public_key_exponent in BASE: identifier octets as an integer. */
    tlv_emv_tag_issuer_public_key_exponent_u64 = 0x9F32,
    /** terminal_capabilities in BASE: identifier octets as an integer. */
    tlv_emv_tag_terminal_capabilities_u64 = 0x9F33,
    /** cvm_results in BASE: identifier octets as an integer. */
    tlv_emv_tag_cvm_results_u64 = 0x9F34,
    /** terminal_type in BASE: identifier octets as an integer. */
    tlv_emv_tag_terminal_type_u64 = 0x9F35,
    /** atc in BASE: identifier octets as an integer. */
    tlv_emv_tag_atc_u64 = 0x9F36,
    /** unpredictable_number in BASE: identifier octets as an integer. */
    tlv_emv_tag_unpredictable_number_u64 = 0x9F37,
    /** pdol in BASE: identifier octets as an integer. */
    tlv_emv_tag_pdol_u64 = 0x9F38,
    /** pos_entry_mode in BASE: identifier octets as an integer. */
    tlv_emv_tag_pos_entry_mode_u64 = 0x9F39,
    /** amount_reference_currency in BASE: identifier octets as an integer. */
    tlv_emv_tag_amount_reference_currency_u64 = 0x9F3A,
    /** application_reference_currency in BASE: identifier octets as an integer. */
    tlv_emv_tag_application_reference_currency_u64 = 0x9F3B,
    /** transaction_reference_currency_code in BASE: identifier octets as an integer. */
    tlv_emv_tag_transaction_reference_currency_code_u64 = 0x9F3C,
    /** transaction_reference_currency_exponent in BASE: identifier octets as an integer. */
    tlv_emv_tag_transaction_reference_currency_exponent_u64 = 0x9F3D,
    /** additional_terminal_capabilities in BASE: identifier octets as an integer. */
    tlv_emv_tag_additional_terminal_capabilities_u64 = 0x9F40,
    /** transaction_sequence_counter in BASE: identifier octets as an integer. */
    tlv_emv_tag_transaction_sequence_counter_u64 = 0x9F41,
    /** application_currency_code in BASE: identifier octets as an integer. */
    tlv_emv_tag_application_currency_code_u64 = 0x9F42,
    /** application_reference_currency_exponent in BASE: identifier octets as an integer. */
    tlv_emv_tag_application_reference_currency_exponent_u64 = 0x9F43,
    /** application_currency_exponent in BASE: identifier octets as an integer. */
    tlv_emv_tag_application_currency_exponent_u64 = 0x9F44,
    /** data_authentication_code in BASE: identifier octets as an integer. */
    tlv_emv_tag_data_authentication_code_u64 = 0x9F45,
    /** icc_public_key_certificate in BASE: identifier octets as an integer. */
    tlv_emv_tag_icc_public_key_certificate_u64 = 0x9F46,
    /** icc_public_key_exponent in BASE: identifier octets as an integer. */
    tlv_emv_tag_icc_public_key_exponent_u64 = 0x9F47,
    /** icc_public_key_remainder in BASE: identifier octets as an integer. */
    tlv_emv_tag_icc_public_key_remainder_u64 = 0x9F48,
    /** ddol in BASE: identifier octets as an integer. */
    tlv_emv_tag_ddol_u64 = 0x9F49,
    /** sda_tag_list in BASE: identifier octets as an integer. */
    tlv_emv_tag_sda_tag_list_u64 = 0x9F4A,
    /** signed_dynamic_application_data in BASE: identifier octets as an integer. */
    tlv_emv_tag_signed_dynamic_application_data_u64 = 0x9F4B,
    /** icc_dynamic_number in BASE: identifier octets as an integer. */
    tlv_emv_tag_icc_dynamic_number_u64 = 0x9F4C,
    /** log_entry in BASE: identifier octets as an integer. */
    tlv_emv_tag_log_entry_u64 = 0x9F4D,
    /** merchant_name_and_location in BASE: identifier octets as an integer. */
    tlv_emv_tag_merchant_name_and_location_u64 = 0x9F4E,
    /** log_format in BASE: identifier octets as an integer. */
    tlv_emv_tag_log_format_u64 = 0x9F4F,
    /** fci_issuer_discretionary_data in BASE: identifier octets as an integer. */
    tlv_emv_tag_fci_issuer_discretionary_data_u64 = 0xBF0C,
    /** offline_bit_group_template in BASE: identifier octets as an integer. */
    tlv_emv_tag_offline_bit_group_template_u64 = 0xBF4A,
    /** online_bit_group_template in BASE: identifier octets as an integer. */
    tlv_emv_tag_online_bit_group_template_u64 = 0xBF4B,
    /** biometric_try_counters_template in BASE: identifier octets as an integer. */
    tlv_emv_tag_biometric_try_counters_template_u64 = 0xBF4C,
    /** preferred_attempts_template in BASE: identifier octets as an integer. */
    tlv_emv_tag_preferred_attempts_template_u64 = 0xBF4D,
    /** biometric_verification_data_template in BASE: identifier octets as an integer. */
    tlv_emv_tag_biometric_verification_data_template_u64 = 0xBF4E,
    /** biometric_header_template in BIT: identifier octets as an integer. */
    tlv_emv_tag_biometric_header_template_u64 = 0xA1,
    /** biometric_header_version in BHT: identifier octets as an integer. */
    tlv_emv_tag_biometric_header_version_u64 = 0x80,
    /** biometric_type in BHT: identifier octets as an integer. */
    tlv_emv_tag_biometric_type_u64 = 0x81,
    /** biometric_subtype in BHT: identifier octets as an integer. */
    tlv_emv_tag_biometric_subtype_u64 = 0x82,
    /** biometric_creation_datetime in BHT: identifier octets as an integer. */
    tlv_emv_tag_biometric_creation_datetime_u64 = 0x83,
    /** biometric_creator in BHT: identifier octets as an integer. */
    tlv_emv_tag_biometric_creator_u64 = 0x84,
    /** biometric_validity_period in BHT: identifier octets as an integer. */
    tlv_emv_tag_biometric_validity_period_u64 = 0x85,
    /** biometric_product_id in BHT: identifier octets as an integer. */
    tlv_emv_tag_biometric_product_id_u64 = 0x86,
    /** biometric_format_owner in BHT: identifier octets as an integer. */
    tlv_emv_tag_biometric_format_owner_u64 = 0x87,
    /** biometric_format_type in BHT: identifier octets as an integer. */
    tlv_emv_tag_biometric_format_type_u64 = 0x88,
    /** biometric_solution_id in BHT: identifier octets as an integer. */
    tlv_emv_tag_biometric_solution_id_u64 = 0x90,
    /** biometric_matching_parameters in BHT: identifier octets as an integer. */
    tlv_emv_tag_biometric_matching_parameters_u64 = 0x91,
    /** bht1 in BHT: identifier octets as an integer. */
    tlv_emv_tag_bht1_u64 = 0xA1,
    /** bht2 in BHT: identifier octets as an integer. */
    tlv_emv_tag_bht2_u64 = 0xA2,
    /** biometric_matching_parameters_template in BHT: identifier octets as an integer. */
    tlv_emv_tag_biometric_matching_parameters_template_u64 = 0xB1,
    /** bht_format_owner in BHT_FORMAT: identifier octets as an integer. */
    tlv_emv_tag_bht_format_owner_u64 = 0x87,
    /** bht_format_type in BHT_FORMAT: identifier octets as an integer. */
    tlv_emv_tag_bht_format_type_u64 = 0x88,
    /** bit_count in BIT_GROUP: identifier octets as an integer. */
    tlv_emv_tag_bit_count_u64 = 0x2,
    /** group_bit in BIT_GROUP: identifier octets as an integer. */
    tlv_emv_tag_group_bit_u64 = 0x7F60,
    /** facial_try_counter in BIOMETRIC_COUNTERS: identifier octets as an integer. */
    tlv_emv_tag_facial_try_counter_u64 = 0xDF50,
    /** finger_try_counter in BIOMETRIC_COUNTERS: identifier octets as an integer. */
    tlv_emv_tag_finger_try_counter_u64 = 0xDF51,
    /** iris_try_counter in BIOMETRIC_COUNTERS: identifier octets as an integer. */
    tlv_emv_tag_iris_try_counter_u64 = 0xDF52,
    /** palm_try_counter in BIOMETRIC_COUNTERS: identifier octets as an integer. */
    tlv_emv_tag_palm_try_counter_u64 = 0xDF53,
    /** voice_try_counter in BIOMETRIC_COUNTERS: identifier octets as an integer. */
    tlv_emv_tag_voice_try_counter_u64 = 0xDF54,
    /** preferred_facial_attempts in BIOMETRIC_ATTEMPTS: identifier octets as an integer. */
    tlv_emv_tag_preferred_facial_attempts_u64 = 0xDF50,
    /** preferred_finger_attempts in BIOMETRIC_ATTEMPTS: identifier octets as an integer. */
    tlv_emv_tag_preferred_finger_attempts_u64 = 0xDF51,
    /** preferred_iris_attempts in BIOMETRIC_ATTEMPTS: identifier octets as an integer. */
    tlv_emv_tag_preferred_iris_attempts_u64 = 0xDF52,
    /** preferred_palm_attempts in BIOMETRIC_ATTEMPTS: identifier octets as an integer. */
    tlv_emv_tag_preferred_palm_attempts_u64 = 0xDF53,
    /** preferred_voice_attempts in BIOMETRIC_ATTEMPTS: identifier octets as an integer. */
    tlv_emv_tag_preferred_voice_attempts_u64 = 0xDF54,
    /** verification_biometric_type in BIOMETRIC_VERIFICATION: identifier octets as an integer. */
    tlv_emv_tag_verification_biometric_type_u64 = 0x81,
    /** verification_biometric_solution_id in BIOMETRIC_VERIFICATION: identifier octets as an
       integer. */
    tlv_emv_tag_verification_biometric_solution_id_u64 = 0x90,
    /** enciphered_biometric_key_seed in BIOMETRIC_VERIFICATION: identifier octets as an integer. */
    tlv_emv_tag_enciphered_biometric_key_seed_u64 = 0xDF50,
    /** enciphered_biometric_data in BIOMETRIC_VERIFICATION: identifier octets as an integer. */
    tlv_emv_tag_enciphered_biometric_data_u64 = 0xDF51,
    /** biometric_data_mac in BIOMETRIC_VERIFICATION: identifier octets as an integer. */
    tlv_emv_tag_biometric_data_mac_u64 = 0xDF52,
};
/** @} */

/** @name Tag objects
 * Immutable borrowed identifier bytes with static lifetime.
 * @{
 */
/** @brief iin identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_iin;
/** @brief adf_name identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_adf_name;
/** @brief application_label identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_application_label;
/** @brief track2_equivalent_data identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_track2_equivalent_data;
/** @brief pan identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_pan;
/** @brief application_template identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_application_template;
/** @brief fci_template identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_fci_template;
/** @brief read_record_template identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_read_record_template;
/** @brief issuer_script_template1 identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_issuer_script_template1;
/** @brief issuer_script_template2 identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_issuer_script_template2;
/** @brief directory_discretionary_template identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_directory_discretionary_template;
/** @brief response_template2 identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_response_template2;
/** @brief response_template1 identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_response_template1;
/** @brief amount_authorised_binary identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_amount_authorised_binary;
/** @brief aip identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_aip;
/** @brief command_template identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_command_template;
/** @brief df_name identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_df_name;
/** @brief issuer_script_command identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_issuer_script_command;
/** @brief application_priority_indicator identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_application_priority_indicator;
/** @brief sfi identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_sfi;
/** @brief authorisation_code identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_authorisation_code;
/** @brief authorisation_response_code identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_authorisation_response_code;
/** @brief cdol1 identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_cdol1;
/** @brief cdol2 identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_cdol2;
/** @brief cvm_list identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_cvm_list;
/** @brief ca_public_key_index identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_ca_public_key_index;
/** @brief issuer_public_key_certificate identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_issuer_public_key_certificate;
/** @brief issuer_authentication_data identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_issuer_authentication_data;
/** @brief issuer_public_key_remainder identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_issuer_public_key_remainder;
/** @brief signed_static_application_data identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_signed_static_application_data;
/** @brief afl identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_afl;
/** @brief tvr identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_tvr;
/** @brief tdol identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_tdol;
/** @brief tc_hash_value identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_tc_hash_value;
/** @brief transaction_pin_data identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_transaction_pin_data;
/** @brief transaction_date identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_transaction_date;
/** @brief tsi identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_tsi;
/** @brief transaction_type identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_transaction_type;
/** @brief ddf_name identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_ddf_name;
/** @brief fci_proprietary_template identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_fci_proprietary_template;
/** @brief cardholder_name identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_cardholder_name;
/** @brief application_expiration_date identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_application_expiration_date;
/** @brief application_effective_date identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_application_effective_date;
/** @brief issuer_country_code identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_issuer_country_code;
/** @brief transaction_currency_code identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_transaction_currency_code;
/** @brief language_preference identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_language_preference;
/** @brief service_code identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_service_code;
/** @brief pan_sequence_number identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_pan_sequence_number;
/** @brief transaction_currency_exponent identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_transaction_currency_exponent;
/** @brief issuer_url identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_issuer_url;
/** @brief iban identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_iban;
/** @brief bic identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_bic;
/** @brief issuer_country_alpha2 identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_issuer_country_alpha2;
/** @brief issuer_country_alpha3 identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_issuer_country_alpha3;
/** @brief account_type identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_account_type;
/** @brief biometric_information_template identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_biometric_information_template;
/** @brief acquirer_identifier identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_acquirer_identifier;
/** @brief amount_authorised identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_amount_authorised;
/** @brief amount_other identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_amount_other;
/** @brief amount_other_binary identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_amount_other_binary;
/** @brief application_discretionary_data identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_application_discretionary_data;
/** @brief aid_terminal identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_aid_terminal;
/** @brief application_usage_control identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_application_usage_control;
/** @brief application_version_card identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_application_version_card;
/** @brief application_version_terminal identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_application_version_terminal;
/** @brief asrpd identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_asrpd;
/** @brief cardholder_name_extended identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_cardholder_name_extended;
/** @brief iin_extended identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_iin_extended;
/** @brief issuer_action_code_default identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_issuer_action_code_default;
/** @brief issuer_action_code_denial identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_issuer_action_code_denial;
/** @brief issuer_action_code_online identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_issuer_action_code_online;
/** @brief issuer_application_data identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_issuer_application_data;
/** @brief issuer_code_table_index identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_issuer_code_table_index;
/** @brief application_preferred_name identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_application_preferred_name;
/** @brief last_online_atc identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_last_online_atc;
/** @brief lower_consecutive_offline_limit identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_lower_consecutive_offline_limit;
/** @brief merchant_category_code identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_merchant_category_code;
/** @brief merchant_identifier identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_merchant_identifier;
/** @brief pin_try_counter identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_pin_try_counter;
/** @brief issuer_script_identifier identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_issuer_script_identifier;
/** @brief token_requestor_id identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_token_requestor_id;
/** @brief terminal_country_code identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_terminal_country_code;
/** @brief terminal_floor_limit identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_terminal_floor_limit;
/** @brief terminal_identification identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_terminal_identification;
/** @brief terminal_risk_management_data identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_terminal_risk_management_data;
/** @brief ifd_serial_number identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_ifd_serial_number;
/** @brief track1_discretionary_data identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_track1_discretionary_data;
/** @brief track2_discretionary_data identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_track2_discretionary_data;
/** @brief transaction_time identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_transaction_time;
/** @brief ca_public_key_index_terminal identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_ca_public_key_index_terminal;
/** @brief upper_consecutive_offline_limit identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_upper_consecutive_offline_limit;
/** @brief payment_account_reference identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_payment_account_reference;
/** @brief last4_pan identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_last4_pan;
/** @brief application_cryptogram identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_application_cryptogram;
/** @brief cryptogram_information_data identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_cryptogram_information_data;
/** @brief icc_pin_public_key_certificate identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_icc_pin_public_key_certificate;
/** @brief icc_pin_public_key_exponent identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_icc_pin_public_key_exponent;
/** @brief icc_pin_public_key_remainder identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_icc_pin_public_key_remainder;
/** @brief biometric_terminal_capabilities identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_biometric_terminal_capabilities;
/** @brief card_bit_group_template identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_card_bit_group_template;
/** @brief issuer_public_key_exponent identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_issuer_public_key_exponent;
/** @brief terminal_capabilities identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_terminal_capabilities;
/** @brief cvm_results identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_cvm_results;
/** @brief terminal_type identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_terminal_type;
/** @brief atc identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_atc;
/** @brief unpredictable_number identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_unpredictable_number;
/** @brief pdol identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_pdol;
/** @brief pos_entry_mode identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_pos_entry_mode;
/** @brief amount_reference_currency identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_amount_reference_currency;
/** @brief application_reference_currency identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_application_reference_currency;
/** @brief transaction_reference_currency_code identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_transaction_reference_currency_code;
/** @brief transaction_reference_currency_exponent identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_transaction_reference_currency_exponent;
/** @brief additional_terminal_capabilities identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_additional_terminal_capabilities;
/** @brief transaction_sequence_counter identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_transaction_sequence_counter;
/** @brief application_currency_code identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_application_currency_code;
/** @brief application_reference_currency_exponent identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_application_reference_currency_exponent;
/** @brief application_currency_exponent identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_application_currency_exponent;
/** @brief data_authentication_code identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_data_authentication_code;
/** @brief icc_public_key_certificate identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_icc_public_key_certificate;
/** @brief icc_public_key_exponent identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_icc_public_key_exponent;
/** @brief icc_public_key_remainder identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_icc_public_key_remainder;
/** @brief ddol identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_ddol;
/** @brief sda_tag_list identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_sda_tag_list;
/** @brief signed_dynamic_application_data identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_signed_dynamic_application_data;
/** @brief icc_dynamic_number identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_icc_dynamic_number;
/** @brief log_entry identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_log_entry;
/** @brief merchant_name_and_location identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_merchant_name_and_location;
/** @brief log_format identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_log_format;
/** @brief fci_issuer_discretionary_data identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_fci_issuer_discretionary_data;
/** @brief offline_bit_group_template identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_offline_bit_group_template;
/** @brief online_bit_group_template identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_online_bit_group_template;
/** @brief biometric_try_counters_template identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_biometric_try_counters_template;
/** @brief preferred_attempts_template identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_preferred_attempts_template;
/** @brief biometric_verification_data_template identifier in BASE. */
extern TLV_API const tlv_tag_t tlv_emv_tag_biometric_verification_data_template;
/** @brief biometric_header_template identifier in BIT. */
extern TLV_API const tlv_tag_t tlv_emv_tag_biometric_header_template;
/** @brief biometric_header_version identifier in BHT. */
extern TLV_API const tlv_tag_t tlv_emv_tag_biometric_header_version;
/** @brief biometric_type identifier in BHT. */
extern TLV_API const tlv_tag_t tlv_emv_tag_biometric_type;
/** @brief biometric_subtype identifier in BHT. */
extern TLV_API const tlv_tag_t tlv_emv_tag_biometric_subtype;
/** @brief biometric_creation_datetime identifier in BHT. */
extern TLV_API const tlv_tag_t tlv_emv_tag_biometric_creation_datetime;
/** @brief biometric_creator identifier in BHT. */
extern TLV_API const tlv_tag_t tlv_emv_tag_biometric_creator;
/** @brief biometric_validity_period identifier in BHT. */
extern TLV_API const tlv_tag_t tlv_emv_tag_biometric_validity_period;
/** @brief biometric_product_id identifier in BHT. */
extern TLV_API const tlv_tag_t tlv_emv_tag_biometric_product_id;
/** @brief biometric_format_owner identifier in BHT. */
extern TLV_API const tlv_tag_t tlv_emv_tag_biometric_format_owner;
/** @brief biometric_format_type identifier in BHT. */
extern TLV_API const tlv_tag_t tlv_emv_tag_biometric_format_type;
/** @brief biometric_solution_id identifier in BHT. */
extern TLV_API const tlv_tag_t tlv_emv_tag_biometric_solution_id;
/** @brief biometric_matching_parameters identifier in BHT. */
extern TLV_API const tlv_tag_t tlv_emv_tag_biometric_matching_parameters;
/** @brief bht1 identifier in BHT. */
extern TLV_API const tlv_tag_t tlv_emv_tag_bht1;
/** @brief bht2 identifier in BHT. */
extern TLV_API const tlv_tag_t tlv_emv_tag_bht2;
/** @brief biometric_matching_parameters_template identifier in BHT. */
extern TLV_API const tlv_tag_t tlv_emv_tag_biometric_matching_parameters_template;
/** @brief bht_format_owner identifier in BHT_FORMAT. */
extern TLV_API const tlv_tag_t tlv_emv_tag_bht_format_owner;
/** @brief bht_format_type identifier in BHT_FORMAT. */
extern TLV_API const tlv_tag_t tlv_emv_tag_bht_format_type;
/** @brief bit_count identifier in BIT_GROUP. */
extern TLV_API const tlv_tag_t tlv_emv_tag_bit_count;
/** @brief group_bit identifier in BIT_GROUP. */
extern TLV_API const tlv_tag_t tlv_emv_tag_group_bit;
/** @brief facial_try_counter identifier in BIOMETRIC_COUNTERS. */
extern TLV_API const tlv_tag_t tlv_emv_tag_facial_try_counter;
/** @brief finger_try_counter identifier in BIOMETRIC_COUNTERS. */
extern TLV_API const tlv_tag_t tlv_emv_tag_finger_try_counter;
/** @brief iris_try_counter identifier in BIOMETRIC_COUNTERS. */
extern TLV_API const tlv_tag_t tlv_emv_tag_iris_try_counter;
/** @brief palm_try_counter identifier in BIOMETRIC_COUNTERS. */
extern TLV_API const tlv_tag_t tlv_emv_tag_palm_try_counter;
/** @brief voice_try_counter identifier in BIOMETRIC_COUNTERS. */
extern TLV_API const tlv_tag_t tlv_emv_tag_voice_try_counter;
/** @brief preferred_facial_attempts identifier in BIOMETRIC_ATTEMPTS. */
extern TLV_API const tlv_tag_t tlv_emv_tag_preferred_facial_attempts;
/** @brief preferred_finger_attempts identifier in BIOMETRIC_ATTEMPTS. */
extern TLV_API const tlv_tag_t tlv_emv_tag_preferred_finger_attempts;
/** @brief preferred_iris_attempts identifier in BIOMETRIC_ATTEMPTS. */
extern TLV_API const tlv_tag_t tlv_emv_tag_preferred_iris_attempts;
/** @brief preferred_palm_attempts identifier in BIOMETRIC_ATTEMPTS. */
extern TLV_API const tlv_tag_t tlv_emv_tag_preferred_palm_attempts;
/** @brief preferred_voice_attempts identifier in BIOMETRIC_ATTEMPTS. */
extern TLV_API const tlv_tag_t tlv_emv_tag_preferred_voice_attempts;
/** @brief verification_biometric_type identifier in BIOMETRIC_VERIFICATION. */
extern TLV_API const tlv_tag_t tlv_emv_tag_verification_biometric_type;
/** @brief verification_biometric_solution_id identifier in BIOMETRIC_VERIFICATION. */
extern TLV_API const tlv_tag_t tlv_emv_tag_verification_biometric_solution_id;
/** @brief enciphered_biometric_key_seed identifier in BIOMETRIC_VERIFICATION. */
extern TLV_API const tlv_tag_t tlv_emv_tag_enciphered_biometric_key_seed;
/** @brief enciphered_biometric_data identifier in BIOMETRIC_VERIFICATION. */
extern TLV_API const tlv_tag_t tlv_emv_tag_enciphered_biometric_data;
/** @brief biometric_data_mac identifier in BIOMETRIC_VERIFICATION. */
extern TLV_API const tlv_tag_t tlv_emv_tag_biometric_data_mac;
/** @} */

/** @brief Borrowed composition of identifier metadata, field Schema and Value Codec.
 * Each referenced object is authoritative for its own properties. The schema's
 * tag must equal definition->tag; both should borrow the same canonical bytes.
 * A dictionary selects context, without imposing a required generic pipeline.
 * All referenced objects and their storage must remain immutable and alive
 * while an entry is used. Builtin entries borrow static storage.
 */
typedef struct {
    /** Identifier and descriptive name; all storage is borrowed. */
    const tlv_definition_t* definition;
    /** Field constraints and optional diagnostic symbol; borrowed. */
    const tlv_schema_entry_t* schema;
    /** Selected Value conversion; NULL means retain opaque input bytes. */
    const tlv_codec_t* codec;
} tlv_emv_definition_t;

/** @brief Returns the optional dictionary symbol owned by the referenced Schema.
 * @param[in] definition Borrowed entry, or NULL.
 * @return Borrowed NUL-terminated symbol, or NULL when absent.
 */
TLV_API const char* tlv_emv_symbol(const tlv_emv_definition_t* definition);

/**
 * @brief Borrowed EMV domain dictionary for one explicitly selected context.
 *
 * Native tables and caller-owned tables use the same lookup. Entries, schemas,
 * tag bytes, names, codecs and codec contexts must remain alive and immutable
 * while this dictionary or returned entries are used. No allocation or ownership
 * transfer occurs. Descriptive labels remain separate from symbolic names.
 */
typedef struct tlv_emv_dictionary {
    /** Contiguous entries; may be NULL only when count is zero. */
    const tlv_emv_definition_t* entries;
    /** Number of entries. */
    size_t count;
} tlv_emv_dictionary_t;

/**
 * @brief Returns the immutable builtin dictionary for an explicit EMV context.
 * @param[in] context Context to select; no fallback is performed.
 * @return Borrowed static dictionary, or NULL for an invalid context.
 */
TLV_API const tlv_emv_dictionary_t* tlv_emv_dictionary_for(tlv_emv_context_t context);

/**
 * @brief Finds the first byte-identical tag in a selected domain dictionary.
 * @param[in] dictionary Borrowed table to search; may be NULL.
 * @param[in] tag Identifier to find; may be NULL.
 * @return Borrowed matching entry, or NULL for invalid arguments or no match.
 * @note Empty/invalid lookup tags are rejected. Entries without Definition or
 *       Schema, or whose identifiers disagree, are skipped. No fallback, allocation, schema
 * validation or value decoding occurs.
 */
TLV_API const tlv_emv_definition_t* tlv_emv_dictionary_find(const tlv_emv_dictionary_t* dictionary,
                                                            const tlv_tag_t* tag);

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
 * Delegates all field-length validation to the referenced generic Schema.
 *
 * @param definition Definition to validate against.
 * @param length     Value length in bytes.
 *
 * @return #TLV_OK if the length is permitted.
 * @return #TLV_ERR_NULL_ARG if `definition` is `NULL`.
 * @return #TLV_ERR_SCHEMA if the length is not permitted.
 * @return #TLV_ERR_INVALID_SCHEMA if the length bounds are reversed.
 *
 * @note This is not a transaction validator: key-dependent lengths,
 *       required and duplicate tags, template membership, and cryptographic
 *       or value semantics are separate checks.
 */
TLV_API tlv_result_t tlv_emv_validate_length(const tlv_emv_definition_t* definition, size_t length);

/**
 * @brief Returns the spacing of permitted lengths for EMV display compatibility.
 * @param[in] definition Entry whose Schema supplies the authoritative constraints.
 * @return Endpoint separation, nonzero length multiple, or one for an interval;
 *         zero for a missing or invalid schema.
 * @note This is derived information, not a separate constraint. Always validate
 *       through tlv_emv_validate_length(), including when bounds are equal.
 */
TLV_API size_t tlv_emv_length_step(const tlv_emv_definition_t* definition);

/**
 * @brief Returns a curated human-readable label for a dictionary symbol.
 *
 * For example, `"afl"` maps to `"Application File Locator (AFL)"`. Intended
 * for diagnostics or tooling. Coverage is limited to symbols whose
 * title-cased form would be misleading (abbreviations, initialisms).
 *
 * @param name Symbol returned by tlv_emv_symbol(); may be `NULL`.
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

#endif /* OPENTLV_BUILTINS_EMV_H */
