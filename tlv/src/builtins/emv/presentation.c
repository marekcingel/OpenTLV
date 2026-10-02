// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/builtins/emv/presentation.h"

/* The builtin UI/binding profile is intentionally separate from the domain
 * dictionary. It describes how this adapter displays known fields and supplies
 * C storage for their immutable builtin codecs. No generic runtime type system
 * or requirement on caller-owned dictionaries follows from this table. */
static const struct {
    tlv_emv_context_t context;
    const tlv_tag_t* tag;
    tlv_emv_value_kind_t kind;
} display_profile[] = {
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_iin, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_application_label, TLV_EMV_VALUE_TEXT},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_track2_equivalent_data, TLV_EMV_VALUE_TRACK2},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_pan, TLV_EMV_VALUE_DIGITS},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_application_template, TLV_EMV_VALUE_TEMPLATE},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_fci_template, TLV_EMV_VALUE_TEMPLATE},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_read_record_template, TLV_EMV_VALUE_TEMPLATE},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_issuer_script_template1, TLV_EMV_VALUE_TEMPLATE},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_issuer_script_template2, TLV_EMV_VALUE_TEMPLATE},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_directory_discretionary_template, TLV_EMV_VALUE_TEMPLATE},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_response_template2, TLV_EMV_VALUE_TEMPLATE},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_amount_authorised_binary, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_aip, TLV_EMV_VALUE_FLAGS},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_application_priority_indicator, TLV_EMV_VALUE_FLAGS},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_sfi, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_authorisation_response_code, TLV_EMV_VALUE_TEXT},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_ca_public_key_index, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_afl, TLV_EMV_VALUE_AFL},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_tvr, TLV_EMV_VALUE_FLAGS},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_transaction_date, TLV_EMV_VALUE_DATE},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_tsi, TLV_EMV_VALUE_FLAGS},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_transaction_type, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_fci_proprietary_template, TLV_EMV_VALUE_TEMPLATE},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_cardholder_name, TLV_EMV_VALUE_TEXT},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_application_expiration_date, TLV_EMV_VALUE_DATE},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_application_effective_date, TLV_EMV_VALUE_DATE},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_issuer_country_code, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_transaction_currency_code, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_language_preference, TLV_EMV_VALUE_TEXT},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_service_code, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_pan_sequence_number, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_transaction_currency_exponent, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_issuer_url, TLV_EMV_VALUE_TEXT},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_iban, TLV_EMV_VALUE_TEXT},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_bic, TLV_EMV_VALUE_TEXT},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_issuer_country_alpha2, TLV_EMV_VALUE_TEXT},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_issuer_country_alpha3, TLV_EMV_VALUE_TEXT},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_account_type, TLV_EMV_VALUE_ACCOUNT},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_biometric_information_template, TLV_EMV_VALUE_TEMPLATE},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_acquirer_identifier, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_amount_authorised, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_amount_other, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_amount_other_binary, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_application_usage_control, TLV_EMV_VALUE_FLAGS},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_application_version_card, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_application_version_terminal, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_cardholder_name_extended, TLV_EMV_VALUE_TEXT},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_iin_extended, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_issuer_action_code_default, TLV_EMV_VALUE_FLAGS},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_issuer_action_code_denial, TLV_EMV_VALUE_FLAGS},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_issuer_action_code_online, TLV_EMV_VALUE_FLAGS},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_issuer_code_table_index, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_application_preferred_name, TLV_EMV_VALUE_TEXT},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_last_online_atc, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_lower_consecutive_offline_limit, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_merchant_category_code, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_merchant_identifier, TLV_EMV_VALUE_TEXT},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_pin_try_counter, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_token_requestor_id, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_terminal_country_code, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_terminal_floor_limit, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_terminal_identification, TLV_EMV_VALUE_TEXT},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_ifd_serial_number, TLV_EMV_VALUE_TEXT},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_track1_discretionary_data, TLV_EMV_VALUE_TEXT},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_track2_discretionary_data, TLV_EMV_VALUE_DIGITS},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_transaction_time, TLV_EMV_VALUE_TIME},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_ca_public_key_index_terminal, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_upper_consecutive_offline_limit, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_payment_account_reference, TLV_EMV_VALUE_TEXT},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_last4_pan, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_cryptogram_information_data, TLV_EMV_VALUE_CRYPTOGRAM},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_icc_pin_public_key_exponent, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_biometric_terminal_capabilities, TLV_EMV_VALUE_FLAGS},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_card_bit_group_template, TLV_EMV_VALUE_TEMPLATE},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_issuer_public_key_exponent, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_terminal_capabilities, TLV_EMV_VALUE_FLAGS},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_cvm_results, TLV_EMV_VALUE_CVM_RESULT},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_terminal_type, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_atc, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_pos_entry_mode, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_amount_reference_currency, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_application_reference_currency, TLV_EMV_VALUE_NUMBER_LIST},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_transaction_reference_currency_code, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_transaction_reference_currency_exponent,
     TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_additional_terminal_capabilities, TLV_EMV_VALUE_FLAGS},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_transaction_sequence_counter, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_application_currency_code, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_application_reference_currency_exponent,
     TLV_EMV_VALUE_NUMBER_LIST},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_application_currency_exponent, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_icc_public_key_exponent, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_merchant_name_and_location, TLV_EMV_VALUE_TEXT},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_fci_issuer_discretionary_data, TLV_EMV_VALUE_TEMPLATE},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_offline_bit_group_template, TLV_EMV_VALUE_TEMPLATE},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_online_bit_group_template, TLV_EMV_VALUE_TEMPLATE},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_biometric_try_counters_template, TLV_EMV_VALUE_TEMPLATE},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_preferred_attempts_template, TLV_EMV_VALUE_TEMPLATE},
    {TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_biometric_verification_data_template,
     TLV_EMV_VALUE_TEMPLATE},
    {TLV_EMV_CONTEXT_BIT, &tlv_emv_tag_biometric_header_template, TLV_EMV_VALUE_TEMPLATE},
    {TLV_EMV_CONTEXT_BHT, &tlv_emv_tag_biometric_header_version, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BHT, &tlv_emv_tag_biometric_type, TLV_EMV_VALUE_BIOMETRIC},
    {TLV_EMV_CONTEXT_BHT, &tlv_emv_tag_biometric_subtype, TLV_EMV_VALUE_FLAGS},
    {TLV_EMV_CONTEXT_BHT, &tlv_emv_tag_biometric_product_id, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BHT, &tlv_emv_tag_biometric_format_owner, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BHT, &tlv_emv_tag_biometric_format_type, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BHT, &tlv_emv_tag_bht1, TLV_EMV_VALUE_TEMPLATE},
    {TLV_EMV_CONTEXT_BHT, &tlv_emv_tag_bht2, TLV_EMV_VALUE_TEMPLATE},
    {TLV_EMV_CONTEXT_BHT, &tlv_emv_tag_biometric_matching_parameters_template,
     TLV_EMV_VALUE_TEMPLATE},
    {TLV_EMV_CONTEXT_BHT_FORMAT, &tlv_emv_tag_bht_format_owner, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BHT_FORMAT, &tlv_emv_tag_bht_format_type, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BIT_GROUP, &tlv_emv_tag_bit_count, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BIT_GROUP, &tlv_emv_tag_group_bit, TLV_EMV_VALUE_TEMPLATE},
    {TLV_EMV_CONTEXT_BIOMETRIC_COUNTERS, &tlv_emv_tag_facial_try_counter, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BIOMETRIC_COUNTERS, &tlv_emv_tag_finger_try_counter, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BIOMETRIC_COUNTERS, &tlv_emv_tag_iris_try_counter, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BIOMETRIC_COUNTERS, &tlv_emv_tag_palm_try_counter, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BIOMETRIC_COUNTERS, &tlv_emv_tag_voice_try_counter, TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BIOMETRIC_ATTEMPTS, &tlv_emv_tag_preferred_facial_attempts,
     TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BIOMETRIC_ATTEMPTS, &tlv_emv_tag_preferred_finger_attempts,
     TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BIOMETRIC_ATTEMPTS, &tlv_emv_tag_preferred_iris_attempts,
     TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BIOMETRIC_ATTEMPTS, &tlv_emv_tag_preferred_palm_attempts,
     TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BIOMETRIC_ATTEMPTS, &tlv_emv_tag_preferred_voice_attempts,
     TLV_EMV_VALUE_NUMBER},
    {TLV_EMV_CONTEXT_BIOMETRIC_VERIFICATION, &tlv_emv_tag_verification_biometric_type,
     TLV_EMV_VALUE_BIOMETRIC}};

tlv_emv_value_kind_t tlv_emv_builtin_value_kind(const tlv_emv_definition_t* definition) {
    int context;
    size_t i, j;
    if (!definition) return TLV_EMV_VALUE_UNKNOWN;
    for (context = 0; context < TLV_EMV_CONTEXT_COUNT; ++context) {
        const tlv_emv_dictionary_t* dictionary = tlv_emv_dictionary_for((tlv_emv_context_t)context);
        for (i = 0; i < dictionary->count; ++i) {
            if (definition != &dictionary->entries[i]) continue;
            for (j = 0; j < sizeof(display_profile) / sizeof(display_profile[0]); ++j)
                if (display_profile[j].context == (tlv_emv_context_t)context &&
                    tlv_tag_equal(*display_profile[j].tag, definition->definition->tag))
                    return display_profile[j].kind;
            return TLV_EMV_VALUE_BYTES;
        }
    }
    return TLV_EMV_VALUE_UNKNOWN;
}

const char* tlv_emv_value_kind_description(tlv_emv_value_kind_t kind) {
    switch (kind) {
        case TLV_EMV_VALUE_BYTES: return "Raw bytes";
        case TLV_EMV_VALUE_TEXT: return "Text bytes (not necessarily UTF-8)";
        case TLV_EMV_VALUE_TEMPLATE: return "Template containing encoded data elements";
        case TLV_EMV_VALUE_NUMBER: return "Numeric value (binary or decimal BCD, tag-dependent)";
        case TLV_EMV_VALUE_FLAGS: return "Bit flags";
        case TLV_EMV_VALUE_DIGITS: return "Decimal digits";
        case TLV_EMV_VALUE_DATE: return "Date (YYMMDD)";
        case TLV_EMV_VALUE_TIME: return "Time (hhmmss)";
        case TLV_EMV_VALUE_ACCOUNT: return "Account type";
        case TLV_EMV_VALUE_CRYPTOGRAM: return "Cryptogram information";
        case TLV_EMV_VALUE_BIOMETRIC: return "Biometric type";
        case TLV_EMV_VALUE_NUMBER_LIST: return "List of numeric values";
        case TLV_EMV_VALUE_AFL: return "Application File Locator entry list";
        case TLV_EMV_VALUE_CVM_RESULT: return "CVM method, condition, and result";
        case TLV_EMV_VALUE_TRACK2:
            return "Track 2 equivalent data (PAN, expiry, service code, discretionary data)";
        default: return "Unspecified representation";
    }
}
