// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/builtins/emv/emv.h"
#include "tlv/codec/number.h"
#include "emv_codec_internal.h"
#include "dictionary_internal.h"

/* Explicit Contact Book 3 data. Each context is independent; no fallback. */

static const uint8_t tag_42[] = {0x42};
static const uint8_t tag_4f[] = {0x4F};
static const uint8_t tag_50[] = {0x50};
static const uint8_t tag_57[] = {0x57};
static const uint8_t tag_5a[] = {0x5A};
static const uint8_t tag_61[] = {0x61};
static const uint8_t tag_6f[] = {0x6F};
static const uint8_t tag_70[] = {0x70};
static const uint8_t tag_71[] = {0x71};
static const uint8_t tag_72[] = {0x72};
static const uint8_t tag_73[] = {0x73};
static const uint8_t tag_77[] = {0x77};
static const uint8_t tag_80[] = {0x80};
static const uint8_t tag_81[] = {0x81};
static const uint8_t tag_82[] = {0x82};
static const uint8_t tag_83[] = {0x83};
static const uint8_t tag_84[] = {0x84};
static const uint8_t tag_86[] = {0x86};
static const uint8_t tag_87[] = {0x87};
static const uint8_t tag_88[] = {0x88};
static const uint8_t tag_89[] = {0x89};
static const uint8_t tag_8a[] = {0x8A};
static const uint8_t tag_8c[] = {0x8C};
static const uint8_t tag_8d[] = {0x8D};
static const uint8_t tag_8e[] = {0x8E};
static const uint8_t tag_8f[] = {0x8F};
static const uint8_t tag_90[] = {0x90};
static const uint8_t tag_91[] = {0x91};
static const uint8_t tag_92[] = {0x92};
static const uint8_t tag_93[] = {0x93};
static const uint8_t tag_94[] = {0x94};
static const uint8_t tag_95[] = {0x95};
static const uint8_t tag_97[] = {0x97};
static const uint8_t tag_98[] = {0x98};
static const uint8_t tag_99[] = {0x99};
static const uint8_t tag_9a[] = {0x9A};
static const uint8_t tag_9b[] = {0x9B};
static const uint8_t tag_9c[] = {0x9C};
static const uint8_t tag_9d[] = {0x9D};
static const uint8_t tag_a5[] = {0xA5};
static const uint8_t tag_5f20[] = {0x5F, 0x20};
static const uint8_t tag_5f24[] = {0x5F, 0x24};
static const uint8_t tag_5f25[] = {0x5F, 0x25};
static const uint8_t tag_5f28[] = {0x5F, 0x28};
static const uint8_t tag_5f2a[] = {0x5F, 0x2A};
static const uint8_t tag_5f2d[] = {0x5F, 0x2D};
static const uint8_t tag_5f30[] = {0x5F, 0x30};
static const uint8_t tag_5f34[] = {0x5F, 0x34};
static const uint8_t tag_5f36[] = {0x5F, 0x36};
static const uint8_t tag_5f50[] = {0x5F, 0x50};
static const uint8_t tag_5f53[] = {0x5F, 0x53};
static const uint8_t tag_5f54[] = {0x5F, 0x54};
static const uint8_t tag_5f55[] = {0x5F, 0x55};
static const uint8_t tag_5f56[] = {0x5F, 0x56};
static const uint8_t tag_5f57[] = {0x5F, 0x57};
static const uint8_t tag_7f60[] = {0x7F, 0x60};
static const uint8_t tag_9f01[] = {0x9F, 0x01};
static const uint8_t tag_9f02[] = {0x9F, 0x02};
static const uint8_t tag_9f03[] = {0x9F, 0x03};
static const uint8_t tag_9f04[] = {0x9F, 0x04};
static const uint8_t tag_9f05[] = {0x9F, 0x05};
static const uint8_t tag_9f06[] = {0x9F, 0x06};
static const uint8_t tag_9f07[] = {0x9F, 0x07};
static const uint8_t tag_9f08[] = {0x9F, 0x08};
static const uint8_t tag_9f09[] = {0x9F, 0x09};
static const uint8_t tag_9f0a[] = {0x9F, 0x0A};
static const uint8_t tag_9f0b[] = {0x9F, 0x0B};
static const uint8_t tag_9f0c[] = {0x9F, 0x0C};
static const uint8_t tag_9f0d[] = {0x9F, 0x0D};
static const uint8_t tag_9f0e[] = {0x9F, 0x0E};
static const uint8_t tag_9f0f[] = {0x9F, 0x0F};
static const uint8_t tag_9f10[] = {0x9F, 0x10};
static const uint8_t tag_9f11[] = {0x9F, 0x11};
static const uint8_t tag_9f12[] = {0x9F, 0x12};
static const uint8_t tag_9f13[] = {0x9F, 0x13};
static const uint8_t tag_9f14[] = {0x9F, 0x14};
static const uint8_t tag_9f15[] = {0x9F, 0x15};
static const uint8_t tag_9f16[] = {0x9F, 0x16};
static const uint8_t tag_9f17[] = {0x9F, 0x17};
static const uint8_t tag_9f18[] = {0x9F, 0x18};
static const uint8_t tag_9f19[] = {0x9F, 0x19};
static const uint8_t tag_9f1a[] = {0x9F, 0x1A};
static const uint8_t tag_9f1b[] = {0x9F, 0x1B};
static const uint8_t tag_9f1c[] = {0x9F, 0x1C};
static const uint8_t tag_9f1d[] = {0x9F, 0x1D};
static const uint8_t tag_9f1e[] = {0x9F, 0x1E};
static const uint8_t tag_9f1f[] = {0x9F, 0x1F};
static const uint8_t tag_9f20[] = {0x9F, 0x20};
static const uint8_t tag_9f21[] = {0x9F, 0x21};
static const uint8_t tag_9f22[] = {0x9F, 0x22};
static const uint8_t tag_9f23[] = {0x9F, 0x23};
static const uint8_t tag_9f24[] = {0x9F, 0x24};
static const uint8_t tag_9f25[] = {0x9F, 0x25};
static const uint8_t tag_9f26[] = {0x9F, 0x26};
static const uint8_t tag_9f27[] = {0x9F, 0x27};
static const uint8_t tag_9f2d[] = {0x9F, 0x2D};
static const uint8_t tag_9f2e[] = {0x9F, 0x2E};
static const uint8_t tag_9f2f[] = {0x9F, 0x2F};
static const uint8_t tag_9f30[] = {0x9F, 0x30};
static const uint8_t tag_9f31[] = {0x9F, 0x31};
static const uint8_t tag_9f32[] = {0x9F, 0x32};
static const uint8_t tag_9f33[] = {0x9F, 0x33};
static const uint8_t tag_9f34[] = {0x9F, 0x34};
static const uint8_t tag_9f35[] = {0x9F, 0x35};
static const uint8_t tag_9f36[] = {0x9F, 0x36};
static const uint8_t tag_9f37[] = {0x9F, 0x37};
static const uint8_t tag_9f38[] = {0x9F, 0x38};
static const uint8_t tag_9f39[] = {0x9F, 0x39};
static const uint8_t tag_9f3a[] = {0x9F, 0x3A};
static const uint8_t tag_9f3b[] = {0x9F, 0x3B};
static const uint8_t tag_9f3c[] = {0x9F, 0x3C};
static const uint8_t tag_9f3d[] = {0x9F, 0x3D};
static const uint8_t tag_9f40[] = {0x9F, 0x40};
static const uint8_t tag_9f41[] = {0x9F, 0x41};
static const uint8_t tag_9f42[] = {0x9F, 0x42};
static const uint8_t tag_9f43[] = {0x9F, 0x43};
static const uint8_t tag_9f44[] = {0x9F, 0x44};
static const uint8_t tag_9f45[] = {0x9F, 0x45};
static const uint8_t tag_9f46[] = {0x9F, 0x46};
static const uint8_t tag_9f47[] = {0x9F, 0x47};
static const uint8_t tag_9f48[] = {0x9F, 0x48};
static const uint8_t tag_9f49[] = {0x9F, 0x49};
static const uint8_t tag_9f4a[] = {0x9F, 0x4A};
static const uint8_t tag_9f4b[] = {0x9F, 0x4B};
static const uint8_t tag_9f4c[] = {0x9F, 0x4C};
static const uint8_t tag_9f4d[] = {0x9F, 0x4D};
static const uint8_t tag_9f4e[] = {0x9F, 0x4E};
static const uint8_t tag_9f4f[] = {0x9F, 0x4F};
static const uint8_t tag_bf0c[] = {0xBF, 0x0C};
static const uint8_t tag_bf4a[] = {0xBF, 0x4A};
static const uint8_t tag_bf4b[] = {0xBF, 0x4B};
static const uint8_t tag_bf4c[] = {0xBF, 0x4C};
static const uint8_t tag_bf4d[] = {0xBF, 0x4D};
static const uint8_t tag_bf4e[] = {0xBF, 0x4E};
static const uint8_t tag_a1[] = {0xA1};
static const uint8_t tag_85[] = {0x85};
static const uint8_t tag_a2[] = {0xA2};
static const uint8_t tag_b1[] = {0xB1};
static const uint8_t tag_02[] = {0x02};
static const uint8_t tag_df50[] = {0xDF, 0x50};
static const uint8_t tag_df51[] = {0xDF, 0x51};
static const uint8_t tag_df52[] = {0xDF, 0x52};
static const uint8_t tag_df53[] = {0xDF, 0x53};
static const uint8_t tag_df54[] = {0xDF, 0x54};
const tlv_tag_t tlv_emv_tag_iin = {tag_42, 1};
const tlv_tag_t tlv_emv_tag_adf_name = {tag_4f, 1};
const tlv_tag_t tlv_emv_tag_application_label = {tag_50, 1};
const tlv_tag_t tlv_emv_tag_track2_equivalent_data = {tag_57, 1};
const tlv_tag_t tlv_emv_tag_pan = {tag_5a, 1};
const tlv_tag_t tlv_emv_tag_application_template = {tag_61, 1};
const tlv_tag_t tlv_emv_tag_fci_template = {tag_6f, 1};
const tlv_tag_t tlv_emv_tag_read_record_template = {tag_70, 1};
const tlv_tag_t tlv_emv_tag_issuer_script_template1 = {tag_71, 1};
const tlv_tag_t tlv_emv_tag_issuer_script_template2 = {tag_72, 1};
const tlv_tag_t tlv_emv_tag_directory_discretionary_template = {tag_73, 1};
const tlv_tag_t tlv_emv_tag_response_template2 = {tag_77, 1};
const tlv_tag_t tlv_emv_tag_response_template1 = {tag_80, 1};
const tlv_tag_t tlv_emv_tag_amount_authorised_binary = {tag_81, 1};
const tlv_tag_t tlv_emv_tag_aip = {tag_82, 1};
const tlv_tag_t tlv_emv_tag_command_template = {tag_83, 1};
const tlv_tag_t tlv_emv_tag_df_name = {tag_84, 1};
const tlv_tag_t tlv_emv_tag_issuer_script_command = {tag_86, 1};
const tlv_tag_t tlv_emv_tag_application_priority_indicator = {tag_87, 1};
const tlv_tag_t tlv_emv_tag_sfi = {tag_88, 1};
const tlv_tag_t tlv_emv_tag_authorisation_code = {tag_89, 1};
const tlv_tag_t tlv_emv_tag_authorisation_response_code = {tag_8a, 1};
const tlv_tag_t tlv_emv_tag_cdol1 = {tag_8c, 1};
const tlv_tag_t tlv_emv_tag_cdol2 = {tag_8d, 1};
const tlv_tag_t tlv_emv_tag_cvm_list = {tag_8e, 1};
const tlv_tag_t tlv_emv_tag_ca_public_key_index = {tag_8f, 1};
const tlv_tag_t tlv_emv_tag_issuer_public_key_certificate = {tag_90, 1};
const tlv_tag_t tlv_emv_tag_issuer_authentication_data = {tag_91, 1};
const tlv_tag_t tlv_emv_tag_issuer_public_key_remainder = {tag_92, 1};
const tlv_tag_t tlv_emv_tag_signed_static_application_data = {tag_93, 1};
const tlv_tag_t tlv_emv_tag_afl = {tag_94, 1};
const tlv_tag_t tlv_emv_tag_tvr = {tag_95, 1};
const tlv_tag_t tlv_emv_tag_tdol = {tag_97, 1};
const tlv_tag_t tlv_emv_tag_tc_hash_value = {tag_98, 1};
const tlv_tag_t tlv_emv_tag_transaction_pin_data = {tag_99, 1};
const tlv_tag_t tlv_emv_tag_transaction_date = {tag_9a, 1};
const tlv_tag_t tlv_emv_tag_tsi = {tag_9b, 1};
const tlv_tag_t tlv_emv_tag_transaction_type = {tag_9c, 1};
const tlv_tag_t tlv_emv_tag_ddf_name = {tag_9d, 1};
const tlv_tag_t tlv_emv_tag_fci_proprietary_template = {tag_a5, 1};
const tlv_tag_t tlv_emv_tag_cardholder_name = {tag_5f20, 2};
const tlv_tag_t tlv_emv_tag_application_expiration_date = {tag_5f24, 2};
const tlv_tag_t tlv_emv_tag_application_effective_date = {tag_5f25, 2};
const tlv_tag_t tlv_emv_tag_issuer_country_code = {tag_5f28, 2};
const tlv_tag_t tlv_emv_tag_transaction_currency_code = {tag_5f2a, 2};
const tlv_tag_t tlv_emv_tag_language_preference = {tag_5f2d, 2};
const tlv_tag_t tlv_emv_tag_service_code = {tag_5f30, 2};
const tlv_tag_t tlv_emv_tag_pan_sequence_number = {tag_5f34, 2};
const tlv_tag_t tlv_emv_tag_transaction_currency_exponent = {tag_5f36, 2};
const tlv_tag_t tlv_emv_tag_issuer_url = {tag_5f50, 2};
const tlv_tag_t tlv_emv_tag_iban = {tag_5f53, 2};
const tlv_tag_t tlv_emv_tag_bic = {tag_5f54, 2};
const tlv_tag_t tlv_emv_tag_issuer_country_alpha2 = {tag_5f55, 2};
const tlv_tag_t tlv_emv_tag_issuer_country_alpha3 = {tag_5f56, 2};
const tlv_tag_t tlv_emv_tag_account_type = {tag_5f57, 2};
const tlv_tag_t tlv_emv_tag_biometric_information_template = {tag_7f60, 2};
const tlv_tag_t tlv_emv_tag_acquirer_identifier = {tag_9f01, 2};
const tlv_tag_t tlv_emv_tag_amount_authorised = {tag_9f02, 2};
const tlv_tag_t tlv_emv_tag_amount_other = {tag_9f03, 2};
const tlv_tag_t tlv_emv_tag_amount_other_binary = {tag_9f04, 2};
const tlv_tag_t tlv_emv_tag_application_discretionary_data = {tag_9f05, 2};
const tlv_tag_t tlv_emv_tag_aid_terminal = {tag_9f06, 2};
const tlv_tag_t tlv_emv_tag_application_usage_control = {tag_9f07, 2};
const tlv_tag_t tlv_emv_tag_application_version_card = {tag_9f08, 2};
const tlv_tag_t tlv_emv_tag_application_version_terminal = {tag_9f09, 2};
const tlv_tag_t tlv_emv_tag_asrpd = {tag_9f0a, 2};
const tlv_tag_t tlv_emv_tag_cardholder_name_extended = {tag_9f0b, 2};
const tlv_tag_t tlv_emv_tag_iin_extended = {tag_9f0c, 2};
const tlv_tag_t tlv_emv_tag_issuer_action_code_default = {tag_9f0d, 2};
const tlv_tag_t tlv_emv_tag_issuer_action_code_denial = {tag_9f0e, 2};
const tlv_tag_t tlv_emv_tag_issuer_action_code_online = {tag_9f0f, 2};
const tlv_tag_t tlv_emv_tag_issuer_application_data = {tag_9f10, 2};
const tlv_tag_t tlv_emv_tag_issuer_code_table_index = {tag_9f11, 2};
const tlv_tag_t tlv_emv_tag_application_preferred_name = {tag_9f12, 2};
const tlv_tag_t tlv_emv_tag_last_online_atc = {tag_9f13, 2};
const tlv_tag_t tlv_emv_tag_lower_consecutive_offline_limit = {tag_9f14, 2};
const tlv_tag_t tlv_emv_tag_merchant_category_code = {tag_9f15, 2};
const tlv_tag_t tlv_emv_tag_merchant_identifier = {tag_9f16, 2};
const tlv_tag_t tlv_emv_tag_pin_try_counter = {tag_9f17, 2};
const tlv_tag_t tlv_emv_tag_issuer_script_identifier = {tag_9f18, 2};
const tlv_tag_t tlv_emv_tag_token_requestor_id = {tag_9f19, 2};
const tlv_tag_t tlv_emv_tag_terminal_country_code = {tag_9f1a, 2};
const tlv_tag_t tlv_emv_tag_terminal_floor_limit = {tag_9f1b, 2};
const tlv_tag_t tlv_emv_tag_terminal_identification = {tag_9f1c, 2};
const tlv_tag_t tlv_emv_tag_terminal_risk_management_data = {tag_9f1d, 2};
const tlv_tag_t tlv_emv_tag_ifd_serial_number = {tag_9f1e, 2};
const tlv_tag_t tlv_emv_tag_track1_discretionary_data = {tag_9f1f, 2};
const tlv_tag_t tlv_emv_tag_track2_discretionary_data = {tag_9f20, 2};
const tlv_tag_t tlv_emv_tag_transaction_time = {tag_9f21, 2};
const tlv_tag_t tlv_emv_tag_ca_public_key_index_terminal = {tag_9f22, 2};
const tlv_tag_t tlv_emv_tag_upper_consecutive_offline_limit = {tag_9f23, 2};
const tlv_tag_t tlv_emv_tag_payment_account_reference = {tag_9f24, 2};
const tlv_tag_t tlv_emv_tag_last4_pan = {tag_9f25, 2};
const tlv_tag_t tlv_emv_tag_application_cryptogram = {tag_9f26, 2};
const tlv_tag_t tlv_emv_tag_cryptogram_information_data = {tag_9f27, 2};
const tlv_tag_t tlv_emv_tag_icc_pin_public_key_certificate = {tag_9f2d, 2};
const tlv_tag_t tlv_emv_tag_icc_pin_public_key_exponent = {tag_9f2e, 2};
const tlv_tag_t tlv_emv_tag_icc_pin_public_key_remainder = {tag_9f2f, 2};
const tlv_tag_t tlv_emv_tag_biometric_terminal_capabilities = {tag_9f30, 2};
const tlv_tag_t tlv_emv_tag_card_bit_group_template = {tag_9f31, 2};
const tlv_tag_t tlv_emv_tag_issuer_public_key_exponent = {tag_9f32, 2};
const tlv_tag_t tlv_emv_tag_terminal_capabilities = {tag_9f33, 2};
const tlv_tag_t tlv_emv_tag_cvm_results = {tag_9f34, 2};
const tlv_tag_t tlv_emv_tag_terminal_type = {tag_9f35, 2};
const tlv_tag_t tlv_emv_tag_atc = {tag_9f36, 2};
const tlv_tag_t tlv_emv_tag_unpredictable_number = {tag_9f37, 2};
const tlv_tag_t tlv_emv_tag_pdol = {tag_9f38, 2};
const tlv_tag_t tlv_emv_tag_pos_entry_mode = {tag_9f39, 2};
const tlv_tag_t tlv_emv_tag_amount_reference_currency = {tag_9f3a, 2};
const tlv_tag_t tlv_emv_tag_application_reference_currency = {tag_9f3b, 2};
const tlv_tag_t tlv_emv_tag_transaction_reference_currency_code = {tag_9f3c, 2};
const tlv_tag_t tlv_emv_tag_transaction_reference_currency_exponent = {tag_9f3d, 2};
const tlv_tag_t tlv_emv_tag_additional_terminal_capabilities = {tag_9f40, 2};
const tlv_tag_t tlv_emv_tag_transaction_sequence_counter = {tag_9f41, 2};
const tlv_tag_t tlv_emv_tag_application_currency_code = {tag_9f42, 2};
const tlv_tag_t tlv_emv_tag_application_reference_currency_exponent = {tag_9f43, 2};
const tlv_tag_t tlv_emv_tag_application_currency_exponent = {tag_9f44, 2};
const tlv_tag_t tlv_emv_tag_data_authentication_code = {tag_9f45, 2};
const tlv_tag_t tlv_emv_tag_icc_public_key_certificate = {tag_9f46, 2};
const tlv_tag_t tlv_emv_tag_icc_public_key_exponent = {tag_9f47, 2};
const tlv_tag_t tlv_emv_tag_icc_public_key_remainder = {tag_9f48, 2};
const tlv_tag_t tlv_emv_tag_ddol = {tag_9f49, 2};
const tlv_tag_t tlv_emv_tag_sda_tag_list = {tag_9f4a, 2};
const tlv_tag_t tlv_emv_tag_signed_dynamic_application_data = {tag_9f4b, 2};
const tlv_tag_t tlv_emv_tag_icc_dynamic_number = {tag_9f4c, 2};
const tlv_tag_t tlv_emv_tag_log_entry = {tag_9f4d, 2};
const tlv_tag_t tlv_emv_tag_merchant_name_and_location = {tag_9f4e, 2};
const tlv_tag_t tlv_emv_tag_log_format = {tag_9f4f, 2};
const tlv_tag_t tlv_emv_tag_fci_issuer_discretionary_data = {tag_bf0c, 2};
const tlv_tag_t tlv_emv_tag_offline_bit_group_template = {tag_bf4a, 2};
const tlv_tag_t tlv_emv_tag_online_bit_group_template = {tag_bf4b, 2};
const tlv_tag_t tlv_emv_tag_biometric_try_counters_template = {tag_bf4c, 2};
const tlv_tag_t tlv_emv_tag_preferred_attempts_template = {tag_bf4d, 2};
const tlv_tag_t tlv_emv_tag_biometric_verification_data_template = {tag_bf4e, 2};
const tlv_tag_t tlv_emv_tag_biometric_header_template = {tag_a1, 1};
const tlv_tag_t tlv_emv_tag_biometric_header_version = {tag_80, 1};
const tlv_tag_t tlv_emv_tag_biometric_type = {tag_81, 1};
const tlv_tag_t tlv_emv_tag_biometric_subtype = {tag_82, 1};
const tlv_tag_t tlv_emv_tag_biometric_creation_datetime = {tag_83, 1};
const tlv_tag_t tlv_emv_tag_biometric_creator = {tag_84, 1};
const tlv_tag_t tlv_emv_tag_biometric_validity_period = {tag_85, 1};
const tlv_tag_t tlv_emv_tag_biometric_product_id = {tag_86, 1};
const tlv_tag_t tlv_emv_tag_biometric_format_owner = {tag_87, 1};
const tlv_tag_t tlv_emv_tag_biometric_format_type = {tag_88, 1};
const tlv_tag_t tlv_emv_tag_biometric_solution_id = {tag_90, 1};
const tlv_tag_t tlv_emv_tag_biometric_matching_parameters = {tag_91, 1};
const tlv_tag_t tlv_emv_tag_bht1 = {tag_a1, 1};
const tlv_tag_t tlv_emv_tag_bht2 = {tag_a2, 1};
const tlv_tag_t tlv_emv_tag_biometric_matching_parameters_template = {tag_b1, 1};
const tlv_tag_t tlv_emv_tag_bht_format_owner = {tag_87, 1};
const tlv_tag_t tlv_emv_tag_bht_format_type = {tag_88, 1};
const tlv_tag_t tlv_emv_tag_bit_count = {tag_02, 1};
const tlv_tag_t tlv_emv_tag_group_bit = {tag_7f60, 2};
const tlv_tag_t tlv_emv_tag_facial_try_counter = {tag_df50, 2};
const tlv_tag_t tlv_emv_tag_finger_try_counter = {tag_df51, 2};
const tlv_tag_t tlv_emv_tag_iris_try_counter = {tag_df52, 2};
const tlv_tag_t tlv_emv_tag_palm_try_counter = {tag_df53, 2};
const tlv_tag_t tlv_emv_tag_voice_try_counter = {tag_df54, 2};
const tlv_tag_t tlv_emv_tag_preferred_facial_attempts = {tag_df50, 2};
const tlv_tag_t tlv_emv_tag_preferred_finger_attempts = {tag_df51, 2};
const tlv_tag_t tlv_emv_tag_preferred_iris_attempts = {tag_df52, 2};
const tlv_tag_t tlv_emv_tag_preferred_palm_attempts = {tag_df53, 2};
const tlv_tag_t tlv_emv_tag_preferred_voice_attempts = {tag_df54, 2};
const tlv_tag_t tlv_emv_tag_verification_biometric_type = {tag_81, 1};
const tlv_tag_t tlv_emv_tag_verification_biometric_solution_id = {tag_90, 1};
const tlv_tag_t tlv_emv_tag_enciphered_biometric_key_seed = {tag_df50, 2};
const tlv_tag_t tlv_emv_tag_enciphered_biometric_data = {tag_df51, 2};
const tlv_tag_t tlv_emv_tag_biometric_data_mac = {tag_df52, 2};

const tlv_schema_entry_t emv_base_fields[] = {
    [index_iin] = {{tag_42, 1}, 3, 3, 0, "iin", 0},
    [index_adf_name] = {{tag_4f, 1}, 5, 16, 0, "adf_name", 0},
    [index_application_label] = {{tag_50, 1}, 1, 16, 0, "application_label", 0},
    [index_track2_equivalent_data] = {{tag_57, 1}, 0, 19, 0, "track2_equivalent_data", 0},
    [index_pan] = {{tag_5a, 1}, 1, 10, 0, "pan", 0},
    [index_application_template] = {{tag_61, 1}, 0, 252, 0, "application_template", 0},
    [index_fci_template] = {{tag_6f, 1}, 0, 252, 0, "fci_template", 0},
    [index_read_record_template] = {{tag_70, 1}, 0, 252, 0, "read_record_template", 0},
    [index_issuer_script_template1] = {{tag_71, 1}, 0, SIZE_MAX, 0, "issuer_script_template1", 0},
    [index_issuer_script_template2] = {{tag_72, 1}, 0, SIZE_MAX, 0, "issuer_script_template2", 0},
    [index_directory_discretionary_template] =
        {{tag_73, 1}, 0, 252, 0, "directory_discretionary_template", 0},
    [index_response_template2] = {{tag_77, 1}, 0, SIZE_MAX, 0, "response_template2", 0},
    [index_response_template1] = {{tag_80, 1}, 0, SIZE_MAX, 0, "response_template1", 0},
    [index_amount_authorised_binary] = {{tag_81, 1}, 4, 4, 0, "amount_authorised_binary", 0},
    [index_aip] = {{tag_82, 1}, 2, 2, 0, "aip", 0},
    [index_command_template] = {{tag_83, 1}, 0, SIZE_MAX, 0, "command_template", 0},
    [index_df_name] = {{tag_84, 1}, 5, 16, 0, "df_name", 0},
    [index_issuer_script_command] = {{tag_86, 1}, 0, 261, 0, "issuer_script_command", 0},
    [index_application_priority_indicator] =
        {{tag_87, 1}, 1, 1, 0, "application_priority_indicator", 0},
    [index_sfi] = {{tag_88, 1}, 1, 1, 0, "sfi", 0},
    [index_authorisation_code] = {{tag_89, 1}, 6, 6, 0, "authorisation_code", 0},
    [index_authorisation_response_code] = {{tag_8a, 1}, 2, 2, 0, "authorisation_response_code", 0},
    [index_cdol1] = {{tag_8c, 1}, 0, 252, 0, "cdol1", 0},
    [index_cdol2] = {{tag_8d, 1}, 0, 252, 0, "cdol2", 0},
    [index_cvm_list] = {{tag_8e, 1}, 10, 252, 0, "cvm_list", 2},
    [index_ca_public_key_index] = {{tag_8f, 1}, 1, 1, 0, "ca_public_key_index", 0},
    [index_issuer_public_key_certificate] =
        {{tag_90, 1}, 1, SIZE_MAX, 0, "issuer_public_key_certificate", 0},
    [index_issuer_authentication_data] = {{tag_91, 1}, 8, 16, 0, "issuer_authentication_data", 0},
    [index_issuer_public_key_remainder] =
        {{tag_92, 1}, 1, SIZE_MAX, 0, "issuer_public_key_remainder", 0},
    [index_signed_static_application_data] =
        {{tag_93, 1}, 1, SIZE_MAX, 0, "signed_static_application_data", 0},
    [index_afl] = {{tag_94, 1}, 4, 252, 0, "afl", 4},
    [index_tvr] = {{tag_95, 1}, 5, 5, 0, "tvr", 0},
    [index_tdol] = {{tag_97, 1}, 0, 252, 0, "tdol", 0},
    [index_tc_hash_value] = {{tag_98, 1}, 20, 20, 0, "tc_hash_value", 0},
    [index_transaction_pin_data] = {{tag_99, 1}, 0, SIZE_MAX, 0, "transaction_pin_data", 0},
    [index_transaction_date] = {{tag_9a, 1}, 3, 3, 0, "transaction_date", 0},
    [index_tsi] = {{tag_9b, 1}, 2, 2, 0, "tsi", 0},
    [index_transaction_type] = {{tag_9c, 1}, 1, 1, 0, "transaction_type", 0},
    [index_ddf_name] = {{tag_9d, 1}, 5, 16, 0, "ddf_name", 0},
    [index_fci_proprietary_template] = {{tag_a5, 1}, 0, SIZE_MAX, 0, "fci_proprietary_template", 0},
    [index_cardholder_name] = {{tag_5f20, 2}, 2, 26, 0, "cardholder_name", 0},
    [index_application_expiration_date] =
        {{tag_5f24, 2}, 3, 3, 0, "application_expiration_date", 0},
    [index_application_effective_date] = {{tag_5f25, 2}, 3, 3, 0, "application_effective_date", 0},
    [index_issuer_country_code] = {{tag_5f28, 2}, 2, 2, 0, "issuer_country_code", 0},
    [index_transaction_currency_code] = {{tag_5f2a, 2}, 2, 2, 0, "transaction_currency_code", 0},
    [index_language_preference] = {{tag_5f2d, 2}, 2, 8, 0, "language_preference", 2},
    [index_service_code] = {{tag_5f30, 2}, 2, 2, 0, "service_code", 0},
    [index_pan_sequence_number] = {{tag_5f34, 2}, 1, 1, 0, "pan_sequence_number", 0},
    [index_transaction_currency_exponent] =
        {{tag_5f36, 2}, 1, 1, 0, "transaction_currency_exponent", 0},
    [index_issuer_url] = {{tag_5f50, 2}, 0, SIZE_MAX, 0, "issuer_url", 0},
    [index_iban] = {{tag_5f53, 2}, 0, 34, 0, "iban", 0},
    [index_bic] = {{tag_5f54, 2}, 8, 11, TLV_SCHEMA_LENGTH_ENDPOINTS, "bic", 0},
    [index_issuer_country_alpha2] = {{tag_5f55, 2}, 2, 2, 0, "issuer_country_alpha2", 0},
    [index_issuer_country_alpha3] = {{tag_5f56, 2}, 3, 3, 0, "issuer_country_alpha3", 0},
    [index_account_type] = {{tag_5f57, 2}, 1, 1, 0, "account_type", 0},
    [index_biometric_information_template] =
        {{tag_7f60, 2}, 0, SIZE_MAX, 0, "biometric_information_template", 0},
    [index_acquirer_identifier] = {{tag_9f01, 2}, 6, 6, 0, "acquirer_identifier", 0},
    [index_amount_authorised] = {{tag_9f02, 2}, 6, 6, 0, "amount_authorised", 0},
    [index_amount_other] = {{tag_9f03, 2}, 6, 6, 0, "amount_other", 0},
    [index_amount_other_binary] = {{tag_9f04, 2}, 4, 4, 0, "amount_other_binary", 0},
    [index_application_discretionary_data] =
        {{tag_9f05, 2}, 1, 32, 0, "application_discretionary_data", 0},
    [index_aid_terminal] = {{tag_9f06, 2}, 5, 16, 0, "aid_terminal", 0},
    [index_application_usage_control] = {{tag_9f07, 2}, 2, 2, 0, "application_usage_control", 0},
    [index_application_version_card] = {{tag_9f08, 2}, 2, 2, 0, "application_version_card", 0},
    [index_application_version_terminal] =
        {{tag_9f09, 2}, 2, 2, 0, "application_version_terminal", 0},
    [index_asrpd] = {{tag_9f0a, 2}, 0, SIZE_MAX, 0, "asrpd", 0},
    [index_cardholder_name_extended] = {{tag_9f0b, 2}, 27, 45, 0, "cardholder_name_extended", 0},
    [index_iin_extended] = {{tag_9f0c, 2}, 3, 4, 0, "iin_extended", 0},
    [index_issuer_action_code_default] = {{tag_9f0d, 2}, 5, 5, 0, "issuer_action_code_default", 0},
    [index_issuer_action_code_denial] = {{tag_9f0e, 2}, 5, 5, 0, "issuer_action_code_denial", 0},
    [index_issuer_action_code_online] = {{tag_9f0f, 2}, 5, 5, 0, "issuer_action_code_online", 0},
    [index_issuer_application_data] = {{tag_9f10, 2}, 0, 32, 0, "issuer_application_data", 0},
    [index_issuer_code_table_index] = {{tag_9f11, 2}, 1, 1, 0, "issuer_code_table_index", 0},
    [index_application_preferred_name] = {{tag_9f12, 2}, 1, 16, 0, "application_preferred_name", 0},
    [index_last_online_atc] = {{tag_9f13, 2}, 2, 2, 0, "last_online_atc", 0},
    [index_lower_consecutive_offline_limit] =
        {{tag_9f14, 2}, 1, 1, 0, "lower_consecutive_offline_limit", 0},
    [index_merchant_category_code] = {{tag_9f15, 2}, 2, 2, 0, "merchant_category_code", 0},
    [index_merchant_identifier] = {{tag_9f16, 2}, 15, 15, 0, "merchant_identifier", 0},
    [index_pin_try_counter] = {{tag_9f17, 2}, 1, 1, 0, "pin_try_counter", 0},
    [index_issuer_script_identifier] = {{tag_9f18, 2}, 4, 4, 0, "issuer_script_identifier", 0},
    [index_token_requestor_id] = {{tag_9f19, 2}, 6, 6, 0, "token_requestor_id", 0},
    [index_terminal_country_code] = {{tag_9f1a, 2}, 2, 2, 0, "terminal_country_code", 0},
    [index_terminal_floor_limit] = {{tag_9f1b, 2}, 4, 4, 0, "terminal_floor_limit", 0},
    [index_terminal_identification] = {{tag_9f1c, 2}, 8, 8, 0, "terminal_identification", 0},
    [index_terminal_risk_management_data] =
        {{tag_9f1d, 2}, 1, 8, 0, "terminal_risk_management_data", 0},
    [index_ifd_serial_number] = {{tag_9f1e, 2}, 8, 8, 0, "ifd_serial_number", 0},
    [index_track1_discretionary_data] =
        {{tag_9f1f, 2}, 0, SIZE_MAX, 0, "track1_discretionary_data", 0},
    [index_track2_discretionary_data] =
        {{tag_9f20, 2}, 0, SIZE_MAX, 0, "track2_discretionary_data", 0},
    [index_transaction_time] = {{tag_9f21, 2}, 3, 3, 0, "transaction_time", 0},
    [index_ca_public_key_index_terminal] =
        {{tag_9f22, 2}, 1, 1, 0, "ca_public_key_index_terminal", 0},
    [index_upper_consecutive_offline_limit] =
        {{tag_9f23, 2}, 1, 1, 0, "upper_consecutive_offline_limit", 0},
    [index_payment_account_reference] = {{tag_9f24, 2}, 29, 29, 0, "payment_account_reference", 0},
    [index_last4_pan] = {{tag_9f25, 2}, 2, 2, 0, "last4_pan", 0},
    [index_application_cryptogram] = {{tag_9f26, 2}, 8, 8, 0, "application_cryptogram", 0},
    [index_cryptogram_information_data] =
        {{tag_9f27, 2}, 1, 1, 0, "cryptogram_information_data", 0},
    [index_icc_pin_public_key_certificate] =
        {{tag_9f2d, 2}, 1, SIZE_MAX, 0, "icc_pin_public_key_certificate", 0},
    [index_icc_pin_public_key_exponent] =
        {{tag_9f2e, 2}, 1, 3, TLV_SCHEMA_LENGTH_ENDPOINTS, "icc_pin_public_key_exponent", 0},
    [index_icc_pin_public_key_remainder] =
        {{tag_9f2f, 2}, 1, SIZE_MAX, 0, "icc_pin_public_key_remainder", 0},
    [index_biometric_terminal_capabilities] =
        {{tag_9f30, 2}, 3, 3, 0, "biometric_terminal_capabilities", 0},
    [index_card_bit_group_template] = {{tag_9f31, 2}, 0, SIZE_MAX, 0, "card_bit_group_template", 0},
    [index_issuer_public_key_exponent] =
        {{tag_9f32, 2}, 1, 3, TLV_SCHEMA_LENGTH_ENDPOINTS, "issuer_public_key_exponent", 0},
    [index_terminal_capabilities] = {{tag_9f33, 2}, 3, 3, 0, "terminal_capabilities", 0},
    [index_cvm_results] = {{tag_9f34, 2}, 3, 3, 0, "cvm_results", 0},
    [index_terminal_type] = {{tag_9f35, 2}, 1, 1, 0, "terminal_type", 0},
    [index_atc] = {{tag_9f36, 2}, 2, 2, 0, "atc", 0},
    [index_unpredictable_number] = {{tag_9f37, 2}, 4, 4, 0, "unpredictable_number", 0},
    [index_pdol] = {{tag_9f38, 2}, 0, SIZE_MAX, 0, "pdol", 0},
    [index_pos_entry_mode] = {{tag_9f39, 2}, 1, 1, 0, "pos_entry_mode", 0},
    [index_amount_reference_currency] = {{tag_9f3a, 2}, 4, 4, 0, "amount_reference_currency", 0},
    [index_application_reference_currency] =
        {{tag_9f3b, 2}, 2, 8, 0, "application_reference_currency", 2},
    [index_transaction_reference_currency_code] =
        {{tag_9f3c, 2}, 2, 2, 0, "transaction_reference_currency_code", 0},
    [index_transaction_reference_currency_exponent] =
        {{tag_9f3d, 2}, 1, 1, 0, "transaction_reference_currency_exponent", 0},
    [index_additional_terminal_capabilities] =
        {{tag_9f40, 2}, 5, 5, 0, "additional_terminal_capabilities", 0},
    [index_transaction_sequence_counter] =
        {{tag_9f41, 2}, 2, 4, 0, "transaction_sequence_counter", 0},
    [index_application_currency_code] = {{tag_9f42, 2}, 2, 2, 0, "application_currency_code", 0},
    [index_application_reference_currency_exponent] =
        {{tag_9f43, 2}, 1, 4, 0, "application_reference_currency_exponent", 0},
    [index_application_currency_exponent] =
        {{tag_9f44, 2}, 1, 1, 0, "application_currency_exponent", 0},
    [index_data_authentication_code] = {{tag_9f45, 2}, 2, 2, 0, "data_authentication_code", 0},
    [index_icc_public_key_certificate] =
        {{tag_9f46, 2}, 1, SIZE_MAX, 0, "icc_public_key_certificate", 0},
    [index_icc_public_key_exponent] =
        {{tag_9f47, 2}, 1, 3, TLV_SCHEMA_LENGTH_ENDPOINTS, "icc_public_key_exponent", 0},
    [index_icc_public_key_remainder] =
        {{tag_9f48, 2}, 1, SIZE_MAX, 0, "icc_public_key_remainder", 0},
    [index_ddol] = {{tag_9f49, 2}, 0, 252, 0, "ddol", 0},
    [index_sda_tag_list] = {{tag_9f4a, 2}, 0, SIZE_MAX, 0, "sda_tag_list", 0},
    [index_signed_dynamic_application_data] =
        {{tag_9f4b, 2}, 1, SIZE_MAX, 0, "signed_dynamic_application_data", 0},
    [index_icc_dynamic_number] = {{tag_9f4c, 2}, 2, 8, 0, "icc_dynamic_number", 0},
    [index_log_entry] = {{tag_9f4d, 2}, 2, 2, 0, "log_entry", 0},
    [index_merchant_name_and_location] =
        {{tag_9f4e, 2}, 0, SIZE_MAX, 0, "merchant_name_and_location", 0},
    [index_log_format] = {{tag_9f4f, 2}, 0, SIZE_MAX, 0, "log_format", 0},
    [index_fci_issuer_discretionary_data] =
        {{tag_bf0c, 2}, 0, 222, 0, "fci_issuer_discretionary_data", 0},
    [index_offline_bit_group_template] =
        {{tag_bf4a, 2}, 0, SIZE_MAX, 0, "offline_bit_group_template", 0},
    [index_online_bit_group_template] =
        {{tag_bf4b, 2}, 0, SIZE_MAX, 0, "online_bit_group_template", 0},
    [index_biometric_try_counters_template] =
        {{tag_bf4c, 2}, 0, SIZE_MAX, 0, "biometric_try_counters_template", 0},
    [index_preferred_attempts_template] =
        {{tag_bf4d, 2}, 0, SIZE_MAX, 0, "preferred_attempts_template", 0},
    [index_biometric_verification_data_template] =
        {{tag_bf4e, 2}, 0, SIZE_MAX, 0, "biometric_verification_data_template", 0},
};
static const tlv_schema_number_t codec_iin_rule = {&emv_base_fields[index_iin],
                                                   {TLV_NUMBER_BCD, 0, 6}};
static const tlv_codec_t codec_iin = {&codec_iin_rule, tlv_schema_number_decode,
                                      tlv_schema_number_encode};
static const emv_value_rule_t codec_track2_equivalent_data_rule = {
    &emv_base_fields[index_track2_equivalent_data], EMV_REP_TRACK2, 0};
static const tlv_codec_t codec_track2_equivalent_data = {&codec_track2_equivalent_data_rule,
                                                         emv_value_decode, emv_value_encode};
static const emv_value_rule_t codec_pan_rule = {&emv_base_fields[index_pan], EMV_REP_DIGITS, 19};
static const tlv_codec_t codec_pan = {&codec_pan_rule, emv_value_decode, emv_value_encode};
static const tlv_schema_number_t codec_amount_authorised_binary_rule = {
    &emv_base_fields[index_amount_authorised_binary], {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_amount_authorised_binary = {
    &codec_amount_authorised_binary_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const tlv_schema_number_t codec_aip_rule = {&emv_base_fields[index_aip],
                                                   {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_aip = {&codec_aip_rule, tlv_schema_number_decode,
                                      tlv_schema_number_encode};
static const tlv_schema_number_t codec_application_priority_indicator_rule = {
    &emv_base_fields[index_application_priority_indicator], {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_application_priority_indicator = {
    &codec_application_priority_indicator_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const tlv_schema_number_t codec_sfi_rule = {&emv_base_fields[index_sfi],
                                                   {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_sfi = {&codec_sfi_rule, tlv_schema_number_decode,
                                      tlv_schema_number_encode};
static const tlv_schema_number_t codec_ca_public_key_index_rule = {
    &emv_base_fields[index_ca_public_key_index], {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_ca_public_key_index = {
    &codec_ca_public_key_index_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const emv_value_rule_t codec_afl_rule = {&emv_base_fields[index_afl], EMV_REP_AFL, 0};
static const tlv_codec_t codec_afl = {&codec_afl_rule, emv_value_decode, emv_value_encode};
static const tlv_schema_number_t codec_tvr_rule = {&emv_base_fields[index_tvr],
                                                   {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_tvr = {&codec_tvr_rule, tlv_schema_number_decode,
                                      tlv_schema_number_encode};
static const emv_value_rule_t codec_transaction_date_rule = {
    &emv_base_fields[index_transaction_date], EMV_REP_DATE, 0};
static const tlv_codec_t codec_transaction_date = {&codec_transaction_date_rule, emv_value_decode,
                                                   emv_value_encode};
static const tlv_schema_number_t codec_tsi_rule = {&emv_base_fields[index_tsi],
                                                   {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_tsi = {&codec_tsi_rule, tlv_schema_number_decode,
                                      tlv_schema_number_encode};
static const tlv_schema_number_t codec_transaction_type_rule = {
    &emv_base_fields[index_transaction_type], {TLV_NUMBER_BCD, 0, 2}};
static const tlv_codec_t codec_transaction_type = {
    &codec_transaction_type_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const emv_value_rule_t codec_application_expiration_date_rule = {
    &emv_base_fields[index_application_expiration_date], EMV_REP_DATE, 0};
static const tlv_codec_t codec_application_expiration_date = {
    &codec_application_expiration_date_rule, emv_value_decode, emv_value_encode};
static const emv_value_rule_t codec_application_effective_date_rule = {
    &emv_base_fields[index_application_effective_date], EMV_REP_DATE, 0};
static const tlv_codec_t codec_application_effective_date = {&codec_application_effective_date_rule,
                                                             emv_value_decode, emv_value_encode};
static const tlv_schema_number_t codec_issuer_country_code_rule = {
    &emv_base_fields[index_issuer_country_code], {TLV_NUMBER_BCD, 0, 3}};
static const tlv_codec_t codec_issuer_country_code = {
    &codec_issuer_country_code_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const tlv_schema_number_t codec_transaction_currency_code_rule = {
    &emv_base_fields[index_transaction_currency_code], {TLV_NUMBER_BCD, 0, 3}};
static const tlv_codec_t codec_transaction_currency_code = {
    &codec_transaction_currency_code_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const tlv_schema_number_t codec_service_code_rule = {&emv_base_fields[index_service_code],
                                                            {TLV_NUMBER_BCD, 0, 3}};
static const tlv_codec_t codec_service_code = {&codec_service_code_rule, tlv_schema_number_decode,
                                               tlv_schema_number_encode};
static const tlv_schema_number_t codec_pan_sequence_number_rule = {
    &emv_base_fields[index_pan_sequence_number], {TLV_NUMBER_BCD, 0, 2}};
static const tlv_codec_t codec_pan_sequence_number = {
    &codec_pan_sequence_number_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const tlv_schema_number_t codec_transaction_currency_exponent_rule = {
    &emv_base_fields[index_transaction_currency_exponent], {TLV_NUMBER_BCD, 0, 1}};
static const tlv_codec_t codec_transaction_currency_exponent = {
    &codec_transaction_currency_exponent_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const emv_value_rule_t codec_account_type_rule = {&emv_base_fields[index_account_type],
                                                         EMV_REP_ACCOUNT, 0};
static const tlv_codec_t codec_account_type = {&codec_account_type_rule, emv_value_decode,
                                               emv_value_encode};
static const tlv_schema_number_t codec_acquirer_identifier_rule = {
    &emv_base_fields[index_acquirer_identifier], {TLV_NUMBER_BCD, 0, 11}};
static const tlv_codec_t codec_acquirer_identifier = {
    &codec_acquirer_identifier_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const tlv_schema_number_t codec_amount_authorised_rule = {
    &emv_base_fields[index_amount_authorised], {TLV_NUMBER_BCD, 0, 12}};
const tlv_codec_t tlv_emv_codec_amount = {&codec_amount_authorised_rule, tlv_schema_number_decode,
                                          tlv_schema_number_encode};
static const tlv_schema_number_t codec_amount_other_rule = {&emv_base_fields[index_amount_other],
                                                            {TLV_NUMBER_BCD, 0, 12}};
static const tlv_codec_t codec_amount_other = {&codec_amount_other_rule, tlv_schema_number_decode,
                                               tlv_schema_number_encode};
static const tlv_schema_number_t codec_amount_other_binary_rule = {
    &emv_base_fields[index_amount_other_binary], {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_amount_other_binary = {
    &codec_amount_other_binary_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const tlv_schema_number_t codec_application_usage_control_rule = {
    &emv_base_fields[index_application_usage_control], {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_application_usage_control = {
    &codec_application_usage_control_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const tlv_schema_number_t codec_application_version_card_rule = {
    &emv_base_fields[index_application_version_card], {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_application_version_card = {
    &codec_application_version_card_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const tlv_schema_number_t codec_application_version_terminal_rule = {
    &emv_base_fields[index_application_version_terminal], {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_application_version_terminal = {
    &codec_application_version_terminal_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const tlv_schema_number_t codec_iin_extended_rule = {&emv_base_fields[index_iin_extended],
                                                            {TLV_NUMBER_BCD, 0, 8}};
static const tlv_codec_t codec_iin_extended = {&codec_iin_extended_rule, tlv_schema_number_decode,
                                               tlv_schema_number_encode};
static const tlv_schema_number_t codec_issuer_action_code_default_rule = {
    &emv_base_fields[index_issuer_action_code_default], {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_issuer_action_code_default = {
    &codec_issuer_action_code_default_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const tlv_schema_number_t codec_issuer_action_code_denial_rule = {
    &emv_base_fields[index_issuer_action_code_denial], {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_issuer_action_code_denial = {
    &codec_issuer_action_code_denial_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const tlv_schema_number_t codec_issuer_action_code_online_rule = {
    &emv_base_fields[index_issuer_action_code_online], {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_issuer_action_code_online = {
    &codec_issuer_action_code_online_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const tlv_schema_number_t codec_issuer_code_table_index_rule = {
    &emv_base_fields[index_issuer_code_table_index], {TLV_NUMBER_BCD, 0, 2}};
static const tlv_codec_t codec_issuer_code_table_index = {
    &codec_issuer_code_table_index_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const tlv_schema_number_t codec_last_online_atc_rule = {
    &emv_base_fields[index_last_online_atc], {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_last_online_atc = {
    &codec_last_online_atc_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const tlv_schema_number_t codec_lower_consecutive_offline_limit_rule = {
    &emv_base_fields[index_lower_consecutive_offline_limit], {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_lower_consecutive_offline_limit = {
    &codec_lower_consecutive_offline_limit_rule, tlv_schema_number_decode,
    tlv_schema_number_encode};
static const tlv_schema_number_t codec_merchant_category_code_rule = {
    &emv_base_fields[index_merchant_category_code], {TLV_NUMBER_BCD, 0, 4}};
static const tlv_codec_t codec_merchant_category_code = {
    &codec_merchant_category_code_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const tlv_schema_number_t codec_pin_try_counter_rule = {
    &emv_base_fields[index_pin_try_counter], {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_pin_try_counter = {
    &codec_pin_try_counter_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const tlv_schema_number_t codec_token_requestor_id_rule = {
    &emv_base_fields[index_token_requestor_id], {TLV_NUMBER_BCD, 0, 11}};
static const tlv_codec_t codec_token_requestor_id = {
    &codec_token_requestor_id_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const tlv_schema_number_t codec_terminal_country_code_rule = {
    &emv_base_fields[index_terminal_country_code], {TLV_NUMBER_BCD, 0, 3}};
static const tlv_codec_t codec_terminal_country_code = {
    &codec_terminal_country_code_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const tlv_schema_number_t codec_terminal_floor_limit_rule = {
    &emv_base_fields[index_terminal_floor_limit], {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_terminal_floor_limit = {
    &codec_terminal_floor_limit_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const emv_value_rule_t codec_track2_discretionary_data_rule = {
    &emv_base_fields[index_track2_discretionary_data], EMV_REP_DIGITS, 0};
static const tlv_codec_t codec_track2_discretionary_data = {&codec_track2_discretionary_data_rule,
                                                            emv_value_decode, emv_value_encode};
static const emv_value_rule_t codec_transaction_time_rule = {
    &emv_base_fields[index_transaction_time], EMV_REP_TIME, 0};
static const tlv_codec_t codec_transaction_time = {&codec_transaction_time_rule, emv_value_decode,
                                                   emv_value_encode};
static const tlv_schema_number_t codec_ca_public_key_index_terminal_rule = {
    &emv_base_fields[index_ca_public_key_index_terminal], {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_ca_public_key_index_terminal = {
    &codec_ca_public_key_index_terminal_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const tlv_schema_number_t codec_upper_consecutive_offline_limit_rule = {
    &emv_base_fields[index_upper_consecutive_offline_limit], {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_upper_consecutive_offline_limit = {
    &codec_upper_consecutive_offline_limit_rule, tlv_schema_number_decode,
    tlv_schema_number_encode};
static const tlv_schema_number_t codec_last4_pan_rule = {&emv_base_fields[index_last4_pan],
                                                         {TLV_NUMBER_BCD, 0, 4}};
static const tlv_codec_t codec_last4_pan = {&codec_last4_pan_rule, tlv_schema_number_decode,
                                            tlv_schema_number_encode};
static const emv_value_rule_t codec_cryptogram_information_data_rule = {
    &emv_base_fields[index_cryptogram_information_data], EMV_REP_CRYPTOGRAM, 0};
static const tlv_codec_t codec_cryptogram_information_data = {
    &codec_cryptogram_information_data_rule, emv_value_decode, emv_value_encode};
static const tlv_schema_number_t codec_icc_pin_public_key_exponent_rule = {
    &emv_base_fields[index_icc_pin_public_key_exponent], {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_icc_pin_public_key_exponent = {
    &codec_icc_pin_public_key_exponent_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const tlv_schema_number_t codec_biometric_terminal_capabilities_rule = {
    &emv_base_fields[index_biometric_terminal_capabilities], {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_biometric_terminal_capabilities = {
    &codec_biometric_terminal_capabilities_rule, tlv_schema_number_decode,
    tlv_schema_number_encode};
static const tlv_schema_number_t codec_issuer_public_key_exponent_rule = {
    &emv_base_fields[index_issuer_public_key_exponent], {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_issuer_public_key_exponent = {
    &codec_issuer_public_key_exponent_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const tlv_schema_number_t codec_terminal_capabilities_rule = {
    &emv_base_fields[index_terminal_capabilities], {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_terminal_capabilities = {
    &codec_terminal_capabilities_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const emv_value_rule_t codec_cvm_results_rule = {&emv_base_fields[index_cvm_results],
                                                        EMV_REP_CVM_RESULT, 0};
static const tlv_codec_t codec_cvm_results = {&codec_cvm_results_rule, emv_value_decode,
                                              emv_value_encode};
static const tlv_schema_number_t codec_terminal_type_rule = {&emv_base_fields[index_terminal_type],
                                                             {TLV_NUMBER_BCD, 0, 2}};
static const tlv_codec_t codec_terminal_type = {&codec_terminal_type_rule, tlv_schema_number_decode,
                                                tlv_schema_number_encode};
static const tlv_schema_number_t codec_atc_rule = {&emv_base_fields[index_atc],
                                                   {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_atc = {&codec_atc_rule, tlv_schema_number_decode,
                                      tlv_schema_number_encode};
static const tlv_schema_number_t codec_pos_entry_mode_rule = {
    &emv_base_fields[index_pos_entry_mode], {TLV_NUMBER_BCD, 0, 2}};
static const tlv_codec_t codec_pos_entry_mode = {
    &codec_pos_entry_mode_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const tlv_schema_number_t codec_amount_reference_currency_rule = {
    &emv_base_fields[index_amount_reference_currency], {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_amount_reference_currency = {
    &codec_amount_reference_currency_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const emv_value_rule_t codec_application_reference_currency_rule = {
    &emv_base_fields[index_application_reference_currency], EMV_REP_NUMBER_LIST, 3};
static const tlv_codec_t codec_application_reference_currency = {
    &codec_application_reference_currency_rule, emv_value_decode, emv_value_encode};
static const tlv_schema_number_t codec_transaction_reference_currency_code_rule = {
    &emv_base_fields[index_transaction_reference_currency_code], {TLV_NUMBER_BCD, 0, 3}};
static const tlv_codec_t codec_transaction_reference_currency_code = {
    &codec_transaction_reference_currency_code_rule, tlv_schema_number_decode,
    tlv_schema_number_encode};
static const tlv_schema_number_t codec_transaction_reference_currency_exponent_rule = {
    &emv_base_fields[index_transaction_reference_currency_exponent], {TLV_NUMBER_BCD, 0, 1}};
static const tlv_codec_t codec_transaction_reference_currency_exponent = {
    &codec_transaction_reference_currency_exponent_rule, tlv_schema_number_decode,
    tlv_schema_number_encode};
static const tlv_schema_number_t codec_additional_terminal_capabilities_rule = {
    &emv_base_fields[index_additional_terminal_capabilities], {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_additional_terminal_capabilities = {
    &codec_additional_terminal_capabilities_rule, tlv_schema_number_decode,
    tlv_schema_number_encode};
static const tlv_schema_number_t codec_transaction_sequence_counter_rule = {
    &emv_base_fields[index_transaction_sequence_counter], {TLV_NUMBER_BCD, 0, 8}};
static const tlv_codec_t codec_transaction_sequence_counter = {
    &codec_transaction_sequence_counter_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const tlv_schema_number_t codec_application_currency_code_rule = {
    &emv_base_fields[index_application_currency_code], {TLV_NUMBER_BCD, 0, 3}};
static const tlv_codec_t codec_application_currency_code = {
    &codec_application_currency_code_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const emv_value_rule_t codec_application_reference_currency_exponent_rule = {
    &emv_base_fields[index_application_reference_currency_exponent], EMV_REP_NUMBER_LIST, 1};
static const tlv_codec_t codec_application_reference_currency_exponent = {
    &codec_application_reference_currency_exponent_rule, emv_value_decode, emv_value_encode};
static const tlv_schema_number_t codec_application_currency_exponent_rule = {
    &emv_base_fields[index_application_currency_exponent], {TLV_NUMBER_BCD, 0, 1}};
static const tlv_codec_t codec_application_currency_exponent = {
    &codec_application_currency_exponent_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const tlv_schema_number_t codec_icc_public_key_exponent_rule = {
    &emv_base_fields[index_icc_public_key_exponent], {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_icc_public_key_exponent = {
    &codec_icc_public_key_exponent_rule, tlv_schema_number_decode, tlv_schema_number_encode};

static const tlv_definition_t definition_iin = {{tag_42, 1}, "Issuer Identification Number (IIN)"};
static const tlv_definition_t definition_adf_name = {{tag_4f, 1},
                                                     "Application Dedicated File (ADF) Name"};
static const tlv_definition_t definition_application_label = {{tag_50, 1}, "Application Label"};
static const tlv_definition_t definition_track2_equivalent_data = {{tag_57, 1},
                                                                   "Track2 Equivalent Data"};
static const tlv_definition_t definition_pan = {{tag_5a, 1}, "Primary Account Number (PAN)"};
static const tlv_definition_t definition_application_template = {{tag_61, 1},
                                                                 "Application Template"};
static const tlv_definition_t definition_fci_template = {{tag_6f, 1},
                                                         "File Control Information (FCI) Template"};
static const tlv_definition_t definition_read_record_template = {{tag_70, 1},
                                                                 "Read Record Template"};
static const tlv_definition_t definition_issuer_script_template1 = {{tag_71, 1},
                                                                    "Issuer Script Template1"};
static const tlv_definition_t definition_issuer_script_template2 = {{tag_72, 1},
                                                                    "Issuer Script Template2"};
static const tlv_definition_t definition_directory_discretionary_template = {
    {tag_73, 1}, "Directory Discretionary Template"};
static const tlv_definition_t definition_response_template2 = {{tag_77, 1}, "Response Template2"};
static const tlv_definition_t definition_response_template1 = {{tag_80, 1}, "Response Template1"};
static const tlv_definition_t definition_amount_authorised_binary = {{tag_81, 1},
                                                                     "Amount Authorised Binary"};
static const tlv_definition_t definition_aip = {{tag_82, 1},
                                                "Application Interchange Profile (AIP)"};
static const tlv_definition_t definition_command_template = {{tag_83, 1}, "Command Template"};
static const tlv_definition_t definition_df_name = {{tag_84, 1}, "Dedicated File (DF) Name"};
static const tlv_definition_t definition_issuer_script_command = {{tag_86, 1},
                                                                  "Issuer Script Command"};
static const tlv_definition_t definition_application_priority_indicator = {
    {tag_87, 1}, "Application Priority Indicator"};
static const tlv_definition_t definition_sfi = {{tag_88, 1}, "Short File Identifier (SFI)"};
static const tlv_definition_t definition_authorisation_code = {{tag_89, 1}, "Authorisation Code"};
static const tlv_definition_t definition_authorisation_response_code = {
    {tag_8a, 1}, "Authorisation Response Code"};
static const tlv_definition_t definition_cdol1 = {{tag_8c, 1}, "Cdol1"};
static const tlv_definition_t definition_cdol2 = {{tag_8d, 1}, "Cdol2"};
static const tlv_definition_t definition_cvm_list = {{tag_8e, 1}, "Cvm List"};
static const tlv_definition_t definition_ca_public_key_index = {{tag_8f, 1}, "Ca Public Key Index"};
static const tlv_definition_t definition_issuer_public_key_certificate = {
    {tag_90, 1}, "Issuer Public Key Certificate"};
static const tlv_definition_t definition_issuer_authentication_data = {
    {tag_91, 1}, "Issuer Authentication Data"};
static const tlv_definition_t definition_issuer_public_key_remainder = {
    {tag_92, 1}, "Issuer Public Key Remainder"};
static const tlv_definition_t definition_signed_static_application_data = {
    {tag_93, 1}, "Signed Static Application Data"};
static const tlv_definition_t definition_afl = {{tag_94, 1}, "Application File Locator (AFL)"};
static const tlv_definition_t definition_tvr = {{tag_95, 1}, "Terminal Verification Results (TVR)"};
static const tlv_definition_t definition_tdol = {{tag_97, 1}, "Tdol"};
static const tlv_definition_t definition_tc_hash_value = {{tag_98, 1}, "Tc Hash Value"};
static const tlv_definition_t definition_transaction_pin_data = {{tag_99, 1},
                                                                 "Transaction Pin Data"};
static const tlv_definition_t definition_transaction_date = {{tag_9a, 1}, "Transaction Date"};
static const tlv_definition_t definition_tsi = {{tag_9b, 1},
                                                "Transaction Status Information (TSI)"};
static const tlv_definition_t definition_transaction_type = {{tag_9c, 1}, "Transaction Type"};
static const tlv_definition_t definition_ddf_name = {{tag_9d, 1}, "Ddf Name"};
static const tlv_definition_t definition_fci_proprietary_template = {
    {tag_a5, 1}, "File Control Information (FCI) Proprietary Template"};
static const tlv_definition_t definition_cardholder_name = {{tag_5f20, 2}, "Cardholder Name"};
static const tlv_definition_t definition_application_expiration_date = {
    {tag_5f24, 2}, "Application Expiration Date"};
static const tlv_definition_t definition_application_effective_date = {
    {tag_5f25, 2}, "Application Effective Date"};
static const tlv_definition_t definition_issuer_country_code = {{tag_5f28, 2},
                                                                "Issuer Country Code"};
static const tlv_definition_t definition_transaction_currency_code = {{tag_5f2a, 2},
                                                                      "Transaction Currency Code"};
static const tlv_definition_t definition_language_preference = {{tag_5f2d, 2},
                                                                "Language Preference"};
static const tlv_definition_t definition_service_code = {{tag_5f30, 2}, "Service Code"};
static const tlv_definition_t definition_pan_sequence_number = {{tag_5f34, 2},
                                                                "Pan Sequence Number"};
static const tlv_definition_t definition_transaction_currency_exponent = {
    {tag_5f36, 2}, "Transaction Currency Exponent"};
static const tlv_definition_t definition_issuer_url = {{tag_5f50, 2}, "Issuer Url"};
static const tlv_definition_t definition_iban = {{tag_5f53, 2}, "Iban"};
static const tlv_definition_t definition_bic = {{tag_5f54, 2}, "Bic"};
static const tlv_definition_t definition_issuer_country_alpha2 = {{tag_5f55, 2},
                                                                  "Issuer Country Alpha2"};
static const tlv_definition_t definition_issuer_country_alpha3 = {{tag_5f56, 2},
                                                                  "Issuer Country Alpha3"};
static const tlv_definition_t definition_account_type = {{tag_5f57, 2}, "Account Type"};
static const tlv_definition_t definition_biometric_information_template = {
    {tag_7f60, 2}, "Biometric Information Template"};
static const tlv_definition_t definition_acquirer_identifier = {{tag_9f01, 2},
                                                                "Acquirer Identifier"};
static const tlv_definition_t definition_amount_authorised = {{tag_9f02, 2}, "Amount Authorised"};
static const tlv_definition_t definition_amount_other = {{tag_9f03, 2}, "Amount Other"};
static const tlv_definition_t definition_amount_other_binary = {{tag_9f04, 2},
                                                                "Amount Other Binary"};
static const tlv_definition_t definition_application_discretionary_data = {
    {tag_9f05, 2}, "Application Discretionary Data"};
static const tlv_definition_t definition_aid_terminal = {{tag_9f06, 2}, "Aid Terminal"};
static const tlv_definition_t definition_application_usage_control = {{tag_9f07, 2},
                                                                      "Application Usage Control"};
static const tlv_definition_t definition_application_version_card = {{tag_9f08, 2},
                                                                     "Application Version Card"};
static const tlv_definition_t definition_application_version_terminal = {
    {tag_9f09, 2}, "Application Version Terminal"};
static const tlv_definition_t definition_asrpd = {{tag_9f0a, 2}, "Asrpd"};
static const tlv_definition_t definition_cardholder_name_extended = {{tag_9f0b, 2},
                                                                     "Cardholder Name Extended"};
static const tlv_definition_t definition_iin_extended = {{tag_9f0c, 2}, "Iin Extended"};
static const tlv_definition_t definition_issuer_action_code_default = {
    {tag_9f0d, 2}, "Issuer Action Code Default"};
static const tlv_definition_t definition_issuer_action_code_denial = {{tag_9f0e, 2},
                                                                      "Issuer Action Code Denial"};
static const tlv_definition_t definition_issuer_action_code_online = {{tag_9f0f, 2},
                                                                      "Issuer Action Code Online"};
static const tlv_definition_t definition_issuer_application_data = {{tag_9f10, 2},
                                                                    "Issuer Application Data"};
static const tlv_definition_t definition_issuer_code_table_index = {{tag_9f11, 2},
                                                                    "Issuer Code Table Index"};
static const tlv_definition_t definition_application_preferred_name = {
    {tag_9f12, 2}, "Application Preferred Name"};
static const tlv_definition_t definition_last_online_atc = {{tag_9f13, 2}, "Last Online Atc"};
static const tlv_definition_t definition_lower_consecutive_offline_limit = {
    {tag_9f14, 2}, "Lower Consecutive Offline Limit"};
static const tlv_definition_t definition_merchant_category_code = {{tag_9f15, 2},
                                                                   "Merchant Category Code"};
static const tlv_definition_t definition_merchant_identifier = {{tag_9f16, 2},
                                                                "Merchant Identifier"};
static const tlv_definition_t definition_pin_try_counter = {{tag_9f17, 2}, "Pin Try Counter"};
static const tlv_definition_t definition_issuer_script_identifier = {{tag_9f18, 2},
                                                                     "Issuer Script Identifier"};
static const tlv_definition_t definition_token_requestor_id = {{tag_9f19, 2}, "Token Requestor Id"};
static const tlv_definition_t definition_terminal_country_code = {{tag_9f1a, 2},
                                                                  "Terminal Country Code"};
static const tlv_definition_t definition_terminal_floor_limit = {{tag_9f1b, 2},
                                                                 "Terminal Floor Limit"};
static const tlv_definition_t definition_terminal_identification = {{tag_9f1c, 2},
                                                                    "Terminal Identification"};
static const tlv_definition_t definition_terminal_risk_management_data = {
    {tag_9f1d, 2}, "Terminal Risk Management Data"};
static const tlv_definition_t definition_ifd_serial_number = {{tag_9f1e, 2}, "Ifd Serial Number"};
static const tlv_definition_t definition_track1_discretionary_data = {{tag_9f1f, 2},
                                                                      "Track1 Discretionary Data"};
static const tlv_definition_t definition_track2_discretionary_data = {{tag_9f20, 2},
                                                                      "Track2 Discretionary Data"};
static const tlv_definition_t definition_transaction_time = {{tag_9f21, 2}, "Transaction Time"};
static const tlv_definition_t definition_ca_public_key_index_terminal = {
    {tag_9f22, 2}, "Ca Public Key Index Terminal"};
static const tlv_definition_t definition_upper_consecutive_offline_limit = {
    {tag_9f23, 2}, "Upper Consecutive Offline Limit"};
static const tlv_definition_t definition_payment_account_reference = {{tag_9f24, 2},
                                                                      "Payment Account Reference"};
static const tlv_definition_t definition_last4_pan = {{tag_9f25, 2}, "Last4 Pan"};
static const tlv_definition_t definition_application_cryptogram = {{tag_9f26, 2},
                                                                   "Application Cryptogram"};
static const tlv_definition_t definition_cryptogram_information_data = {
    {tag_9f27, 2}, "Cryptogram Information Data"};
static const tlv_definition_t definition_icc_pin_public_key_certificate = {
    {tag_9f2d, 2}, "Icc Pin Public Key Certificate"};
static const tlv_definition_t definition_icc_pin_public_key_exponent = {
    {tag_9f2e, 2}, "Icc Pin Public Key Exponent"};
static const tlv_definition_t definition_icc_pin_public_key_remainder = {
    {tag_9f2f, 2}, "Icc Pin Public Key Remainder"};
static const tlv_definition_t definition_biometric_terminal_capabilities = {
    {tag_9f30, 2}, "Biometric Terminal Capabilities"};
static const tlv_definition_t definition_card_bit_group_template = {{tag_9f31, 2},
                                                                    "Card Bit Group Template"};
static const tlv_definition_t definition_issuer_public_key_exponent = {
    {tag_9f32, 2}, "Issuer Public Key Exponent"};
static const tlv_definition_t definition_terminal_capabilities = {{tag_9f33, 2},
                                                                  "Terminal Capabilities"};
static const tlv_definition_t definition_cvm_results = {{tag_9f34, 2}, "Cvm Results"};
static const tlv_definition_t definition_terminal_type = {{tag_9f35, 2}, "Terminal Type"};
static const tlv_definition_t definition_atc = {{tag_9f36, 2},
                                                "Application Transaction Counter (ATC)"};
static const tlv_definition_t definition_unpredictable_number = {{tag_9f37, 2},
                                                                 "Unpredictable Number"};
static const tlv_definition_t definition_pdol = {{tag_9f38, 2}, "Pdol"};
static const tlv_definition_t definition_pos_entry_mode = {{tag_9f39, 2}, "Pos Entry Mode"};
static const tlv_definition_t definition_amount_reference_currency = {{tag_9f3a, 2},
                                                                      "Amount Reference Currency"};
static const tlv_definition_t definition_application_reference_currency = {
    {tag_9f3b, 2}, "Application Reference Currency"};
static const tlv_definition_t definition_transaction_reference_currency_code = {
    {tag_9f3c, 2}, "Transaction Reference Currency Code"};
static const tlv_definition_t definition_transaction_reference_currency_exponent = {
    {tag_9f3d, 2}, "Transaction Reference Currency Exponent"};
static const tlv_definition_t definition_additional_terminal_capabilities = {
    {tag_9f40, 2}, "Additional Terminal Capabilities"};
static const tlv_definition_t definition_transaction_sequence_counter = {
    {tag_9f41, 2}, "Transaction Sequence Counter"};
static const tlv_definition_t definition_application_currency_code = {{tag_9f42, 2},
                                                                      "Application Currency Code"};
static const tlv_definition_t definition_application_reference_currency_exponent = {
    {tag_9f43, 2}, "Application Reference Currency Exponent"};
static const tlv_definition_t definition_application_currency_exponent = {
    {tag_9f44, 2}, "Application Currency Exponent"};
static const tlv_definition_t definition_data_authentication_code = {{tag_9f45, 2},
                                                                     "Data Authentication Code"};
static const tlv_definition_t definition_icc_public_key_certificate = {
    {tag_9f46, 2}, "Icc Public Key Certificate"};
static const tlv_definition_t definition_icc_public_key_exponent = {{tag_9f47, 2},
                                                                    "Icc Public Key Exponent"};
static const tlv_definition_t definition_icc_public_key_remainder = {{tag_9f48, 2},
                                                                     "Icc Public Key Remainder"};
static const tlv_definition_t definition_ddol = {{tag_9f49, 2}, "Ddol"};
static const tlv_definition_t definition_sda_tag_list = {{tag_9f4a, 2}, "Sda Tag List"};
static const tlv_definition_t definition_signed_dynamic_application_data = {
    {tag_9f4b, 2}, "Signed Dynamic Application Data"};
static const tlv_definition_t definition_icc_dynamic_number = {{tag_9f4c, 2}, "Icc Dynamic Number"};
static const tlv_definition_t definition_log_entry = {{tag_9f4d, 2}, "Log Entry"};
static const tlv_definition_t definition_merchant_name_and_location = {
    {tag_9f4e, 2}, "Merchant Name And Location"};
static const tlv_definition_t definition_log_format = {{tag_9f4f, 2}, "Log Format"};
static const tlv_definition_t definition_fci_issuer_discretionary_data = {
    {tag_bf0c, 2}, "Fci Issuer Discretionary Data"};
static const tlv_definition_t definition_offline_bit_group_template = {
    {tag_bf4a, 2}, "Offline Bit Group Template"};
static const tlv_definition_t definition_online_bit_group_template = {{tag_bf4b, 2},
                                                                      "Online Bit Group Template"};
static const tlv_definition_t definition_biometric_try_counters_template = {
    {tag_bf4c, 2}, "Biometric Try Counters Template"};
static const tlv_definition_t definition_preferred_attempts_template = {
    {tag_bf4d, 2}, "Preferred Attempts Template"};
static const tlv_definition_t definition_biometric_verification_data_template = {
    {tag_bf4e, 2}, "Biometric Verification Data Template"};

static const tlv_emv_definition_t dictionary_BASE[] = {
    {.definition = &definition_iin, .schema = &emv_base_fields[index_iin], .codec = &codec_iin},
    {.definition = &definition_adf_name, .schema = &emv_base_fields[index_adf_name], .codec = NULL},
    {.definition = &definition_application_label,
     .schema = &emv_base_fields[index_application_label],
     .codec = NULL},
    {.definition = &definition_track2_equivalent_data,
     .schema = &emv_base_fields[index_track2_equivalent_data],
     .codec = &codec_track2_equivalent_data},
    {.definition = &definition_pan, .schema = &emv_base_fields[index_pan], .codec = &codec_pan},
    {.definition = &definition_application_template,
     .schema = &emv_base_fields[index_application_template],
     .codec = NULL},
    {.definition = &definition_fci_template,
     .schema = &emv_base_fields[index_fci_template],
     .codec = NULL},
    {.definition = &definition_read_record_template,
     .schema = &emv_base_fields[index_read_record_template],
     .codec = NULL},
    {.definition = &definition_issuer_script_template1,
     .schema = &emv_base_fields[index_issuer_script_template1],
     .codec = NULL},
    {.definition = &definition_issuer_script_template2,
     .schema = &emv_base_fields[index_issuer_script_template2],
     .codec = NULL},
    {.definition = &definition_directory_discretionary_template,
     .schema = &emv_base_fields[index_directory_discretionary_template],
     .codec = NULL},
    {.definition = &definition_response_template2,
     .schema = &emv_base_fields[index_response_template2],
     .codec = NULL},
    {.definition = &definition_response_template1,
     .schema = &emv_base_fields[index_response_template1],
     .codec = NULL},
    {.definition = &definition_amount_authorised_binary,
     .schema = &emv_base_fields[index_amount_authorised_binary],
     .codec = &codec_amount_authorised_binary},
    {.definition = &definition_aip, .schema = &emv_base_fields[index_aip], .codec = &codec_aip},
    {.definition = &definition_command_template,
     .schema = &emv_base_fields[index_command_template],
     .codec = NULL},
    {.definition = &definition_df_name, .schema = &emv_base_fields[index_df_name], .codec = NULL},
    {.definition = &definition_issuer_script_command,
     .schema = &emv_base_fields[index_issuer_script_command],
     .codec = NULL},
    {.definition = &definition_application_priority_indicator,
     .schema = &emv_base_fields[index_application_priority_indicator],
     .codec = &codec_application_priority_indicator},
    {.definition = &definition_sfi, .schema = &emv_base_fields[index_sfi], .codec = &codec_sfi},
    {.definition = &definition_authorisation_code,
     .schema = &emv_base_fields[index_authorisation_code],
     .codec = NULL},
    {.definition = &definition_authorisation_response_code,
     .schema = &emv_base_fields[index_authorisation_response_code],
     .codec = NULL},
    {.definition = &definition_cdol1, .schema = &emv_base_fields[index_cdol1], .codec = NULL},
    {.definition = &definition_cdol2, .schema = &emv_base_fields[index_cdol2], .codec = NULL},
    {.definition = &definition_cvm_list, .schema = &emv_base_fields[index_cvm_list], .codec = NULL},
    {.definition = &definition_ca_public_key_index,
     .schema = &emv_base_fields[index_ca_public_key_index],
     .codec = &codec_ca_public_key_index},
    {.definition = &definition_issuer_public_key_certificate,
     .schema = &emv_base_fields[index_issuer_public_key_certificate],
     .codec = NULL},
    {.definition = &definition_issuer_authentication_data,
     .schema = &emv_base_fields[index_issuer_authentication_data],
     .codec = NULL},
    {.definition = &definition_issuer_public_key_remainder,
     .schema = &emv_base_fields[index_issuer_public_key_remainder],
     .codec = NULL},
    {.definition = &definition_signed_static_application_data,
     .schema = &emv_base_fields[index_signed_static_application_data],
     .codec = NULL},
    {.definition = &definition_afl, .schema = &emv_base_fields[index_afl], .codec = &codec_afl},
    {.definition = &definition_tvr, .schema = &emv_base_fields[index_tvr], .codec = &codec_tvr},
    {.definition = &definition_tdol, .schema = &emv_base_fields[index_tdol], .codec = NULL},
    {.definition = &definition_tc_hash_value,
     .schema = &emv_base_fields[index_tc_hash_value],
     .codec = NULL},
    {.definition = &definition_transaction_pin_data,
     .schema = &emv_base_fields[index_transaction_pin_data],
     .codec = NULL},
    {.definition = &definition_transaction_date,
     .schema = &emv_base_fields[index_transaction_date],
     .codec = &codec_transaction_date},
    {.definition = &definition_tsi, .schema = &emv_base_fields[index_tsi], .codec = &codec_tsi},
    {.definition = &definition_transaction_type,
     .schema = &emv_base_fields[index_transaction_type],
     .codec = &codec_transaction_type},
    {.definition = &definition_ddf_name, .schema = &emv_base_fields[index_ddf_name], .codec = NULL},
    {.definition = &definition_fci_proprietary_template,
     .schema = &emv_base_fields[index_fci_proprietary_template],
     .codec = NULL},
    {.definition = &definition_cardholder_name,
     .schema = &emv_base_fields[index_cardholder_name],
     .codec = NULL},
    {.definition = &definition_application_expiration_date,
     .schema = &emv_base_fields[index_application_expiration_date],
     .codec = &codec_application_expiration_date},
    {.definition = &definition_application_effective_date,
     .schema = &emv_base_fields[index_application_effective_date],
     .codec = &codec_application_effective_date},
    {.definition = &definition_issuer_country_code,
     .schema = &emv_base_fields[index_issuer_country_code],
     .codec = &codec_issuer_country_code},
    {.definition = &definition_transaction_currency_code,
     .schema = &emv_base_fields[index_transaction_currency_code],
     .codec = &codec_transaction_currency_code},
    {.definition = &definition_language_preference,
     .schema = &emv_base_fields[index_language_preference],
     .codec = NULL},
    {.definition = &definition_service_code,
     .schema = &emv_base_fields[index_service_code],
     .codec = &codec_service_code},
    {.definition = &definition_pan_sequence_number,
     .schema = &emv_base_fields[index_pan_sequence_number],
     .codec = &codec_pan_sequence_number},
    {.definition = &definition_transaction_currency_exponent,
     .schema = &emv_base_fields[index_transaction_currency_exponent],
     .codec = &codec_transaction_currency_exponent},
    {.definition = &definition_issuer_url,
     .schema = &emv_base_fields[index_issuer_url],
     .codec = NULL},
    {.definition = &definition_iban, .schema = &emv_base_fields[index_iban], .codec = NULL},
    {.definition = &definition_bic, .schema = &emv_base_fields[index_bic], .codec = NULL},
    {.definition = &definition_issuer_country_alpha2,
     .schema = &emv_base_fields[index_issuer_country_alpha2],
     .codec = NULL},
    {.definition = &definition_issuer_country_alpha3,
     .schema = &emv_base_fields[index_issuer_country_alpha3],
     .codec = NULL},
    {.definition = &definition_account_type,
     .schema = &emv_base_fields[index_account_type],
     .codec = &codec_account_type},
    {.definition = &definition_biometric_information_template,
     .schema = &emv_base_fields[index_biometric_information_template],
     .codec = NULL},
    {.definition = &definition_acquirer_identifier,
     .schema = &emv_base_fields[index_acquirer_identifier],
     .codec = &codec_acquirer_identifier},
    {.definition = &definition_amount_authorised,
     .schema = &emv_base_fields[index_amount_authorised],
     .codec = &tlv_emv_codec_amount},
    {.definition = &definition_amount_other,
     .schema = &emv_base_fields[index_amount_other],
     .codec = &codec_amount_other},
    {.definition = &definition_amount_other_binary,
     .schema = &emv_base_fields[index_amount_other_binary],
     .codec = &codec_amount_other_binary},
    {.definition = &definition_application_discretionary_data,
     .schema = &emv_base_fields[index_application_discretionary_data],
     .codec = NULL},
    {.definition = &definition_aid_terminal,
     .schema = &emv_base_fields[index_aid_terminal],
     .codec = NULL},
    {.definition = &definition_application_usage_control,
     .schema = &emv_base_fields[index_application_usage_control],
     .codec = &codec_application_usage_control},
    {.definition = &definition_application_version_card,
     .schema = &emv_base_fields[index_application_version_card],
     .codec = &codec_application_version_card},
    {.definition = &definition_application_version_terminal,
     .schema = &emv_base_fields[index_application_version_terminal],
     .codec = &codec_application_version_terminal},
    {.definition = &definition_asrpd, .schema = &emv_base_fields[index_asrpd], .codec = NULL},
    {.definition = &definition_cardholder_name_extended,
     .schema = &emv_base_fields[index_cardholder_name_extended],
     .codec = NULL},
    {.definition = &definition_iin_extended,
     .schema = &emv_base_fields[index_iin_extended],
     .codec = &codec_iin_extended},
    {.definition = &definition_issuer_action_code_default,
     .schema = &emv_base_fields[index_issuer_action_code_default],
     .codec = &codec_issuer_action_code_default},
    {.definition = &definition_issuer_action_code_denial,
     .schema = &emv_base_fields[index_issuer_action_code_denial],
     .codec = &codec_issuer_action_code_denial},
    {.definition = &definition_issuer_action_code_online,
     .schema = &emv_base_fields[index_issuer_action_code_online],
     .codec = &codec_issuer_action_code_online},
    {.definition = &definition_issuer_application_data,
     .schema = &emv_base_fields[index_issuer_application_data],
     .codec = NULL},
    {.definition = &definition_issuer_code_table_index,
     .schema = &emv_base_fields[index_issuer_code_table_index],
     .codec = &codec_issuer_code_table_index},
    {.definition = &definition_application_preferred_name,
     .schema = &emv_base_fields[index_application_preferred_name],
     .codec = NULL},
    {.definition = &definition_last_online_atc,
     .schema = &emv_base_fields[index_last_online_atc],
     .codec = &codec_last_online_atc},
    {.definition = &definition_lower_consecutive_offline_limit,
     .schema = &emv_base_fields[index_lower_consecutive_offline_limit],
     .codec = &codec_lower_consecutive_offline_limit},
    {.definition = &definition_merchant_category_code,
     .schema = &emv_base_fields[index_merchant_category_code],
     .codec = &codec_merchant_category_code},
    {.definition = &definition_merchant_identifier,
     .schema = &emv_base_fields[index_merchant_identifier],
     .codec = NULL},
    {.definition = &definition_pin_try_counter,
     .schema = &emv_base_fields[index_pin_try_counter],
     .codec = &codec_pin_try_counter},
    {.definition = &definition_issuer_script_identifier,
     .schema = &emv_base_fields[index_issuer_script_identifier],
     .codec = NULL},
    {.definition = &definition_token_requestor_id,
     .schema = &emv_base_fields[index_token_requestor_id],
     .codec = &codec_token_requestor_id},
    {.definition = &definition_terminal_country_code,
     .schema = &emv_base_fields[index_terminal_country_code],
     .codec = &codec_terminal_country_code},
    {.definition = &definition_terminal_floor_limit,
     .schema = &emv_base_fields[index_terminal_floor_limit],
     .codec = &codec_terminal_floor_limit},
    {.definition = &definition_terminal_identification,
     .schema = &emv_base_fields[index_terminal_identification],
     .codec = NULL},
    {.definition = &definition_terminal_risk_management_data,
     .schema = &emv_base_fields[index_terminal_risk_management_data],
     .codec = NULL},
    {.definition = &definition_ifd_serial_number,
     .schema = &emv_base_fields[index_ifd_serial_number],
     .codec = NULL},
    {.definition = &definition_track1_discretionary_data,
     .schema = &emv_base_fields[index_track1_discretionary_data],
     .codec = NULL},
    {.definition = &definition_track2_discretionary_data,
     .schema = &emv_base_fields[index_track2_discretionary_data],
     .codec = &codec_track2_discretionary_data},
    {.definition = &definition_transaction_time,
     .schema = &emv_base_fields[index_transaction_time],
     .codec = &codec_transaction_time},
    {.definition = &definition_ca_public_key_index_terminal,
     .schema = &emv_base_fields[index_ca_public_key_index_terminal],
     .codec = &codec_ca_public_key_index_terminal},
    {.definition = &definition_upper_consecutive_offline_limit,
     .schema = &emv_base_fields[index_upper_consecutive_offline_limit],
     .codec = &codec_upper_consecutive_offline_limit},
    {.definition = &definition_payment_account_reference,
     .schema = &emv_base_fields[index_payment_account_reference],
     .codec = NULL},
    {.definition = &definition_last4_pan,
     .schema = &emv_base_fields[index_last4_pan],
     .codec = &codec_last4_pan},
    {.definition = &definition_application_cryptogram,
     .schema = &emv_base_fields[index_application_cryptogram],
     .codec = NULL},
    {.definition = &definition_cryptogram_information_data,
     .schema = &emv_base_fields[index_cryptogram_information_data],
     .codec = &codec_cryptogram_information_data},
    {.definition = &definition_icc_pin_public_key_certificate,
     .schema = &emv_base_fields[index_icc_pin_public_key_certificate],
     .codec = NULL},
    {.definition = &definition_icc_pin_public_key_exponent,
     .schema = &emv_base_fields[index_icc_pin_public_key_exponent],
     .codec = &codec_icc_pin_public_key_exponent},
    {.definition = &definition_icc_pin_public_key_remainder,
     .schema = &emv_base_fields[index_icc_pin_public_key_remainder],
     .codec = NULL},
    {.definition = &definition_biometric_terminal_capabilities,
     .schema = &emv_base_fields[index_biometric_terminal_capabilities],
     .codec = &codec_biometric_terminal_capabilities},
    {.definition = &definition_card_bit_group_template,
     .schema = &emv_base_fields[index_card_bit_group_template],
     .codec = NULL},
    {.definition = &definition_issuer_public_key_exponent,
     .schema = &emv_base_fields[index_issuer_public_key_exponent],
     .codec = &codec_issuer_public_key_exponent},
    {.definition = &definition_terminal_capabilities,
     .schema = &emv_base_fields[index_terminal_capabilities],
     .codec = &codec_terminal_capabilities},
    {.definition = &definition_cvm_results,
     .schema = &emv_base_fields[index_cvm_results],
     .codec = &codec_cvm_results},
    {.definition = &definition_terminal_type,
     .schema = &emv_base_fields[index_terminal_type],
     .codec = &codec_terminal_type},
    {.definition = &definition_atc, .schema = &emv_base_fields[index_atc], .codec = &codec_atc},
    {.definition = &definition_unpredictable_number,
     .schema = &emv_base_fields[index_unpredictable_number],
     .codec = NULL},
    {.definition = &definition_pdol, .schema = &emv_base_fields[index_pdol], .codec = NULL},
    {.definition = &definition_pos_entry_mode,
     .schema = &emv_base_fields[index_pos_entry_mode],
     .codec = &codec_pos_entry_mode},
    {.definition = &definition_amount_reference_currency,
     .schema = &emv_base_fields[index_amount_reference_currency],
     .codec = &codec_amount_reference_currency},
    {.definition = &definition_application_reference_currency,
     .schema = &emv_base_fields[index_application_reference_currency],
     .codec = &codec_application_reference_currency},
    {.definition = &definition_transaction_reference_currency_code,
     .schema = &emv_base_fields[index_transaction_reference_currency_code],
     .codec = &codec_transaction_reference_currency_code},
    {.definition = &definition_transaction_reference_currency_exponent,
     .schema = &emv_base_fields[index_transaction_reference_currency_exponent],
     .codec = &codec_transaction_reference_currency_exponent},
    {.definition = &definition_additional_terminal_capabilities,
     .schema = &emv_base_fields[index_additional_terminal_capabilities],
     .codec = &codec_additional_terminal_capabilities},
    {.definition = &definition_transaction_sequence_counter,
     .schema = &emv_base_fields[index_transaction_sequence_counter],
     .codec = &codec_transaction_sequence_counter},
    {.definition = &definition_application_currency_code,
     .schema = &emv_base_fields[index_application_currency_code],
     .codec = &codec_application_currency_code},
    {.definition = &definition_application_reference_currency_exponent,
     .schema = &emv_base_fields[index_application_reference_currency_exponent],
     .codec = &codec_application_reference_currency_exponent},
    {.definition = &definition_application_currency_exponent,
     .schema = &emv_base_fields[index_application_currency_exponent],
     .codec = &codec_application_currency_exponent},
    {.definition = &definition_data_authentication_code,
     .schema = &emv_base_fields[index_data_authentication_code],
     .codec = NULL},
    {.definition = &definition_icc_public_key_certificate,
     .schema = &emv_base_fields[index_icc_public_key_certificate],
     .codec = NULL},
    {.definition = &definition_icc_public_key_exponent,
     .schema = &emv_base_fields[index_icc_public_key_exponent],
     .codec = &codec_icc_public_key_exponent},
    {.definition = &definition_icc_public_key_remainder,
     .schema = &emv_base_fields[index_icc_public_key_remainder],
     .codec = NULL},
    {.definition = &definition_ddol, .schema = &emv_base_fields[index_ddol], .codec = NULL},
    {.definition = &definition_sda_tag_list,
     .schema = &emv_base_fields[index_sda_tag_list],
     .codec = NULL},
    {.definition = &definition_signed_dynamic_application_data,
     .schema = &emv_base_fields[index_signed_dynamic_application_data],
     .codec = NULL},
    {.definition = &definition_icc_dynamic_number,
     .schema = &emv_base_fields[index_icc_dynamic_number],
     .codec = NULL},
    {.definition = &definition_log_entry,
     .schema = &emv_base_fields[index_log_entry],
     .codec = NULL},
    {.definition = &definition_merchant_name_and_location,
     .schema = &emv_base_fields[index_merchant_name_and_location],
     .codec = NULL},
    {.definition = &definition_log_format,
     .schema = &emv_base_fields[index_log_format],
     .codec = NULL},
    {.definition = &definition_fci_issuer_discretionary_data,
     .schema = &emv_base_fields[index_fci_issuer_discretionary_data],
     .codec = NULL},
    {.definition = &definition_offline_bit_group_template,
     .schema = &emv_base_fields[index_offline_bit_group_template],
     .codec = NULL},
    {.definition = &definition_online_bit_group_template,
     .schema = &emv_base_fields[index_online_bit_group_template],
     .codec = NULL},
    {.definition = &definition_biometric_try_counters_template,
     .schema = &emv_base_fields[index_biometric_try_counters_template],
     .codec = NULL},
    {.definition = &definition_preferred_attempts_template,
     .schema = &emv_base_fields[index_preferred_attempts_template],
     .codec = NULL},
    {.definition = &definition_biometric_verification_data_template,
     .schema = &emv_base_fields[index_biometric_verification_data_template],
     .codec = NULL},
};

enum { index_biometric_header_template, count_BIT };
static const tlv_schema_entry_t schema_BIT[] = {
    [index_biometric_header_template] =
        {{tag_a1, 1}, 0, SIZE_MAX, 0, "biometric_header_template", 0},
};

static const tlv_definition_t definition_biometric_header_template = {{tag_a1, 1},
                                                                      "Biometric Header Template"};

static const tlv_emv_definition_t dictionary_BIT[] = {
    {.definition = &definition_biometric_header_template,
     .schema = &schema_BIT[index_biometric_header_template],
     .codec = NULL},
};

enum {
    index_biometric_header_version,
    index_biometric_type,
    index_biometric_subtype,
    index_biometric_creation_datetime,
    index_biometric_creator,
    index_biometric_validity_period,
    index_biometric_product_id,
    index_biometric_format_owner,
    index_biometric_format_type,
    index_biometric_solution_id,
    index_biometric_matching_parameters,
    index_bht1,
    index_bht2,
    index_biometric_matching_parameters_template,
    count_BHT
};
static const tlv_schema_entry_t schema_BHT[] = {
    [index_biometric_header_version] = {{tag_80, 1}, 2, 2, 0, "biometric_header_version", 0},
    [index_biometric_type] = {{tag_81, 1}, 1, 3, 0, "biometric_type", 0},
    [index_biometric_subtype] = {{tag_82, 1}, 1, 1, 0, "biometric_subtype", 0},
    [index_biometric_creation_datetime] = {{tag_83, 1}, 7, 7, 0, "biometric_creation_datetime", 0},
    [index_biometric_creator] = {{tag_84, 1}, 0, SIZE_MAX, 0, "biometric_creator", 0},
    [index_biometric_validity_period] = {{tag_85, 1}, 8, 8, 0, "biometric_validity_period", 0},
    [index_biometric_product_id] = {{tag_86, 1}, 2, 2, 0, "biometric_product_id", 0},
    [index_biometric_format_owner] = {{tag_87, 1}, 2, 2, 0, "biometric_format_owner", 0},
    [index_biometric_format_type] = {{tag_88, 1}, 2, 2, 0, "biometric_format_type", 0},
    [index_biometric_solution_id] = {{tag_90, 1}, 0, SIZE_MAX, 0, "biometric_solution_id", 0},
    [index_biometric_matching_parameters] =
        {{tag_91, 1}, 0, SIZE_MAX, 0, "biometric_matching_parameters", 0},
    [index_bht1] = {{tag_a1, 1}, 0, SIZE_MAX, 0, "bht1", 0},
    [index_bht2] = {{tag_a2, 1}, 0, SIZE_MAX, 0, "bht2", 0},
    [index_biometric_matching_parameters_template] =
        {{tag_b1, 1}, 0, SIZE_MAX, 0, "biometric_matching_parameters_template", 0},
};
static const tlv_schema_number_t codec_biometric_header_version_rule = {
    &schema_BHT[index_biometric_header_version], {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_biometric_header_version = {
    &codec_biometric_header_version_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const emv_value_rule_t codec_biometric_type_rule = {&schema_BHT[index_biometric_type],
                                                           EMV_REP_BIOMETRIC, 0};
static const tlv_codec_t codec_biometric_type = {&codec_biometric_type_rule, emv_value_decode,
                                                 emv_value_encode};
static const tlv_schema_number_t codec_biometric_subtype_rule = {
    &schema_BHT[index_biometric_subtype], {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_biometric_subtype = {
    &codec_biometric_subtype_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const tlv_schema_number_t codec_biometric_product_id_rule = {
    &schema_BHT[index_biometric_product_id], {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_biometric_product_id = {
    &codec_biometric_product_id_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const tlv_schema_number_t codec_biometric_format_owner_rule = {
    &schema_BHT[index_biometric_format_owner], {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_biometric_format_owner = {
    &codec_biometric_format_owner_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const tlv_schema_number_t codec_biometric_format_type_rule = {
    &schema_BHT[index_biometric_format_type], {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_biometric_format_type = {
    &codec_biometric_format_type_rule, tlv_schema_number_decode, tlv_schema_number_encode};

static const tlv_definition_t definition_biometric_header_version = {{tag_80, 1},
                                                                     "Biometric Header Version"};
static const tlv_definition_t definition_biometric_type = {{tag_81, 1}, "Biometric Type"};
static const tlv_definition_t definition_biometric_subtype = {{tag_82, 1}, "Biometric Subtype"};
static const tlv_definition_t definition_biometric_creation_datetime = {
    {tag_83, 1}, "Biometric Creation Datetime"};
static const tlv_definition_t definition_biometric_creator = {{tag_84, 1}, "Biometric Creator"};
static const tlv_definition_t definition_biometric_validity_period = {{tag_85, 1},
                                                                      "Biometric Validity Period"};
static const tlv_definition_t definition_biometric_product_id = {{tag_86, 1},
                                                                 "Biometric Product Id"};
static const tlv_definition_t definition_biometric_format_owner = {{tag_87, 1},
                                                                   "Biometric Format Owner"};
static const tlv_definition_t definition_biometric_format_type = {{tag_88, 1},
                                                                  "Biometric Format Type"};
static const tlv_definition_t definition_biometric_solution_id = {{tag_90, 1},
                                                                  "Biometric Solution Id"};
static const tlv_definition_t definition_biometric_matching_parameters = {
    {tag_91, 1}, "Biometric Matching Parameters"};
static const tlv_definition_t definition_bht1 = {{tag_a1, 1}, "Bht1"};
static const tlv_definition_t definition_bht2 = {{tag_a2, 1}, "Bht2"};
static const tlv_definition_t definition_biometric_matching_parameters_template = {
    {tag_b1, 1}, "Biometric Matching Parameters Template"};

static const tlv_emv_definition_t dictionary_BHT[] = {
    {.definition = &definition_biometric_header_version,
     .schema = &schema_BHT[index_biometric_header_version],
     .codec = &codec_biometric_header_version},
    {.definition = &definition_biometric_type,
     .schema = &schema_BHT[index_biometric_type],
     .codec = &codec_biometric_type},
    {.definition = &definition_biometric_subtype,
     .schema = &schema_BHT[index_biometric_subtype],
     .codec = &codec_biometric_subtype},
    {.definition = &definition_biometric_creation_datetime,
     .schema = &schema_BHT[index_biometric_creation_datetime],
     .codec = NULL},
    {.definition = &definition_biometric_creator,
     .schema = &schema_BHT[index_biometric_creator],
     .codec = NULL},
    {.definition = &definition_biometric_validity_period,
     .schema = &schema_BHT[index_biometric_validity_period],
     .codec = NULL},
    {.definition = &definition_biometric_product_id,
     .schema = &schema_BHT[index_biometric_product_id],
     .codec = &codec_biometric_product_id},
    {.definition = &definition_biometric_format_owner,
     .schema = &schema_BHT[index_biometric_format_owner],
     .codec = &codec_biometric_format_owner},
    {.definition = &definition_biometric_format_type,
     .schema = &schema_BHT[index_biometric_format_type],
     .codec = &codec_biometric_format_type},
    {.definition = &definition_biometric_solution_id,
     .schema = &schema_BHT[index_biometric_solution_id],
     .codec = NULL},
    {.definition = &definition_biometric_matching_parameters,
     .schema = &schema_BHT[index_biometric_matching_parameters],
     .codec = NULL},
    {.definition = &definition_bht1, .schema = &schema_BHT[index_bht1], .codec = NULL},
    {.definition = &definition_bht2, .schema = &schema_BHT[index_bht2], .codec = NULL},
    {.definition = &definition_biometric_matching_parameters_template,
     .schema = &schema_BHT[index_biometric_matching_parameters_template],
     .codec = NULL},
};

enum { index_bht_format_owner, index_bht_format_type, count_BHT_FORMAT };
static const tlv_schema_entry_t schema_BHT_FORMAT[] = {
    [index_bht_format_owner] = {{tag_87, 1}, 2, 2, 0, "bht_format_owner", 0},
    [index_bht_format_type] = {{tag_88, 1}, 2, 2, 0, "bht_format_type", 0},
};
static const tlv_schema_number_t codec_bht_format_owner_rule = {
    &schema_BHT_FORMAT[index_bht_format_owner], {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_bht_format_owner = {
    &codec_bht_format_owner_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const tlv_schema_number_t codec_bht_format_type_rule = {
    &schema_BHT_FORMAT[index_bht_format_type], {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_bht_format_type = {
    &codec_bht_format_type_rule, tlv_schema_number_decode, tlv_schema_number_encode};

static const tlv_definition_t definition_bht_format_owner = {{tag_87, 1}, "Bht Format Owner"};
static const tlv_definition_t definition_bht_format_type = {{tag_88, 1}, "Bht Format Type"};

static const tlv_emv_definition_t dictionary_BHT_FORMAT[] = {
    {.definition = &definition_bht_format_owner,
     .schema = &schema_BHT_FORMAT[index_bht_format_owner],
     .codec = &codec_bht_format_owner},
    {.definition = &definition_bht_format_type,
     .schema = &schema_BHT_FORMAT[index_bht_format_type],
     .codec = &codec_bht_format_type},
};

enum { index_bit_count, index_group_bit, count_BIT_GROUP };
static const tlv_schema_entry_t schema_BIT_GROUP[] = {
    [index_bit_count] = {{tag_02, 1}, 1, 1, 0, "bit_count", 0},
    [index_group_bit] = {{tag_7f60, 2}, 0, SIZE_MAX, 0, "group_bit", 0},
};
static const tlv_schema_number_t codec_bit_count_rule = {&schema_BIT_GROUP[index_bit_count],
                                                         {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_bit_count = {&codec_bit_count_rule, tlv_schema_number_decode,
                                            tlv_schema_number_encode};

static const tlv_definition_t definition_bit_count = {{tag_02, 1}, "Bit Count"};
static const tlv_definition_t definition_group_bit = {{tag_7f60, 2}, "Group Bit"};

static const tlv_emv_definition_t dictionary_BIT_GROUP[] = {
    {.definition = &definition_bit_count,
     .schema = &schema_BIT_GROUP[index_bit_count],
     .codec = &codec_bit_count},
    {.definition = &definition_group_bit,
     .schema = &schema_BIT_GROUP[index_group_bit],
     .codec = NULL},
};

enum {
    index_facial_try_counter,
    index_finger_try_counter,
    index_iris_try_counter,
    index_palm_try_counter,
    index_voice_try_counter,
    count_BIOMETRIC_COUNTERS
};
static const tlv_schema_entry_t schema_BIOMETRIC_COUNTERS[] = {
    [index_facial_try_counter] = {{tag_df50, 2}, 1, 1, 0, "facial_try_counter", 0},
    [index_finger_try_counter] = {{tag_df51, 2}, 1, 1, 0, "finger_try_counter", 0},
    [index_iris_try_counter] = {{tag_df52, 2}, 1, 1, 0, "iris_try_counter", 0},
    [index_palm_try_counter] = {{tag_df53, 2}, 1, 1, 0, "palm_try_counter", 0},
    [index_voice_try_counter] = {{tag_df54, 2}, 1, 1, 0, "voice_try_counter", 0},
};
static const tlv_schema_number_t codec_facial_try_counter_rule = {
    &schema_BIOMETRIC_COUNTERS[index_facial_try_counter], {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_facial_try_counter = {
    &codec_facial_try_counter_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const tlv_schema_number_t codec_finger_try_counter_rule = {
    &schema_BIOMETRIC_COUNTERS[index_finger_try_counter], {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_finger_try_counter = {
    &codec_finger_try_counter_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const tlv_schema_number_t codec_iris_try_counter_rule = {
    &schema_BIOMETRIC_COUNTERS[index_iris_try_counter], {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_iris_try_counter = {
    &codec_iris_try_counter_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const tlv_schema_number_t codec_palm_try_counter_rule = {
    &schema_BIOMETRIC_COUNTERS[index_palm_try_counter], {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_palm_try_counter = {
    &codec_palm_try_counter_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const tlv_schema_number_t codec_voice_try_counter_rule = {
    &schema_BIOMETRIC_COUNTERS[index_voice_try_counter], {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_voice_try_counter = {
    &codec_voice_try_counter_rule, tlv_schema_number_decode, tlv_schema_number_encode};

static const tlv_definition_t definition_facial_try_counter = {{tag_df50, 2}, "Facial Try Counter"};
static const tlv_definition_t definition_finger_try_counter = {{tag_df51, 2}, "Finger Try Counter"};
static const tlv_definition_t definition_iris_try_counter = {{tag_df52, 2}, "Iris Try Counter"};
static const tlv_definition_t definition_palm_try_counter = {{tag_df53, 2}, "Palm Try Counter"};
static const tlv_definition_t definition_voice_try_counter = {{tag_df54, 2}, "Voice Try Counter"};

static const tlv_emv_definition_t dictionary_BIOMETRIC_COUNTERS[] = {
    {.definition = &definition_facial_try_counter,
     .schema = &schema_BIOMETRIC_COUNTERS[index_facial_try_counter],
     .codec = &codec_facial_try_counter},
    {.definition = &definition_finger_try_counter,
     .schema = &schema_BIOMETRIC_COUNTERS[index_finger_try_counter],
     .codec = &codec_finger_try_counter},
    {.definition = &definition_iris_try_counter,
     .schema = &schema_BIOMETRIC_COUNTERS[index_iris_try_counter],
     .codec = &codec_iris_try_counter},
    {.definition = &definition_palm_try_counter,
     .schema = &schema_BIOMETRIC_COUNTERS[index_palm_try_counter],
     .codec = &codec_palm_try_counter},
    {.definition = &definition_voice_try_counter,
     .schema = &schema_BIOMETRIC_COUNTERS[index_voice_try_counter],
     .codec = &codec_voice_try_counter},
};

enum {
    index_preferred_facial_attempts,
    index_preferred_finger_attempts,
    index_preferred_iris_attempts,
    index_preferred_palm_attempts,
    index_preferred_voice_attempts,
    count_BIOMETRIC_ATTEMPTS
};
static const tlv_schema_entry_t schema_BIOMETRIC_ATTEMPTS[] = {
    [index_preferred_facial_attempts] = {{tag_df50, 2}, 1, 1, 0, "preferred_facial_attempts", 0},
    [index_preferred_finger_attempts] = {{tag_df51, 2}, 1, 1, 0, "preferred_finger_attempts", 0},
    [index_preferred_iris_attempts] = {{tag_df52, 2}, 1, 1, 0, "preferred_iris_attempts", 0},
    [index_preferred_palm_attempts] = {{tag_df53, 2}, 1, 1, 0, "preferred_palm_attempts", 0},
    [index_preferred_voice_attempts] = {{tag_df54, 2}, 1, 1, 0, "preferred_voice_attempts", 0},
};
static const tlv_schema_number_t codec_preferred_facial_attempts_rule = {
    &schema_BIOMETRIC_ATTEMPTS[index_preferred_facial_attempts], {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_preferred_facial_attempts = {
    &codec_preferred_facial_attempts_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const tlv_schema_number_t codec_preferred_finger_attempts_rule = {
    &schema_BIOMETRIC_ATTEMPTS[index_preferred_finger_attempts], {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_preferred_finger_attempts = {
    &codec_preferred_finger_attempts_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const tlv_schema_number_t codec_preferred_iris_attempts_rule = {
    &schema_BIOMETRIC_ATTEMPTS[index_preferred_iris_attempts], {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_preferred_iris_attempts = {
    &codec_preferred_iris_attempts_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const tlv_schema_number_t codec_preferred_palm_attempts_rule = {
    &schema_BIOMETRIC_ATTEMPTS[index_preferred_palm_attempts], {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_preferred_palm_attempts = {
    &codec_preferred_palm_attempts_rule, tlv_schema_number_decode, tlv_schema_number_encode};
static const tlv_schema_number_t codec_preferred_voice_attempts_rule = {
    &schema_BIOMETRIC_ATTEMPTS[index_preferred_voice_attempts], {TLV_NUMBER_BINARY_BE, 0, 0}};
static const tlv_codec_t codec_preferred_voice_attempts = {
    &codec_preferred_voice_attempts_rule, tlv_schema_number_decode, tlv_schema_number_encode};

static const tlv_definition_t definition_preferred_facial_attempts = {{tag_df50, 2},
                                                                      "Preferred Facial Attempts"};
static const tlv_definition_t definition_preferred_finger_attempts = {{tag_df51, 2},
                                                                      "Preferred Finger Attempts"};
static const tlv_definition_t definition_preferred_iris_attempts = {{tag_df52, 2},
                                                                    "Preferred Iris Attempts"};
static const tlv_definition_t definition_preferred_palm_attempts = {{tag_df53, 2},
                                                                    "Preferred Palm Attempts"};
static const tlv_definition_t definition_preferred_voice_attempts = {{tag_df54, 2},
                                                                     "Preferred Voice Attempts"};

static const tlv_emv_definition_t dictionary_BIOMETRIC_ATTEMPTS[] = {
    {.definition = &definition_preferred_facial_attempts,
     .schema = &schema_BIOMETRIC_ATTEMPTS[index_preferred_facial_attempts],
     .codec = &codec_preferred_facial_attempts},
    {.definition = &definition_preferred_finger_attempts,
     .schema = &schema_BIOMETRIC_ATTEMPTS[index_preferred_finger_attempts],
     .codec = &codec_preferred_finger_attempts},
    {.definition = &definition_preferred_iris_attempts,
     .schema = &schema_BIOMETRIC_ATTEMPTS[index_preferred_iris_attempts],
     .codec = &codec_preferred_iris_attempts},
    {.definition = &definition_preferred_palm_attempts,
     .schema = &schema_BIOMETRIC_ATTEMPTS[index_preferred_palm_attempts],
     .codec = &codec_preferred_palm_attempts},
    {.definition = &definition_preferred_voice_attempts,
     .schema = &schema_BIOMETRIC_ATTEMPTS[index_preferred_voice_attempts],
     .codec = &codec_preferred_voice_attempts},
};

enum {
    index_verification_biometric_type,
    index_verification_biometric_solution_id,
    index_enciphered_biometric_key_seed,
    index_enciphered_biometric_data,
    index_biometric_data_mac,
    count_BIOMETRIC_VERIFICATION
};
static const tlv_schema_entry_t schema_BIOMETRIC_VERIFICATION[] = {
    [index_verification_biometric_type] = {{tag_81, 1}, 1, 3, 0, "verification_biometric_type", 0},
    [index_verification_biometric_solution_id] =
        {{tag_90, 1}, 0, SIZE_MAX, 0, "verification_biometric_solution_id", 0},
    [index_enciphered_biometric_key_seed] =
        {{tag_df50, 2}, 1, SIZE_MAX, 0, "enciphered_biometric_key_seed", 0},
    [index_enciphered_biometric_data] =
        {{tag_df51, 2}, 0, SIZE_MAX, 0, "enciphered_biometric_data", 0},
    [index_biometric_data_mac] = {{tag_df52, 2}, 8, 8, 0, "biometric_data_mac", 0},
};
static const emv_value_rule_t codec_verification_biometric_type_rule = {
    &schema_BIOMETRIC_VERIFICATION[index_verification_biometric_type], EMV_REP_BIOMETRIC, 0};
static const tlv_codec_t codec_verification_biometric_type = {
    &codec_verification_biometric_type_rule, emv_value_decode, emv_value_encode};

static const tlv_definition_t definition_verification_biometric_type = {
    {tag_81, 1}, "Verification Biometric Type"};
static const tlv_definition_t definition_verification_biometric_solution_id = {
    {tag_90, 1}, "Verification Biometric Solution Id"};
static const tlv_definition_t definition_enciphered_biometric_key_seed = {
    {tag_df50, 2}, "Enciphered Biometric Key Seed"};
static const tlv_definition_t definition_enciphered_biometric_data = {{tag_df51, 2},
                                                                      "Enciphered Biometric Data"};
static const tlv_definition_t definition_biometric_data_mac = {{tag_df52, 2}, "Biometric Data Mac"};

static const tlv_emv_definition_t dictionary_BIOMETRIC_VERIFICATION[] = {
    {.definition = &definition_verification_biometric_type,
     .schema = &schema_BIOMETRIC_VERIFICATION[index_verification_biometric_type],
     .codec = &codec_verification_biometric_type},
    {.definition = &definition_verification_biometric_solution_id,
     .schema = &schema_BIOMETRIC_VERIFICATION[index_verification_biometric_solution_id],
     .codec = NULL},
    {.definition = &definition_enciphered_biometric_key_seed,
     .schema = &schema_BIOMETRIC_VERIFICATION[index_enciphered_biometric_key_seed],
     .codec = NULL},
    {.definition = &definition_enciphered_biometric_data,
     .schema = &schema_BIOMETRIC_VERIFICATION[index_enciphered_biometric_data],
     .codec = NULL},
    {.definition = &definition_biometric_data_mac,
     .schema = &schema_BIOMETRIC_VERIFICATION[index_biometric_data_mac],
     .codec = NULL},
};

static const tlv_schema_t schemas[] = {
    [TLV_EMV_CONTEXT_BASE] = {emv_base_fields, count_BASE},
    [TLV_EMV_CONTEXT_BIT] = {schema_BIT, count_BIT},
    [TLV_EMV_CONTEXT_BHT] = {schema_BHT, count_BHT},
    [TLV_EMV_CONTEXT_BHT_FORMAT] = {schema_BHT_FORMAT, count_BHT_FORMAT},
    [TLV_EMV_CONTEXT_BIT_GROUP] = {schema_BIT_GROUP, count_BIT_GROUP},
    [TLV_EMV_CONTEXT_BIOMETRIC_COUNTERS] = {schema_BIOMETRIC_COUNTERS, count_BIOMETRIC_COUNTERS},
    [TLV_EMV_CONTEXT_BIOMETRIC_ATTEMPTS] = {schema_BIOMETRIC_ATTEMPTS, count_BIOMETRIC_ATTEMPTS},
    [TLV_EMV_CONTEXT_BIOMETRIC_VERIFICATION] = {schema_BIOMETRIC_VERIFICATION,
                                                count_BIOMETRIC_VERIFICATION},
};
static const tlv_emv_dictionary_t dictionaries[] = {
    [TLV_EMV_CONTEXT_BASE] = {dictionary_BASE, count_BASE},
    [TLV_EMV_CONTEXT_BIT] = {dictionary_BIT, count_BIT},
    [TLV_EMV_CONTEXT_BHT] = {dictionary_BHT, count_BHT},
    [TLV_EMV_CONTEXT_BHT_FORMAT] = {dictionary_BHT_FORMAT, count_BHT_FORMAT},
    [TLV_EMV_CONTEXT_BIT_GROUP] = {dictionary_BIT_GROUP, count_BIT_GROUP},
    [TLV_EMV_CONTEXT_BIOMETRIC_COUNTERS] = {dictionary_BIOMETRIC_COUNTERS,
                                            count_BIOMETRIC_COUNTERS},
    [TLV_EMV_CONTEXT_BIOMETRIC_ATTEMPTS] = {dictionary_BIOMETRIC_ATTEMPTS,
                                            count_BIOMETRIC_ATTEMPTS},
    [TLV_EMV_CONTEXT_BIOMETRIC_VERIFICATION] = {dictionary_BIOMETRIC_VERIFICATION,
                                                count_BIOMETRIC_VERIFICATION},
};
const tlv_schema_t tlv_emv_schema = {emv_base_fields, count_BASE};

const tlv_schema_t* tlv_emv_schema_for(tlv_emv_context_t context) {
    if ((unsigned)context >= TLV_EMV_CONTEXT_COUNT) return NULL;
    return context == TLV_EMV_CONTEXT_BASE ? &tlv_emv_schema : &schemas[context];
}

const tlv_emv_dictionary_t* tlv_emv_dictionary_for(tlv_emv_context_t context) {
    if ((unsigned)context >= TLV_EMV_CONTEXT_COUNT) return NULL;
    return &dictionaries[context];
}

const tlv_emv_definition_t* tlv_emv_dictionary_find(const tlv_emv_dictionary_t* dictionary,
                                                    const tlv_tag_t* tag) {
    size_t i;
    if (!dictionary || !tag || !tag->data || !tag->size ||
        (!dictionary->entries && dictionary->count))
        return NULL;
    for (i = 0; i < dictionary->count; ++i) {
        const tlv_emv_definition_t* entry = &dictionary->entries[i];
        if (entry->definition && entry->schema && entry->definition->tag.data &&
            tlv_tag_equal(entry->definition->tag, entry->schema->tag) &&
            tlv_tag_equal(entry->definition->tag, *tag))
            return entry;
    }
    return NULL;
}

const tlv_emv_definition_t* tlv_emv_find(tlv_emv_context_t context, const tlv_tag_t* tag) {
    return tlv_emv_dictionary_find(tlv_emv_dictionary_for(context), tag);
}
