#include "tlv/builtins/emv/emv.h"
#include "tlv/codec/number.h"
#include "emv_codec_internal.h"

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

static const tlv_number_codec_config_t number_bcd_3_3_1_6_config = {TLV_NUMBER_BCD, 3, 3, 1, 6};
static const tlv_codec_t number_bcd_3_3_1_6 = {&number_bcd_3_3_1_6_config, tlv_number_decode,
                                               tlv_number_encode};
static const emv_value_rule_t track2_0_19_1_0_config = {0, 19, 1, TLV_EMV_VALUE_TRACK2, 0};
static const tlv_codec_t track2_0_19_1_0 = {&track2_0_19_1_0_config, emv_value_decode,
                                            emv_value_encode};
static const emv_value_rule_t digits_1_10_1_19_config = {1, 10, 1, TLV_EMV_VALUE_DIGITS, 19};
static const tlv_codec_t digits_1_10_1_19 = {&digits_1_10_1_19_config, emv_value_decode,
                                             emv_value_encode};
static const tlv_number_codec_config_t number_binary_be_4_4_1_0_config = {TLV_NUMBER_BINARY_BE, 4,
                                                                          4, 1, 0};
static const tlv_codec_t number_binary_be_4_4_1_0 = {&number_binary_be_4_4_1_0_config,
                                                     tlv_number_decode, tlv_number_encode};
static const tlv_number_codec_config_t number_binary_be_2_2_1_0_config = {TLV_NUMBER_BINARY_BE, 2,
                                                                          2, 1, 0};
static const tlv_codec_t number_binary_be_2_2_1_0 = {&number_binary_be_2_2_1_0_config,
                                                     tlv_number_decode, tlv_number_encode};
static const tlv_number_codec_config_t number_binary_be_1_1_1_0_config = {TLV_NUMBER_BINARY_BE, 1,
                                                                          1, 1, 0};
static const tlv_codec_t number_binary_be_1_1_1_0 = {&number_binary_be_1_1_1_0_config,
                                                     tlv_number_decode, tlv_number_encode};
static const emv_value_rule_t afl_4_252_4_0_config = {4, 252, 4, TLV_EMV_VALUE_AFL, 0};
static const tlv_codec_t afl_4_252_4_0 = {&afl_4_252_4_0_config, emv_value_decode,
                                          emv_value_encode};
static const tlv_number_codec_config_t number_binary_be_5_5_1_0_config = {TLV_NUMBER_BINARY_BE, 5,
                                                                          5, 1, 0};
static const tlv_codec_t number_binary_be_5_5_1_0 = {&number_binary_be_5_5_1_0_config,
                                                     tlv_number_decode, tlv_number_encode};
static const emv_value_rule_t date_3_3_1_0_config = {3, 3, 1, TLV_EMV_VALUE_DATE, 0};
static const tlv_codec_t date_3_3_1_0 = {&date_3_3_1_0_config, emv_value_decode, emv_value_encode};
static const tlv_number_codec_config_t number_bcd_1_1_1_2_config = {TLV_NUMBER_BCD, 1, 1, 1, 2};
static const tlv_codec_t number_bcd_1_1_1_2 = {&number_bcd_1_1_1_2_config, tlv_number_decode,
                                               tlv_number_encode};
static const tlv_number_codec_config_t number_bcd_2_2_1_3_config = {TLV_NUMBER_BCD, 2, 2, 1, 3};
static const tlv_codec_t number_bcd_2_2_1_3 = {&number_bcd_2_2_1_3_config, tlv_number_decode,
                                               tlv_number_encode};
static const tlv_number_codec_config_t number_bcd_1_1_1_1_config = {TLV_NUMBER_BCD, 1, 1, 1, 1};
static const tlv_codec_t number_bcd_1_1_1_1 = {&number_bcd_1_1_1_1_config, tlv_number_decode,
                                               tlv_number_encode};
static const emv_value_rule_t account_1_1_1_0_config = {1, 1, 1, TLV_EMV_VALUE_ACCOUNT, 0};
static const tlv_codec_t account_1_1_1_0 = {&account_1_1_1_0_config, emv_value_decode,
                                            emv_value_encode};
static const tlv_number_codec_config_t number_bcd_6_6_1_11_config = {TLV_NUMBER_BCD, 6, 6, 1, 11};
static const tlv_codec_t number_bcd_6_6_1_11 = {&number_bcd_6_6_1_11_config, tlv_number_decode,
                                                tlv_number_encode};
static const tlv_number_codec_config_t number_bcd_3_4_1_8_config = {TLV_NUMBER_BCD, 3, 4, 1, 8};
static const tlv_codec_t number_bcd_3_4_1_8 = {&number_bcd_3_4_1_8_config, tlv_number_decode,
                                               tlv_number_encode};
static const tlv_number_codec_config_t number_bcd_2_2_1_4_config = {TLV_NUMBER_BCD, 2, 2, 1, 4};
static const tlv_codec_t number_bcd_2_2_1_4 = {&number_bcd_2_2_1_4_config, tlv_number_decode,
                                               tlv_number_encode};
static const emv_value_rule_t digits_0_SIZE_MAX_1_0_config = {0, SIZE_MAX, 1, TLV_EMV_VALUE_DIGITS,
                                                              0};
static const tlv_codec_t digits_0_SIZE_MAX_1_0 = {&digits_0_SIZE_MAX_1_0_config, emv_value_decode,
                                                  emv_value_encode};
static const emv_value_rule_t time_3_3_1_0_config = {3, 3, 1, TLV_EMV_VALUE_TIME, 0};
static const tlv_codec_t time_3_3_1_0 = {&time_3_3_1_0_config, emv_value_decode, emv_value_encode};
static const emv_value_rule_t cryptogram_1_1_1_0_config = {1, 1, 1, TLV_EMV_VALUE_CRYPTOGRAM, 0};
static const tlv_codec_t cryptogram_1_1_1_0 = {&cryptogram_1_1_1_0_config, emv_value_decode,
                                               emv_value_encode};
static const tlv_number_codec_config_t number_binary_be_1_3_2_0_config = {TLV_NUMBER_BINARY_BE, 1,
                                                                          3, 2, 0};
static const tlv_codec_t number_binary_be_1_3_2_0 = {&number_binary_be_1_3_2_0_config,
                                                     tlv_number_decode, tlv_number_encode};
static const tlv_number_codec_config_t number_binary_be_3_3_1_0_config = {TLV_NUMBER_BINARY_BE, 3,
                                                                          3, 1, 0};
static const tlv_codec_t number_binary_be_3_3_1_0 = {&number_binary_be_3_3_1_0_config,
                                                     tlv_number_decode, tlv_number_encode};
static const emv_value_rule_t cvm_result_3_3_1_0_config = {3, 3, 1, TLV_EMV_VALUE_CVM_RESULT, 0};
static const tlv_codec_t cvm_result_3_3_1_0 = {&cvm_result_3_3_1_0_config, emv_value_decode,
                                               emv_value_encode};
static const emv_value_rule_t number_list_2_8_2_3_config = {2, 8, 2, TLV_EMV_VALUE_NUMBER_LIST, 3};
static const tlv_codec_t number_list_2_8_2_3 = {&number_list_2_8_2_3_config, emv_value_decode,
                                                emv_value_encode};
static const tlv_number_codec_config_t number_bcd_2_4_1_8_config = {TLV_NUMBER_BCD, 2, 4, 1, 8};
static const tlv_codec_t number_bcd_2_4_1_8 = {&number_bcd_2_4_1_8_config, tlv_number_decode,
                                               tlv_number_encode};
static const emv_value_rule_t number_list_1_4_1_1_config = {1, 4, 1, TLV_EMV_VALUE_NUMBER_LIST, 1};
static const tlv_codec_t number_list_1_4_1_1 = {&number_list_1_4_1_1_config, emv_value_decode,
                                                emv_value_encode};
static const emv_value_rule_t biometric_1_3_1_0_config = {1, 3, 1, TLV_EMV_VALUE_BIOMETRIC, 0};
static const tlv_codec_t biometric_1_3_1_0 = {&biometric_1_3_1_0_config, emv_value_decode,
                                              emv_value_encode};

enum {
    index_iin,
    index_adf_name,
    index_application_label,
    index_track2_equivalent_data,
    index_pan,
    index_application_template,
    index_fci_template,
    index_read_record_template,
    index_issuer_script_template1,
    index_issuer_script_template2,
    index_directory_discretionary_template,
    index_response_template2,
    index_response_template1,
    index_amount_authorised_binary,
    index_aip,
    index_command_template,
    index_df_name,
    index_issuer_script_command,
    index_application_priority_indicator,
    index_sfi,
    index_authorisation_code,
    index_authorisation_response_code,
    index_cdol1,
    index_cdol2,
    index_cvm_list,
    index_ca_public_key_index,
    index_issuer_public_key_certificate,
    index_issuer_authentication_data,
    index_issuer_public_key_remainder,
    index_signed_static_application_data,
    index_afl,
    index_tvr,
    index_tdol,
    index_tc_hash_value,
    index_transaction_pin_data,
    index_transaction_date,
    index_tsi,
    index_transaction_type,
    index_ddf_name,
    index_fci_proprietary_template,
    index_cardholder_name,
    index_application_expiration_date,
    index_application_effective_date,
    index_issuer_country_code,
    index_transaction_currency_code,
    index_language_preference,
    index_service_code,
    index_pan_sequence_number,
    index_transaction_currency_exponent,
    index_issuer_url,
    index_iban,
    index_bic,
    index_issuer_country_alpha2,
    index_issuer_country_alpha3,
    index_account_type,
    index_biometric_information_template,
    index_acquirer_identifier,
    index_amount_authorised,
    index_amount_other,
    index_amount_other_binary,
    index_application_discretionary_data,
    index_aid_terminal,
    index_application_usage_control,
    index_application_version_card,
    index_application_version_terminal,
    index_asrpd,
    index_cardholder_name_extended,
    index_iin_extended,
    index_issuer_action_code_default,
    index_issuer_action_code_denial,
    index_issuer_action_code_online,
    index_issuer_application_data,
    index_issuer_code_table_index,
    index_application_preferred_name,
    index_last_online_atc,
    index_lower_consecutive_offline_limit,
    index_merchant_category_code,
    index_merchant_identifier,
    index_pin_try_counter,
    index_issuer_script_identifier,
    index_token_requestor_id,
    index_terminal_country_code,
    index_terminal_floor_limit,
    index_terminal_identification,
    index_terminal_risk_management_data,
    index_ifd_serial_number,
    index_track1_discretionary_data,
    index_track2_discretionary_data,
    index_transaction_time,
    index_ca_public_key_index_terminal,
    index_upper_consecutive_offline_limit,
    index_payment_account_reference,
    index_last4_pan,
    index_application_cryptogram,
    index_cryptogram_information_data,
    index_icc_pin_public_key_certificate,
    index_icc_pin_public_key_exponent,
    index_icc_pin_public_key_remainder,
    index_biometric_terminal_capabilities,
    index_card_bit_group_template,
    index_issuer_public_key_exponent,
    index_terminal_capabilities,
    index_cvm_results,
    index_terminal_type,
    index_atc,
    index_unpredictable_number,
    index_pdol,
    index_pos_entry_mode,
    index_amount_reference_currency,
    index_application_reference_currency,
    index_transaction_reference_currency_code,
    index_transaction_reference_currency_exponent,
    index_additional_terminal_capabilities,
    index_transaction_sequence_counter,
    index_application_currency_code,
    index_application_reference_currency_exponent,
    index_application_currency_exponent,
    index_data_authentication_code,
    index_icc_public_key_certificate,
    index_icc_public_key_exponent,
    index_icc_public_key_remainder,
    index_ddol,
    index_sda_tag_list,
    index_signed_dynamic_application_data,
    index_icc_dynamic_number,
    index_log_entry,
    index_merchant_name_and_location,
    index_log_format,
    index_fci_issuer_discretionary_data,
    index_offline_bit_group_template,
    index_online_bit_group_template,
    index_biometric_try_counters_template,
    index_preferred_attempts_template,
    index_biometric_verification_data_template,
    count_BASE
};
static const tlv_schema_entry_t schema_BASE[] = {
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
    [index_cvm_list] = {{tag_8e, 1}, 10, 252, 0, "cvm_list", 0},
    [index_ca_public_key_index] = {{tag_8f, 1}, 1, 1, 0, "ca_public_key_index", 0},
    [index_issuer_public_key_certificate] =
        {{tag_90, 1}, 1, SIZE_MAX, 0, "issuer_public_key_certificate", 0},
    [index_issuer_authentication_data] = {{tag_91, 1}, 8, 16, 0, "issuer_authentication_data", 0},
    [index_issuer_public_key_remainder] =
        {{tag_92, 1}, 1, SIZE_MAX, 0, "issuer_public_key_remainder", 0},
    [index_signed_static_application_data] =
        {{tag_93, 1}, 1, SIZE_MAX, 0, "signed_static_application_data", 0},
    [index_afl] = {{tag_94, 1}, 4, 252, 0, "afl", 0},
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
    [index_language_preference] = {{tag_5f2d, 2}, 2, 8, 0, "language_preference", 0},
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
        {{tag_9f3b, 2}, 2, 8, 0, "application_reference_currency", 0},
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
static const tlv_emv_definition_t dictionary_BASE[] = {
    {.schema = &schema_BASE[index_iin],
     .name = "iin",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_bcd_3_3_1_6,
     .length_step = 1},
    {.schema = &schema_BASE[index_adf_name],
     .name = "adf_name",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_application_label],
     .name = "application_label",
     .value_kind = TLV_EMV_VALUE_TEXT,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_track2_equivalent_data],
     .name = "track2_equivalent_data",
     .value_kind = TLV_EMV_VALUE_TRACK2,
     .codec = &track2_0_19_1_0,
     .length_step = 1},
    {.schema = &schema_BASE[index_pan],
     .name = "pan",
     .value_kind = TLV_EMV_VALUE_DIGITS,
     .codec = &digits_1_10_1_19,
     .length_step = 1},
    {.schema = &schema_BASE[index_application_template],
     .name = "application_template",
     .value_kind = TLV_EMV_VALUE_TEMPLATE,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_fci_template],
     .name = "fci_template",
     .value_kind = TLV_EMV_VALUE_TEMPLATE,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_read_record_template],
     .name = "read_record_template",
     .value_kind = TLV_EMV_VALUE_TEMPLATE,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_issuer_script_template1],
     .name = "issuer_script_template1",
     .value_kind = TLV_EMV_VALUE_TEMPLATE,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_issuer_script_template2],
     .name = "issuer_script_template2",
     .value_kind = TLV_EMV_VALUE_TEMPLATE,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_directory_discretionary_template],
     .name = "directory_discretionary_template",
     .value_kind = TLV_EMV_VALUE_TEMPLATE,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_response_template2],
     .name = "response_template2",
     .value_kind = TLV_EMV_VALUE_TEMPLATE,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_response_template1],
     .name = "response_template1",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_amount_authorised_binary],
     .name = "amount_authorised_binary",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_binary_be_4_4_1_0,
     .length_step = 1},
    {.schema = &schema_BASE[index_aip],
     .name = "aip",
     .value_kind = TLV_EMV_VALUE_FLAGS,
     .codec = &number_binary_be_2_2_1_0,
     .length_step = 1},
    {.schema = &schema_BASE[index_command_template],
     .name = "command_template",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_df_name],
     .name = "df_name",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_issuer_script_command],
     .name = "issuer_script_command",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_application_priority_indicator],
     .name = "application_priority_indicator",
     .value_kind = TLV_EMV_VALUE_FLAGS,
     .codec = &number_binary_be_1_1_1_0,
     .length_step = 1},
    {.schema = &schema_BASE[index_sfi],
     .name = "sfi",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_binary_be_1_1_1_0,
     .length_step = 1},
    {.schema = &schema_BASE[index_authorisation_code],
     .name = "authorisation_code",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_authorisation_response_code],
     .name = "authorisation_response_code",
     .value_kind = TLV_EMV_VALUE_TEXT,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_cdol1],
     .name = "cdol1",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_cdol2],
     .name = "cdol2",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_cvm_list],
     .name = "cvm_list",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 2},
    {.schema = &schema_BASE[index_ca_public_key_index],
     .name = "ca_public_key_index",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_binary_be_1_1_1_0,
     .length_step = 1},
    {.schema = &schema_BASE[index_issuer_public_key_certificate],
     .name = "issuer_public_key_certificate",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_issuer_authentication_data],
     .name = "issuer_authentication_data",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_issuer_public_key_remainder],
     .name = "issuer_public_key_remainder",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_signed_static_application_data],
     .name = "signed_static_application_data",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_afl],
     .name = "afl",
     .value_kind = TLV_EMV_VALUE_AFL,
     .codec = &afl_4_252_4_0,
     .length_step = 4},
    {.schema = &schema_BASE[index_tvr],
     .name = "tvr",
     .value_kind = TLV_EMV_VALUE_FLAGS,
     .codec = &number_binary_be_5_5_1_0,
     .length_step = 1},
    {.schema = &schema_BASE[index_tdol],
     .name = "tdol",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_tc_hash_value],
     .name = "tc_hash_value",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_transaction_pin_data],
     .name = "transaction_pin_data",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_transaction_date],
     .name = "transaction_date",
     .value_kind = TLV_EMV_VALUE_DATE,
     .codec = &date_3_3_1_0,
     .length_step = 1},
    {.schema = &schema_BASE[index_tsi],
     .name = "tsi",
     .value_kind = TLV_EMV_VALUE_FLAGS,
     .codec = &number_binary_be_2_2_1_0,
     .length_step = 1},
    {.schema = &schema_BASE[index_transaction_type],
     .name = "transaction_type",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_bcd_1_1_1_2,
     .length_step = 1},
    {.schema = &schema_BASE[index_ddf_name],
     .name = "ddf_name",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_fci_proprietary_template],
     .name = "fci_proprietary_template",
     .value_kind = TLV_EMV_VALUE_TEMPLATE,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_cardholder_name],
     .name = "cardholder_name",
     .value_kind = TLV_EMV_VALUE_TEXT,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_application_expiration_date],
     .name = "application_expiration_date",
     .value_kind = TLV_EMV_VALUE_DATE,
     .codec = &date_3_3_1_0,
     .length_step = 1},
    {.schema = &schema_BASE[index_application_effective_date],
     .name = "application_effective_date",
     .value_kind = TLV_EMV_VALUE_DATE,
     .codec = &date_3_3_1_0,
     .length_step = 1},
    {.schema = &schema_BASE[index_issuer_country_code],
     .name = "issuer_country_code",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_bcd_2_2_1_3,
     .length_step = 1},
    {.schema = &schema_BASE[index_transaction_currency_code],
     .name = "transaction_currency_code",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_bcd_2_2_1_3,
     .length_step = 1},
    {.schema = &schema_BASE[index_language_preference],
     .name = "language_preference",
     .value_kind = TLV_EMV_VALUE_TEXT,
     .codec = NULL,
     .length_step = 2},
    {.schema = &schema_BASE[index_service_code],
     .name = "service_code",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_bcd_2_2_1_3,
     .length_step = 1},
    {.schema = &schema_BASE[index_pan_sequence_number],
     .name = "pan_sequence_number",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_bcd_1_1_1_2,
     .length_step = 1},
    {.schema = &schema_BASE[index_transaction_currency_exponent],
     .name = "transaction_currency_exponent",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_bcd_1_1_1_1,
     .length_step = 1},
    {.schema = &schema_BASE[index_issuer_url],
     .name = "issuer_url",
     .value_kind = TLV_EMV_VALUE_TEXT,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_iban],
     .name = "iban",
     .value_kind = TLV_EMV_VALUE_TEXT,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_bic],
     .name = "bic",
     .value_kind = TLV_EMV_VALUE_TEXT,
     .codec = NULL,
     .length_step = 3},
    {.schema = &schema_BASE[index_issuer_country_alpha2],
     .name = "issuer_country_alpha2",
     .value_kind = TLV_EMV_VALUE_TEXT,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_issuer_country_alpha3],
     .name = "issuer_country_alpha3",
     .value_kind = TLV_EMV_VALUE_TEXT,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_account_type],
     .name = "account_type",
     .value_kind = TLV_EMV_VALUE_ACCOUNT,
     .codec = &account_1_1_1_0,
     .length_step = 1},
    {.schema = &schema_BASE[index_biometric_information_template],
     .name = "biometric_information_template",
     .value_kind = TLV_EMV_VALUE_TEMPLATE,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_acquirer_identifier],
     .name = "acquirer_identifier",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_bcd_6_6_1_11,
     .length_step = 1},
    {.schema = &schema_BASE[index_amount_authorised],
     .name = "amount_authorised",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &tlv_emv_codec_amount,
     .length_step = 1},
    {.schema = &schema_BASE[index_amount_other],
     .name = "amount_other",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &tlv_emv_codec_amount,
     .length_step = 1},
    {.schema = &schema_BASE[index_amount_other_binary],
     .name = "amount_other_binary",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_binary_be_4_4_1_0,
     .length_step = 1},
    {.schema = &schema_BASE[index_application_discretionary_data],
     .name = "application_discretionary_data",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_aid_terminal],
     .name = "aid_terminal",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_application_usage_control],
     .name = "application_usage_control",
     .value_kind = TLV_EMV_VALUE_FLAGS,
     .codec = &number_binary_be_2_2_1_0,
     .length_step = 1},
    {.schema = &schema_BASE[index_application_version_card],
     .name = "application_version_card",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_binary_be_2_2_1_0,
     .length_step = 1},
    {.schema = &schema_BASE[index_application_version_terminal],
     .name = "application_version_terminal",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_binary_be_2_2_1_0,
     .length_step = 1},
    {.schema = &schema_BASE[index_asrpd],
     .name = "asrpd",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_cardholder_name_extended],
     .name = "cardholder_name_extended",
     .value_kind = TLV_EMV_VALUE_TEXT,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_iin_extended],
     .name = "iin_extended",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_bcd_3_4_1_8,
     .length_step = 1},
    {.schema = &schema_BASE[index_issuer_action_code_default],
     .name = "issuer_action_code_default",
     .value_kind = TLV_EMV_VALUE_FLAGS,
     .codec = &number_binary_be_5_5_1_0,
     .length_step = 1},
    {.schema = &schema_BASE[index_issuer_action_code_denial],
     .name = "issuer_action_code_denial",
     .value_kind = TLV_EMV_VALUE_FLAGS,
     .codec = &number_binary_be_5_5_1_0,
     .length_step = 1},
    {.schema = &schema_BASE[index_issuer_action_code_online],
     .name = "issuer_action_code_online",
     .value_kind = TLV_EMV_VALUE_FLAGS,
     .codec = &number_binary_be_5_5_1_0,
     .length_step = 1},
    {.schema = &schema_BASE[index_issuer_application_data],
     .name = "issuer_application_data",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_issuer_code_table_index],
     .name = "issuer_code_table_index",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_bcd_1_1_1_2,
     .length_step = 1},
    {.schema = &schema_BASE[index_application_preferred_name],
     .name = "application_preferred_name",
     .value_kind = TLV_EMV_VALUE_TEXT,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_last_online_atc],
     .name = "last_online_atc",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_binary_be_2_2_1_0,
     .length_step = 1},
    {.schema = &schema_BASE[index_lower_consecutive_offline_limit],
     .name = "lower_consecutive_offline_limit",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_binary_be_1_1_1_0,
     .length_step = 1},
    {.schema = &schema_BASE[index_merchant_category_code],
     .name = "merchant_category_code",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_bcd_2_2_1_4,
     .length_step = 1},
    {.schema = &schema_BASE[index_merchant_identifier],
     .name = "merchant_identifier",
     .value_kind = TLV_EMV_VALUE_TEXT,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_pin_try_counter],
     .name = "pin_try_counter",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_binary_be_1_1_1_0,
     .length_step = 1},
    {.schema = &schema_BASE[index_issuer_script_identifier],
     .name = "issuer_script_identifier",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_token_requestor_id],
     .name = "token_requestor_id",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_bcd_6_6_1_11,
     .length_step = 1},
    {.schema = &schema_BASE[index_terminal_country_code],
     .name = "terminal_country_code",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_bcd_2_2_1_3,
     .length_step = 1},
    {.schema = &schema_BASE[index_terminal_floor_limit],
     .name = "terminal_floor_limit",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_binary_be_4_4_1_0,
     .length_step = 1},
    {.schema = &schema_BASE[index_terminal_identification],
     .name = "terminal_identification",
     .value_kind = TLV_EMV_VALUE_TEXT,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_terminal_risk_management_data],
     .name = "terminal_risk_management_data",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_ifd_serial_number],
     .name = "ifd_serial_number",
     .value_kind = TLV_EMV_VALUE_TEXT,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_track1_discretionary_data],
     .name = "track1_discretionary_data",
     .value_kind = TLV_EMV_VALUE_TEXT,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_track2_discretionary_data],
     .name = "track2_discretionary_data",
     .value_kind = TLV_EMV_VALUE_DIGITS,
     .codec = &digits_0_SIZE_MAX_1_0,
     .length_step = 1},
    {.schema = &schema_BASE[index_transaction_time],
     .name = "transaction_time",
     .value_kind = TLV_EMV_VALUE_TIME,
     .codec = &time_3_3_1_0,
     .length_step = 1},
    {.schema = &schema_BASE[index_ca_public_key_index_terminal],
     .name = "ca_public_key_index_terminal",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_binary_be_1_1_1_0,
     .length_step = 1},
    {.schema = &schema_BASE[index_upper_consecutive_offline_limit],
     .name = "upper_consecutive_offline_limit",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_binary_be_1_1_1_0,
     .length_step = 1},
    {.schema = &schema_BASE[index_payment_account_reference],
     .name = "payment_account_reference",
     .value_kind = TLV_EMV_VALUE_TEXT,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_last4_pan],
     .name = "last4_pan",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_bcd_2_2_1_4,
     .length_step = 1},
    {.schema = &schema_BASE[index_application_cryptogram],
     .name = "application_cryptogram",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_cryptogram_information_data],
     .name = "cryptogram_information_data",
     .value_kind = TLV_EMV_VALUE_CRYPTOGRAM,
     .codec = &cryptogram_1_1_1_0,
     .length_step = 1},
    {.schema = &schema_BASE[index_icc_pin_public_key_certificate],
     .name = "icc_pin_public_key_certificate",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_icc_pin_public_key_exponent],
     .name = "icc_pin_public_key_exponent",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_binary_be_1_3_2_0,
     .length_step = 2},
    {.schema = &schema_BASE[index_icc_pin_public_key_remainder],
     .name = "icc_pin_public_key_remainder",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_biometric_terminal_capabilities],
     .name = "biometric_terminal_capabilities",
     .value_kind = TLV_EMV_VALUE_FLAGS,
     .codec = &number_binary_be_3_3_1_0,
     .length_step = 1},
    {.schema = &schema_BASE[index_card_bit_group_template],
     .name = "card_bit_group_template",
     .value_kind = TLV_EMV_VALUE_TEMPLATE,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_issuer_public_key_exponent],
     .name = "issuer_public_key_exponent",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_binary_be_1_3_2_0,
     .length_step = 2},
    {.schema = &schema_BASE[index_terminal_capabilities],
     .name = "terminal_capabilities",
     .value_kind = TLV_EMV_VALUE_FLAGS,
     .codec = &number_binary_be_3_3_1_0,
     .length_step = 1},
    {.schema = &schema_BASE[index_cvm_results],
     .name = "cvm_results",
     .value_kind = TLV_EMV_VALUE_CVM_RESULT,
     .codec = &cvm_result_3_3_1_0,
     .length_step = 1},
    {.schema = &schema_BASE[index_terminal_type],
     .name = "terminal_type",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_bcd_1_1_1_2,
     .length_step = 1},
    {.schema = &schema_BASE[index_atc],
     .name = "atc",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_binary_be_2_2_1_0,
     .length_step = 1},
    {.schema = &schema_BASE[index_unpredictable_number],
     .name = "unpredictable_number",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_pdol],
     .name = "pdol",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_pos_entry_mode],
     .name = "pos_entry_mode",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_bcd_1_1_1_2,
     .length_step = 1},
    {.schema = &schema_BASE[index_amount_reference_currency],
     .name = "amount_reference_currency",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_binary_be_4_4_1_0,
     .length_step = 1},
    {.schema = &schema_BASE[index_application_reference_currency],
     .name = "application_reference_currency",
     .value_kind = TLV_EMV_VALUE_NUMBER_LIST,
     .codec = &number_list_2_8_2_3,
     .length_step = 2},
    {.schema = &schema_BASE[index_transaction_reference_currency_code],
     .name = "transaction_reference_currency_code",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_bcd_2_2_1_3,
     .length_step = 1},
    {.schema = &schema_BASE[index_transaction_reference_currency_exponent],
     .name = "transaction_reference_currency_exponent",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_bcd_1_1_1_1,
     .length_step = 1},
    {.schema = &schema_BASE[index_additional_terminal_capabilities],
     .name = "additional_terminal_capabilities",
     .value_kind = TLV_EMV_VALUE_FLAGS,
     .codec = &number_binary_be_5_5_1_0,
     .length_step = 1},
    {.schema = &schema_BASE[index_transaction_sequence_counter],
     .name = "transaction_sequence_counter",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_bcd_2_4_1_8,
     .length_step = 1},
    {.schema = &schema_BASE[index_application_currency_code],
     .name = "application_currency_code",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_bcd_2_2_1_3,
     .length_step = 1},
    {.schema = &schema_BASE[index_application_reference_currency_exponent],
     .name = "application_reference_currency_exponent",
     .value_kind = TLV_EMV_VALUE_NUMBER_LIST,
     .codec = &number_list_1_4_1_1,
     .length_step = 1},
    {.schema = &schema_BASE[index_application_currency_exponent],
     .name = "application_currency_exponent",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_bcd_1_1_1_1,
     .length_step = 1},
    {.schema = &schema_BASE[index_data_authentication_code],
     .name = "data_authentication_code",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_icc_public_key_certificate],
     .name = "icc_public_key_certificate",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_icc_public_key_exponent],
     .name = "icc_public_key_exponent",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_binary_be_1_3_2_0,
     .length_step = 2},
    {.schema = &schema_BASE[index_icc_public_key_remainder],
     .name = "icc_public_key_remainder",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_ddol],
     .name = "ddol",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_sda_tag_list],
     .name = "sda_tag_list",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_signed_dynamic_application_data],
     .name = "signed_dynamic_application_data",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_icc_dynamic_number],
     .name = "icc_dynamic_number",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_log_entry],
     .name = "log_entry",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_merchant_name_and_location],
     .name = "merchant_name_and_location",
     .value_kind = TLV_EMV_VALUE_TEXT,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_log_format],
     .name = "log_format",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_fci_issuer_discretionary_data],
     .name = "fci_issuer_discretionary_data",
     .value_kind = TLV_EMV_VALUE_TEMPLATE,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_offline_bit_group_template],
     .name = "offline_bit_group_template",
     .value_kind = TLV_EMV_VALUE_TEMPLATE,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_online_bit_group_template],
     .name = "online_bit_group_template",
     .value_kind = TLV_EMV_VALUE_TEMPLATE,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_biometric_try_counters_template],
     .name = "biometric_try_counters_template",
     .value_kind = TLV_EMV_VALUE_TEMPLATE,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_preferred_attempts_template],
     .name = "preferred_attempts_template",
     .value_kind = TLV_EMV_VALUE_TEMPLATE,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BASE[index_biometric_verification_data_template],
     .name = "biometric_verification_data_template",
     .value_kind = TLV_EMV_VALUE_TEMPLATE,
     .codec = NULL,
     .length_step = 1},
};

enum { index_biometric_header_template, count_BIT };
static const tlv_schema_entry_t schema_BIT[] = {
    [index_biometric_header_template] =
        {{tag_a1, 1}, 0, SIZE_MAX, 0, "biometric_header_template", 0},
};
static const tlv_emv_definition_t dictionary_BIT[] = {
    {.schema = &schema_BIT[index_biometric_header_template],
     .name = "biometric_header_template",
     .value_kind = TLV_EMV_VALUE_TEMPLATE,
     .codec = NULL,
     .length_step = 1},
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
static const tlv_emv_definition_t dictionary_BHT[] = {
    {.schema = &schema_BHT[index_biometric_header_version],
     .name = "biometric_header_version",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_binary_be_2_2_1_0,
     .length_step = 1},
    {.schema = &schema_BHT[index_biometric_type],
     .name = "biometric_type",
     .value_kind = TLV_EMV_VALUE_BIOMETRIC,
     .codec = &biometric_1_3_1_0,
     .length_step = 1},
    {.schema = &schema_BHT[index_biometric_subtype],
     .name = "biometric_subtype",
     .value_kind = TLV_EMV_VALUE_FLAGS,
     .codec = &number_binary_be_1_1_1_0,
     .length_step = 1},
    {.schema = &schema_BHT[index_biometric_creation_datetime],
     .name = "biometric_creation_datetime",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BHT[index_biometric_creator],
     .name = "biometric_creator",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BHT[index_biometric_validity_period],
     .name = "biometric_validity_period",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BHT[index_biometric_product_id],
     .name = "biometric_product_id",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_binary_be_2_2_1_0,
     .length_step = 1},
    {.schema = &schema_BHT[index_biometric_format_owner],
     .name = "biometric_format_owner",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_binary_be_2_2_1_0,
     .length_step = 1},
    {.schema = &schema_BHT[index_biometric_format_type],
     .name = "biometric_format_type",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_binary_be_2_2_1_0,
     .length_step = 1},
    {.schema = &schema_BHT[index_biometric_solution_id],
     .name = "biometric_solution_id",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BHT[index_biometric_matching_parameters],
     .name = "biometric_matching_parameters",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BHT[index_bht1],
     .name = "bht1",
     .value_kind = TLV_EMV_VALUE_TEMPLATE,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BHT[index_bht2],
     .name = "bht2",
     .value_kind = TLV_EMV_VALUE_TEMPLATE,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BHT[index_biometric_matching_parameters_template],
     .name = "biometric_matching_parameters_template",
     .value_kind = TLV_EMV_VALUE_TEMPLATE,
     .codec = NULL,
     .length_step = 1},
};

enum { index_bht_format_owner, index_bht_format_type, count_BHT_FORMAT };
static const tlv_schema_entry_t schema_BHT_FORMAT[] = {
    [index_bht_format_owner] = {{tag_87, 1}, 2, 2, 0, "bht_format_owner", 0},
    [index_bht_format_type] = {{tag_88, 1}, 2, 2, 0, "bht_format_type", 0},
};
static const tlv_emv_definition_t dictionary_BHT_FORMAT[] = {
    {.schema = &schema_BHT_FORMAT[index_bht_format_owner],
     .name = "bht_format_owner",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_binary_be_2_2_1_0,
     .length_step = 1},
    {.schema = &schema_BHT_FORMAT[index_bht_format_type],
     .name = "bht_format_type",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_binary_be_2_2_1_0,
     .length_step = 1},
};

enum { index_bit_count, index_group_bit, count_BIT_GROUP };
static const tlv_schema_entry_t schema_BIT_GROUP[] = {
    [index_bit_count] = {{tag_02, 1}, 1, 1, 0, "bit_count", 0},
    [index_group_bit] = {{tag_7f60, 2}, 0, SIZE_MAX, 0, "group_bit", 0},
};
static const tlv_emv_definition_t dictionary_BIT_GROUP[] = {
    {.schema = &schema_BIT_GROUP[index_bit_count],
     .name = "bit_count",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_binary_be_1_1_1_0,
     .length_step = 1},
    {.schema = &schema_BIT_GROUP[index_group_bit],
     .name = "group_bit",
     .value_kind = TLV_EMV_VALUE_TEMPLATE,
     .codec = NULL,
     .length_step = 1},
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
static const tlv_emv_definition_t dictionary_BIOMETRIC_COUNTERS[] = {
    {.schema = &schema_BIOMETRIC_COUNTERS[index_facial_try_counter],
     .name = "facial_try_counter",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_binary_be_1_1_1_0,
     .length_step = 1},
    {.schema = &schema_BIOMETRIC_COUNTERS[index_finger_try_counter],
     .name = "finger_try_counter",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_binary_be_1_1_1_0,
     .length_step = 1},
    {.schema = &schema_BIOMETRIC_COUNTERS[index_iris_try_counter],
     .name = "iris_try_counter",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_binary_be_1_1_1_0,
     .length_step = 1},
    {.schema = &schema_BIOMETRIC_COUNTERS[index_palm_try_counter],
     .name = "palm_try_counter",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_binary_be_1_1_1_0,
     .length_step = 1},
    {.schema = &schema_BIOMETRIC_COUNTERS[index_voice_try_counter],
     .name = "voice_try_counter",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_binary_be_1_1_1_0,
     .length_step = 1},
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
static const tlv_emv_definition_t dictionary_BIOMETRIC_ATTEMPTS[] = {
    {.schema = &schema_BIOMETRIC_ATTEMPTS[index_preferred_facial_attempts],
     .name = "preferred_facial_attempts",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_binary_be_1_1_1_0,
     .length_step = 1},
    {.schema = &schema_BIOMETRIC_ATTEMPTS[index_preferred_finger_attempts],
     .name = "preferred_finger_attempts",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_binary_be_1_1_1_0,
     .length_step = 1},
    {.schema = &schema_BIOMETRIC_ATTEMPTS[index_preferred_iris_attempts],
     .name = "preferred_iris_attempts",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_binary_be_1_1_1_0,
     .length_step = 1},
    {.schema = &schema_BIOMETRIC_ATTEMPTS[index_preferred_palm_attempts],
     .name = "preferred_palm_attempts",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_binary_be_1_1_1_0,
     .length_step = 1},
    {.schema = &schema_BIOMETRIC_ATTEMPTS[index_preferred_voice_attempts],
     .name = "preferred_voice_attempts",
     .value_kind = TLV_EMV_VALUE_NUMBER,
     .codec = &number_binary_be_1_1_1_0,
     .length_step = 1},
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
static const tlv_emv_definition_t dictionary_BIOMETRIC_VERIFICATION[] = {
    {.schema = &schema_BIOMETRIC_VERIFICATION[index_verification_biometric_type],
     .name = "verification_biometric_type",
     .value_kind = TLV_EMV_VALUE_BIOMETRIC,
     .codec = &biometric_1_3_1_0,
     .length_step = 1},
    {.schema = &schema_BIOMETRIC_VERIFICATION[index_verification_biometric_solution_id],
     .name = "verification_biometric_solution_id",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BIOMETRIC_VERIFICATION[index_enciphered_biometric_key_seed],
     .name = "enciphered_biometric_key_seed",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BIOMETRIC_VERIFICATION[index_enciphered_biometric_data],
     .name = "enciphered_biometric_data",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
    {.schema = &schema_BIOMETRIC_VERIFICATION[index_biometric_data_mac],
     .name = "biometric_data_mac",
     .value_kind = TLV_EMV_VALUE_BYTES,
     .codec = NULL,
     .length_step = 1},
};

static const tlv_schema_t schemas[] = {
    [TLV_EMV_CONTEXT_BASE] = {schema_BASE, count_BASE},
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
const tlv_schema_t tlv_emv_schema = {schema_BASE, count_BASE};

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
        if (entry->schema && entry->schema->tag.data && tlv_tag_equal(entry->schema->tag, *tag))
            return entry;
    }
    return NULL;
}

const tlv_emv_definition_t* tlv_emv_find(tlv_emv_context_t context, const tlv_tag_t* tag) {
    return tlv_emv_dictionary_find(tlv_emv_dictionary_for(context), tag);
}
