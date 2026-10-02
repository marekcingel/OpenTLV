// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_TLVPP_BUILTINS_EMV_CODEC_HPP
#define OPENTLV_TLVPP_BUILTINS_EMV_CODEC_HPP

/** @file
 * @brief C++ EMV codecs and fields for every codec-bearing builtin dictionary entry.
 *
 * Codecs interpret Value only, delegate validation to the canonical C engine,
 * and implement the generic typed-field contract. Fixed-size codecs allocate nothing; owning digit
 * decoding may allocate. Borrowed results require immutable input to outlive every retained copy.
 * Encode storage must be disjoint from all borrowed input; nullptr/0 validates
 * and measures. Codec errors are propagated unchanged.
 */
#include <limits>
#include "tlv/builtins/emv/emv.h"
#include "tlv/builtins/emv/emv_codec.h"
#include "tlv++/codec/typed.hpp"

namespace tlv {
/** @brief EMV Contact Book 3 Value semantics and explicitly scoped dictionary fields. */
namespace emv {
/** @brief Self-contained EMV account value; see #tlv_emv_account_type_t. */
using account = tlv_emv_account_type_t;
/** @brief Self-contained EMV afl value; see #tlv_emv_afl_t. */
using afl = tlv_emv_afl_t;
/** @brief Self-contained EMV biometric value; see #tlv_emv_biometric_type_t. */
using biometric = tlv_emv_biometric_type_t;
/** @brief Self-contained EMV cryptogram value; see #tlv_emv_cryptogram_info_t. */
using cryptogram = tlv_emv_cryptogram_info_t;
/** @brief Self-contained EMV cvm result value; see #tlv_emv_cvm_result_t. */
using cvm_result = tlv_emv_cvm_result_t;
/** @brief Self-contained EMV date value; see #tlv_emv_date_t. */
using date = tlv_emv_date_t;
/** @brief Self-contained EMV number list value; see #tlv_emv_number_list_t. */
using number_list = tlv_emv_number_list_t;
/** @brief Self-contained EMV time value; see #tlv_emv_time_t. */
using time = tlv_emv_time_t;
/** @brief Self-contained EMV track2 value; see #tlv_emv_track2_t. */
using track2 = tlv_emv_track2_t;
} // namespace emv
/// @cond INTERNAL
namespace detail {
template <tlv_emv_context_t Context, typename Tag> struct emv_dictionary_codec_provider {
    static const tlv_codec_t* descriptor() {
        static const tlv_codec_t* const value = [] {
            auto        tag = detail::semantic_access::get(Tag::tag());
            const auto* entry = tlv_emv_find(Context, &tag);
            return entry ? entry->codec : nullptr;
        }();
        return value;
    }
};
template <typename T, typename Provider> struct emv_dictionary_value_codec {
    using value_type = T;
    static expected<T, tlv_codec_result_t> decode(bytes input) {
        T          result{};
        const auto rc =
            tlv_codec_decode(Provider::descriptor(), reinterpret_cast<const uint8_t*>(input.data()),
                             input.size(), &result, sizeof(result));
        if (rc != TLV_CODEC_OK) return unexpected<tlv_codec_result_t>(rc);
        return result;
    }
    static expected<size_t, tlv_codec_result_t> encode(const T& value, byte* output,
                                                       size_t capacity) {
        size_t     written = 0;
        const auto rc = tlv_codec_encode(Provider::descriptor(), &value, sizeof(value),
                                         reinterpret_cast<uint8_t*>(output), capacity, &written);
        if (rc != TLV_CODEC_OK) return unexpected<tlv_codec_result_t>(rc);
        return written;
    }
};
template <typename Provider> struct emv_dictionary_value_codec<std::string, Provider> {
    using value_type = std::string;
    static expected<std::string, tlv_codec_result_t> decode(bytes input) {
        if (!input.data() && input.size())
            return unexpected<tlv_codec_result_t>(TLV_CODEC_ERR_NULL_ARG);
        if (input.size() > (std::numeric_limits<size_t>::max() - 1) / 2)
            return unexpected<tlv_codec_result_t>(TLV_CODEC_ERR_INVALID_VALUE);
        std::vector<char> storage(input.size() * 2 + 1);
        const auto        rc =
            tlv_codec_decode(Provider::descriptor(), reinterpret_cast<const uint8_t*>(input.data()),
                             input.size(), storage.data(), storage.size());
        if (rc != TLV_CODEC_OK) return unexpected<tlv_codec_result_t>(rc);
        return std::string(storage.data());
    }
    static expected<size_t, tlv_codec_result_t> encode(const std::string& value, byte* output,
                                                       size_t capacity) {
        size_t     written = 0;
        const auto rc = tlv_codec_encode(Provider::descriptor(), value.c_str(), value.size(),
                                         reinterpret_cast<uint8_t*>(output), capacity, &written);
        if (rc != TLV_CODEC_OK) return unexpected<tlv_codec_result_t>(rc);
        return written;
    }
};
} // namespace detail
/// @endcond
namespace emv {
/** @brief Amount in unscaled minor units, encoded as six BCD bytes; see #tlv_emv_codec_amount. */
using amount_codec = tlv::codec_adapter<uint64_t, &tlv_emv_codec_amount>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 42 independently of input tags; no context fallback.
 */
using iin_codec = detail::emv_dictionary_value_codec<
    uint64_t, detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x42>>>;
/** @brief EMV iin field in the explicit BASE context. */
using iin_field = tlv::field<tlv::tag_constant<0x42>, iin_codec::value_type, iin_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 57 independently of input tags; no context fallback.
 */
using track2_equivalent_data_codec = detail::emv_dictionary_value_codec<
    tlv_emv_track2_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x57>>>;
/** @brief EMV track2 equivalent data field in the explicit BASE context. */
using track2_equivalent_data_field =
    tlv::field<tlv::tag_constant<0x57>, track2_equivalent_data_codec::value_type,
               track2_equivalent_data_codec>;
/** @brief Owning decimal digit codec preserving leading zeroes; decoding may allocate.
 * @note Selects BASE / 5A independently of input tags; no context fallback.
 */
using pan_codec = detail::emv_dictionary_value_codec<
    std::string,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x5A>>>;
/** @brief EMV pan field in the explicit BASE context. */
using pan_field = tlv::field<tlv::tag_constant<0x5A>, pan_codec::value_type, pan_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 81 independently of input tags; no context fallback.
 */
using amount_authorised_binary_codec = detail::emv_dictionary_value_codec<
    uint64_t, detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x81>>>;
/** @brief EMV amount authorised binary field in the explicit BASE context. */
using amount_authorised_binary_field =
    tlv::field<tlv::tag_constant<0x81>, amount_authorised_binary_codec::value_type,
               amount_authorised_binary_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 82 independently of input tags; no context fallback.
 */
using aip_codec = detail::emv_dictionary_value_codec<
    uint64_t, detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x82>>>;
/** @brief EMV aip field in the explicit BASE context. */
using aip_field = tlv::field<tlv::tag_constant<0x82>, aip_codec::value_type, aip_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 87 independently of input tags; no context fallback.
 */
using application_priority_indicator_codec = detail::emv_dictionary_value_codec<
    uint64_t, detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x87>>>;
/** @brief EMV application priority indicator field in the explicit BASE context. */
using application_priority_indicator_field =
    tlv::field<tlv::tag_constant<0x87>, application_priority_indicator_codec::value_type,
               application_priority_indicator_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 88 independently of input tags; no context fallback.
 */
using sfi_codec = detail::emv_dictionary_value_codec<
    uint64_t, detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x88>>>;
/** @brief EMV sfi field in the explicit BASE context. */
using sfi_field = tlv::field<tlv::tag_constant<0x88>, sfi_codec::value_type, sfi_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 8F independently of input tags; no context fallback.
 */
using ca_public_key_index_codec = detail::emv_dictionary_value_codec<
    uint64_t, detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x8F>>>;
/** @brief EMV ca public key index field in the explicit BASE context. */
using ca_public_key_index_field =
    tlv::field<tlv::tag_constant<0x8F>, ca_public_key_index_codec::value_type,
               ca_public_key_index_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 94 independently of input tags; no context fallback.
 */
using afl_codec = detail::emv_dictionary_value_codec<
    tlv_emv_afl_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x94>>>;
/** @brief EMV afl field in the explicit BASE context. */
using afl_field = tlv::field<tlv::tag_constant<0x94>, afl_codec::value_type, afl_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 95 independently of input tags; no context fallback.
 */
using tvr_codec = detail::emv_dictionary_value_codec<
    uint64_t, detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x95>>>;
/** @brief EMV tvr field in the explicit BASE context. */
using tvr_field = tlv::field<tlv::tag_constant<0x95>, tvr_codec::value_type, tvr_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9A independently of input tags; no context fallback.
 */
using transaction_date_codec = detail::emv_dictionary_value_codec<
    tlv_emv_date_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9A>>>;
/** @brief EMV transaction date field in the explicit BASE context. */
using transaction_date_field =
    tlv::field<tlv::tag_constant<0x9A>, transaction_date_codec::value_type, transaction_date_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9B independently of input tags; no context fallback.
 */
using tsi_codec = detail::emv_dictionary_value_codec<
    uint64_t, detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9B>>>;
/** @brief EMV tsi field in the explicit BASE context. */
using tsi_field = tlv::field<tlv::tag_constant<0x9B>, tsi_codec::value_type, tsi_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9C independently of input tags; no context fallback.
 */
using transaction_type_codec = detail::emv_dictionary_value_codec<
    uint64_t, detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9C>>>;
/** @brief EMV transaction type field in the explicit BASE context. */
using transaction_type_field =
    tlv::field<tlv::tag_constant<0x9C>, transaction_type_codec::value_type, transaction_type_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 5F24 independently of input tags; no context fallback.
 */
using application_expiration_date_codec = detail::emv_dictionary_value_codec<
    tlv_emv_date_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x5F, 0x24>>>;
/** @brief EMV application expiration date field in the explicit BASE context. */
using application_expiration_date_field =
    tlv::field<tlv::tag_constant<0x5F, 0x24>, application_expiration_date_codec::value_type,
               application_expiration_date_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 5F25 independently of input tags; no context fallback.
 */
using application_effective_date_codec = detail::emv_dictionary_value_codec<
    tlv_emv_date_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x5F, 0x25>>>;
/** @brief EMV application effective date field in the explicit BASE context. */
using application_effective_date_field =
    tlv::field<tlv::tag_constant<0x5F, 0x25>, application_effective_date_codec::value_type,
               application_effective_date_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 5F28 independently of input tags; no context fallback.
 */
using issuer_country_code_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x5F, 0x28>>>;
/** @brief EMV issuer country code field in the explicit BASE context. */
using issuer_country_code_field =
    tlv::field<tlv::tag_constant<0x5F, 0x28>, issuer_country_code_codec::value_type,
               issuer_country_code_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 5F2A independently of input tags; no context fallback.
 */
using transaction_currency_code_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x5F, 0x2A>>>;
/** @brief EMV transaction currency code field in the explicit BASE context. */
using transaction_currency_code_field =
    tlv::field<tlv::tag_constant<0x5F, 0x2A>, transaction_currency_code_codec::value_type,
               transaction_currency_code_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 5F30 independently of input tags; no context fallback.
 */
using service_code_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x5F, 0x30>>>;
/** @brief EMV service code field in the explicit BASE context. */
using service_code_field =
    tlv::field<tlv::tag_constant<0x5F, 0x30>, service_code_codec::value_type, service_code_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 5F34 independently of input tags; no context fallback.
 */
using pan_sequence_number_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x5F, 0x34>>>;
/** @brief EMV pan sequence number field in the explicit BASE context. */
using pan_sequence_number_field =
    tlv::field<tlv::tag_constant<0x5F, 0x34>, pan_sequence_number_codec::value_type,
               pan_sequence_number_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 5F36 independently of input tags; no context fallback.
 */
using transaction_currency_exponent_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x5F, 0x36>>>;
/** @brief EMV transaction currency exponent field in the explicit BASE context. */
using transaction_currency_exponent_field =
    tlv::field<tlv::tag_constant<0x5F, 0x36>, transaction_currency_exponent_codec::value_type,
               transaction_currency_exponent_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 5F57 independently of input tags; no context fallback.
 */
using account_type_codec = detail::emv_dictionary_value_codec<
    tlv_emv_account_type_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x5F, 0x57>>>;
/** @brief EMV account type field in the explicit BASE context. */
using account_type_field =
    tlv::field<tlv::tag_constant<0x5F, 0x57>, account_type_codec::value_type, account_type_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9F01 independently of input tags; no context fallback.
 */
using acquirer_identifier_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9F, 0x01>>>;
/** @brief EMV acquirer identifier field in the explicit BASE context. */
using acquirer_identifier_field =
    tlv::field<tlv::tag_constant<0x9F, 0x01>, acquirer_identifier_codec::value_type,
               acquirer_identifier_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9F03 independently of input tags; no context fallback.
 */
using amount_other_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9F, 0x03>>>;
/** @brief EMV amount other field in the explicit BASE context. */
using amount_other_field =
    tlv::field<tlv::tag_constant<0x9F, 0x03>, amount_other_codec::value_type, amount_other_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9F04 independently of input tags; no context fallback.
 */
using amount_other_binary_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9F, 0x04>>>;
/** @brief EMV amount other binary field in the explicit BASE context. */
using amount_other_binary_field =
    tlv::field<tlv::tag_constant<0x9F, 0x04>, amount_other_binary_codec::value_type,
               amount_other_binary_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9F07 independently of input tags; no context fallback.
 */
using application_usage_control_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9F, 0x07>>>;
/** @brief EMV application usage control field in the explicit BASE context. */
using application_usage_control_field =
    tlv::field<tlv::tag_constant<0x9F, 0x07>, application_usage_control_codec::value_type,
               application_usage_control_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9F08 independently of input tags; no context fallback.
 */
using application_version_card_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9F, 0x08>>>;
/** @brief EMV application version card field in the explicit BASE context. */
using application_version_card_field =
    tlv::field<tlv::tag_constant<0x9F, 0x08>, application_version_card_codec::value_type,
               application_version_card_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9F09 independently of input tags; no context fallback.
 */
using application_version_terminal_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9F, 0x09>>>;
/** @brief EMV application version terminal field in the explicit BASE context. */
using application_version_terminal_field =
    tlv::field<tlv::tag_constant<0x9F, 0x09>, application_version_terminal_codec::value_type,
               application_version_terminal_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9F0C independently of input tags; no context fallback.
 */
using iin_extended_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9F, 0x0C>>>;
/** @brief EMV iin extended field in the explicit BASE context. */
using iin_extended_field =
    tlv::field<tlv::tag_constant<0x9F, 0x0C>, iin_extended_codec::value_type, iin_extended_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9F0D independently of input tags; no context fallback.
 */
using issuer_action_code_default_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9F, 0x0D>>>;
/** @brief EMV issuer action code default field in the explicit BASE context. */
using issuer_action_code_default_field =
    tlv::field<tlv::tag_constant<0x9F, 0x0D>, issuer_action_code_default_codec::value_type,
               issuer_action_code_default_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9F0E independently of input tags; no context fallback.
 */
using issuer_action_code_denial_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9F, 0x0E>>>;
/** @brief EMV issuer action code denial field in the explicit BASE context. */
using issuer_action_code_denial_field =
    tlv::field<tlv::tag_constant<0x9F, 0x0E>, issuer_action_code_denial_codec::value_type,
               issuer_action_code_denial_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9F0F independently of input tags; no context fallback.
 */
using issuer_action_code_online_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9F, 0x0F>>>;
/** @brief EMV issuer action code online field in the explicit BASE context. */
using issuer_action_code_online_field =
    tlv::field<tlv::tag_constant<0x9F, 0x0F>, issuer_action_code_online_codec::value_type,
               issuer_action_code_online_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9F11 independently of input tags; no context fallback.
 */
using issuer_code_table_index_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9F, 0x11>>>;
/** @brief EMV issuer code table index field in the explicit BASE context. */
using issuer_code_table_index_field =
    tlv::field<tlv::tag_constant<0x9F, 0x11>, issuer_code_table_index_codec::value_type,
               issuer_code_table_index_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9F13 independently of input tags; no context fallback.
 */
using last_online_atc_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9F, 0x13>>>;
/** @brief EMV last online atc field in the explicit BASE context. */
using last_online_atc_field = tlv::field<tlv::tag_constant<0x9F, 0x13>,
                                         last_online_atc_codec::value_type, last_online_atc_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9F14 independently of input tags; no context fallback.
 */
using lower_consecutive_offline_limit_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9F, 0x14>>>;
/** @brief EMV lower consecutive offline limit field in the explicit BASE context. */
using lower_consecutive_offline_limit_field =
    tlv::field<tlv::tag_constant<0x9F, 0x14>, lower_consecutive_offline_limit_codec::value_type,
               lower_consecutive_offline_limit_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9F15 independently of input tags; no context fallback.
 */
using merchant_category_code_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9F, 0x15>>>;
/** @brief EMV merchant category code field in the explicit BASE context. */
using merchant_category_code_field =
    tlv::field<tlv::tag_constant<0x9F, 0x15>, merchant_category_code_codec::value_type,
               merchant_category_code_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9F17 independently of input tags; no context fallback.
 */
using pin_try_counter_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9F, 0x17>>>;
/** @brief EMV pin try counter field in the explicit BASE context. */
using pin_try_counter_field = tlv::field<tlv::tag_constant<0x9F, 0x17>,
                                         pin_try_counter_codec::value_type, pin_try_counter_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9F19 independently of input tags; no context fallback.
 */
using token_requestor_id_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9F, 0x19>>>;
/** @brief EMV token requestor id field in the explicit BASE context. */
using token_requestor_id_field =
    tlv::field<tlv::tag_constant<0x9F, 0x19>, token_requestor_id_codec::value_type,
               token_requestor_id_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9F1A independently of input tags; no context fallback.
 */
using terminal_country_code_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9F, 0x1A>>>;
/** @brief EMV terminal country code field in the explicit BASE context. */
using terminal_country_code_field =
    tlv::field<tlv::tag_constant<0x9F, 0x1A>, terminal_country_code_codec::value_type,
               terminal_country_code_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9F1B independently of input tags; no context fallback.
 */
using terminal_floor_limit_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9F, 0x1B>>>;
/** @brief EMV terminal floor limit field in the explicit BASE context. */
using terminal_floor_limit_field =
    tlv::field<tlv::tag_constant<0x9F, 0x1B>, terminal_floor_limit_codec::value_type,
               terminal_floor_limit_codec>;
/** @brief Owning decimal digit codec preserving leading zeroes; decoding may allocate.
 * @note Selects BASE / 9F20 independently of input tags; no context fallback.
 */
using track2_discretionary_data_codec = detail::emv_dictionary_value_codec<
    std::string,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9F, 0x20>>>;
/** @brief EMV track2 discretionary data field in the explicit BASE context. */
using track2_discretionary_data_field =
    tlv::field<tlv::tag_constant<0x9F, 0x20>, track2_discretionary_data_codec::value_type,
               track2_discretionary_data_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9F21 independently of input tags; no context fallback.
 */
using transaction_time_codec = detail::emv_dictionary_value_codec<
    tlv_emv_time_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9F, 0x21>>>;
/** @brief EMV transaction time field in the explicit BASE context. */
using transaction_time_field =
    tlv::field<tlv::tag_constant<0x9F, 0x21>, transaction_time_codec::value_type,
               transaction_time_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9F22 independently of input tags; no context fallback.
 */
using ca_public_key_index_terminal_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9F, 0x22>>>;
/** @brief EMV ca public key index terminal field in the explicit BASE context. */
using ca_public_key_index_terminal_field =
    tlv::field<tlv::tag_constant<0x9F, 0x22>, ca_public_key_index_terminal_codec::value_type,
               ca_public_key_index_terminal_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9F23 independently of input tags; no context fallback.
 */
using upper_consecutive_offline_limit_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9F, 0x23>>>;
/** @brief EMV upper consecutive offline limit field in the explicit BASE context. */
using upper_consecutive_offline_limit_field =
    tlv::field<tlv::tag_constant<0x9F, 0x23>, upper_consecutive_offline_limit_codec::value_type,
               upper_consecutive_offline_limit_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9F25 independently of input tags; no context fallback.
 */
using last4_pan_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9F, 0x25>>>;
/** @brief EMV last4 pan field in the explicit BASE context. */
using last4_pan_field =
    tlv::field<tlv::tag_constant<0x9F, 0x25>, last4_pan_codec::value_type, last4_pan_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9F27 independently of input tags; no context fallback.
 */
using cryptogram_information_data_codec = detail::emv_dictionary_value_codec<
    tlv_emv_cryptogram_info_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9F, 0x27>>>;
/** @brief EMV cryptogram information data field in the explicit BASE context. */
using cryptogram_information_data_field =
    tlv::field<tlv::tag_constant<0x9F, 0x27>, cryptogram_information_data_codec::value_type,
               cryptogram_information_data_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9F2E independently of input tags; no context fallback.
 */
using icc_pin_public_key_exponent_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9F, 0x2E>>>;
/** @brief EMV icc pin public key exponent field in the explicit BASE context. */
using icc_pin_public_key_exponent_field =
    tlv::field<tlv::tag_constant<0x9F, 0x2E>, icc_pin_public_key_exponent_codec::value_type,
               icc_pin_public_key_exponent_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9F30 independently of input tags; no context fallback.
 */
using biometric_terminal_capabilities_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9F, 0x30>>>;
/** @brief EMV biometric terminal capabilities field in the explicit BASE context. */
using biometric_terminal_capabilities_field =
    tlv::field<tlv::tag_constant<0x9F, 0x30>, biometric_terminal_capabilities_codec::value_type,
               biometric_terminal_capabilities_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9F32 independently of input tags; no context fallback.
 */
using issuer_public_key_exponent_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9F, 0x32>>>;
/** @brief EMV issuer public key exponent field in the explicit BASE context. */
using issuer_public_key_exponent_field =
    tlv::field<tlv::tag_constant<0x9F, 0x32>, issuer_public_key_exponent_codec::value_type,
               issuer_public_key_exponent_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9F33 independently of input tags; no context fallback.
 */
using terminal_capabilities_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9F, 0x33>>>;
/** @brief EMV terminal capabilities field in the explicit BASE context. */
using terminal_capabilities_field =
    tlv::field<tlv::tag_constant<0x9F, 0x33>, terminal_capabilities_codec::value_type,
               terminal_capabilities_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9F34 independently of input tags; no context fallback.
 */
using cvm_results_codec = detail::emv_dictionary_value_codec<
    tlv_emv_cvm_result_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9F, 0x34>>>;
/** @brief EMV cvm results field in the explicit BASE context. */
using cvm_results_field =
    tlv::field<tlv::tag_constant<0x9F, 0x34>, cvm_results_codec::value_type, cvm_results_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9F35 independently of input tags; no context fallback.
 */
using terminal_type_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9F, 0x35>>>;
/** @brief EMV terminal type field in the explicit BASE context. */
using terminal_type_field =
    tlv::field<tlv::tag_constant<0x9F, 0x35>, terminal_type_codec::value_type, terminal_type_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9F36 independently of input tags; no context fallback.
 */
using atc_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9F, 0x36>>>;
/** @brief EMV atc field in the explicit BASE context. */
using atc_field = tlv::field<tlv::tag_constant<0x9F, 0x36>, atc_codec::value_type, atc_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9F39 independently of input tags; no context fallback.
 */
using pos_entry_mode_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9F, 0x39>>>;
/** @brief EMV pos entry mode field in the explicit BASE context. */
using pos_entry_mode_field = tlv::field<tlv::tag_constant<0x9F, 0x39>,
                                        pos_entry_mode_codec::value_type, pos_entry_mode_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9F3A independently of input tags; no context fallback.
 */
using amount_reference_currency_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9F, 0x3A>>>;
/** @brief EMV amount reference currency field in the explicit BASE context. */
using amount_reference_currency_field =
    tlv::field<tlv::tag_constant<0x9F, 0x3A>, amount_reference_currency_codec::value_type,
               amount_reference_currency_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9F3B independently of input tags; no context fallback.
 */
using application_reference_currency_codec = detail::emv_dictionary_value_codec<
    tlv_emv_number_list_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9F, 0x3B>>>;
/** @brief EMV application reference currency field in the explicit BASE context. */
using application_reference_currency_field =
    tlv::field<tlv::tag_constant<0x9F, 0x3B>, application_reference_currency_codec::value_type,
               application_reference_currency_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9F3C independently of input tags; no context fallback.
 */
using transaction_reference_currency_code_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9F, 0x3C>>>;
/** @brief EMV transaction reference currency code field in the explicit BASE context. */
using transaction_reference_currency_code_field =
    tlv::field<tlv::tag_constant<0x9F, 0x3C>, transaction_reference_currency_code_codec::value_type,
               transaction_reference_currency_code_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9F3D independently of input tags; no context fallback.
 */
using transaction_reference_currency_exponent_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9F, 0x3D>>>;
/** @brief EMV transaction reference currency exponent field in the explicit BASE context. */
using transaction_reference_currency_exponent_field =
    tlv::field<tlv::tag_constant<0x9F, 0x3D>,
               transaction_reference_currency_exponent_codec::value_type,
               transaction_reference_currency_exponent_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9F40 independently of input tags; no context fallback.
 */
using additional_terminal_capabilities_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9F, 0x40>>>;
/** @brief EMV additional terminal capabilities field in the explicit BASE context. */
using additional_terminal_capabilities_field =
    tlv::field<tlv::tag_constant<0x9F, 0x40>, additional_terminal_capabilities_codec::value_type,
               additional_terminal_capabilities_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9F41 independently of input tags; no context fallback.
 */
using transaction_sequence_counter_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9F, 0x41>>>;
/** @brief EMV transaction sequence counter field in the explicit BASE context. */
using transaction_sequence_counter_field =
    tlv::field<tlv::tag_constant<0x9F, 0x41>, transaction_sequence_counter_codec::value_type,
               transaction_sequence_counter_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9F42 independently of input tags; no context fallback.
 */
using application_currency_code_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9F, 0x42>>>;
/** @brief EMV application currency code field in the explicit BASE context. */
using application_currency_code_field =
    tlv::field<tlv::tag_constant<0x9F, 0x42>, application_currency_code_codec::value_type,
               application_currency_code_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9F43 independently of input tags; no context fallback.
 */
using application_reference_currency_exponent_codec = detail::emv_dictionary_value_codec<
    tlv_emv_number_list_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9F, 0x43>>>;
/** @brief EMV application reference currency exponent field in the explicit BASE context. */
using application_reference_currency_exponent_field =
    tlv::field<tlv::tag_constant<0x9F, 0x43>,
               application_reference_currency_exponent_codec::value_type,
               application_reference_currency_exponent_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9F44 independently of input tags; no context fallback.
 */
using application_currency_exponent_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9F, 0x44>>>;
/** @brief EMV application currency exponent field in the explicit BASE context. */
using application_currency_exponent_field =
    tlv::field<tlv::tag_constant<0x9F, 0x44>, application_currency_exponent_codec::value_type,
               application_currency_exponent_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BASE / 9F47 independently of input tags; no context fallback.
 */
using icc_public_key_exponent_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BASE, tlv::tag_constant<0x9F, 0x47>>>;
/** @brief EMV icc public key exponent field in the explicit BASE context. */
using icc_public_key_exponent_field =
    tlv::field<tlv::tag_constant<0x9F, 0x47>, icc_public_key_exponent_codec::value_type,
               icc_public_key_exponent_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BHT / 80 independently of input tags; no context fallback.
 */
using bht_biometric_header_version_codec = detail::emv_dictionary_value_codec<
    uint64_t, detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BHT, tlv::tag_constant<0x80>>>;
/** @brief EMV biometric header version field in the explicit BHT context. */
using bht_biometric_header_version_field =
    tlv::field<tlv::tag_constant<0x80>, bht_biometric_header_version_codec::value_type,
               bht_biometric_header_version_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BHT / 81 independently of input tags; no context fallback.
 */
using bht_biometric_type_codec = detail::emv_dictionary_value_codec<
    tlv_emv_biometric_type_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BHT, tlv::tag_constant<0x81>>>;
/** @brief EMV biometric type field in the explicit BHT context. */
using bht_biometric_type_field =
    tlv::field<tlv::tag_constant<0x81>, bht_biometric_type_codec::value_type,
               bht_biometric_type_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BHT / 82 independently of input tags; no context fallback.
 */
using bht_biometric_subtype_codec = detail::emv_dictionary_value_codec<
    uint64_t, detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BHT, tlv::tag_constant<0x82>>>;
/** @brief EMV biometric subtype field in the explicit BHT context. */
using bht_biometric_subtype_field =
    tlv::field<tlv::tag_constant<0x82>, bht_biometric_subtype_codec::value_type,
               bht_biometric_subtype_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BHT / 86 independently of input tags; no context fallback.
 */
using bht_biometric_product_id_codec = detail::emv_dictionary_value_codec<
    uint64_t, detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BHT, tlv::tag_constant<0x86>>>;
/** @brief EMV biometric product id field in the explicit BHT context. */
using bht_biometric_product_id_field =
    tlv::field<tlv::tag_constant<0x86>, bht_biometric_product_id_codec::value_type,
               bht_biometric_product_id_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BHT / 87 independently of input tags; no context fallback.
 */
using bht_biometric_format_owner_codec = detail::emv_dictionary_value_codec<
    uint64_t, detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BHT, tlv::tag_constant<0x87>>>;
/** @brief EMV biometric format owner field in the explicit BHT context. */
using bht_biometric_format_owner_field =
    tlv::field<tlv::tag_constant<0x87>, bht_biometric_format_owner_codec::value_type,
               bht_biometric_format_owner_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BHT / 88 independently of input tags; no context fallback.
 */
using bht_biometric_format_type_codec = detail::emv_dictionary_value_codec<
    uint64_t, detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BHT, tlv::tag_constant<0x88>>>;
/** @brief EMV biometric format type field in the explicit BHT context. */
using bht_biometric_format_type_field =
    tlv::field<tlv::tag_constant<0x88>, bht_biometric_format_type_codec::value_type,
               bht_biometric_format_type_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BHT_FORMAT / 87 independently of input tags; no context fallback.
 */
using bht_format_bht_format_owner_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BHT_FORMAT, tlv::tag_constant<0x87>>>;
/** @brief EMV bht format owner field in the explicit BHT_FORMAT context. */
using bht_format_bht_format_owner_field =
    tlv::field<tlv::tag_constant<0x87>, bht_format_bht_format_owner_codec::value_type,
               bht_format_bht_format_owner_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BHT_FORMAT / 88 independently of input tags; no context fallback.
 */
using bht_format_bht_format_type_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BHT_FORMAT, tlv::tag_constant<0x88>>>;
/** @brief EMV bht format type field in the explicit BHT_FORMAT context. */
using bht_format_bht_format_type_field =
    tlv::field<tlv::tag_constant<0x88>, bht_format_bht_format_type_codec::value_type,
               bht_format_bht_format_type_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BIT_GROUP / 02 independently of input tags; no context fallback.
 */
using bit_group_bit_count_codec = detail::emv_dictionary_value_codec<
    uint64_t,
    detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BIT_GROUP, tlv::tag_constant<0x02>>>;
/** @brief EMV bit count field in the explicit BIT_GROUP context. */
using bit_group_bit_count_field =
    tlv::field<tlv::tag_constant<0x02>, bit_group_bit_count_codec::value_type,
               bit_group_bit_count_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BIOMETRIC_COUNTERS / DF50 independently of input tags; no context fallback.
 */
using biometric_counters_facial_try_counter_codec = detail::emv_dictionary_value_codec<
    uint64_t, detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BIOMETRIC_COUNTERS,
                                                    tlv::tag_constant<0xDF, 0x50>>>;
/** @brief EMV facial try counter field in the explicit BIOMETRIC_COUNTERS context. */
using biometric_counters_facial_try_counter_field =
    tlv::field<tlv::tag_constant<0xDF, 0x50>,
               biometric_counters_facial_try_counter_codec::value_type,
               biometric_counters_facial_try_counter_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BIOMETRIC_COUNTERS / DF51 independently of input tags; no context fallback.
 */
using biometric_counters_finger_try_counter_codec = detail::emv_dictionary_value_codec<
    uint64_t, detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BIOMETRIC_COUNTERS,
                                                    tlv::tag_constant<0xDF, 0x51>>>;
/** @brief EMV finger try counter field in the explicit BIOMETRIC_COUNTERS context. */
using biometric_counters_finger_try_counter_field =
    tlv::field<tlv::tag_constant<0xDF, 0x51>,
               biometric_counters_finger_try_counter_codec::value_type,
               biometric_counters_finger_try_counter_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BIOMETRIC_COUNTERS / DF52 independently of input tags; no context fallback.
 */
using biometric_counters_iris_try_counter_codec = detail::emv_dictionary_value_codec<
    uint64_t, detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BIOMETRIC_COUNTERS,
                                                    tlv::tag_constant<0xDF, 0x52>>>;
/** @brief EMV iris try counter field in the explicit BIOMETRIC_COUNTERS context. */
using biometric_counters_iris_try_counter_field =
    tlv::field<tlv::tag_constant<0xDF, 0x52>, biometric_counters_iris_try_counter_codec::value_type,
               biometric_counters_iris_try_counter_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BIOMETRIC_COUNTERS / DF53 independently of input tags; no context fallback.
 */
using biometric_counters_palm_try_counter_codec = detail::emv_dictionary_value_codec<
    uint64_t, detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BIOMETRIC_COUNTERS,
                                                    tlv::tag_constant<0xDF, 0x53>>>;
/** @brief EMV palm try counter field in the explicit BIOMETRIC_COUNTERS context. */
using biometric_counters_palm_try_counter_field =
    tlv::field<tlv::tag_constant<0xDF, 0x53>, biometric_counters_palm_try_counter_codec::value_type,
               biometric_counters_palm_try_counter_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BIOMETRIC_COUNTERS / DF54 independently of input tags; no context fallback.
 */
using biometric_counters_voice_try_counter_codec = detail::emv_dictionary_value_codec<
    uint64_t, detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BIOMETRIC_COUNTERS,
                                                    tlv::tag_constant<0xDF, 0x54>>>;
/** @brief EMV voice try counter field in the explicit BIOMETRIC_COUNTERS context. */
using biometric_counters_voice_try_counter_field =
    tlv::field<tlv::tag_constant<0xDF, 0x54>,
               biometric_counters_voice_try_counter_codec::value_type,
               biometric_counters_voice_try_counter_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BIOMETRIC_ATTEMPTS / DF50 independently of input tags; no context fallback.
 */
using biometric_attempts_preferred_facial_attempts_codec = detail::emv_dictionary_value_codec<
    uint64_t, detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BIOMETRIC_ATTEMPTS,
                                                    tlv::tag_constant<0xDF, 0x50>>>;
/** @brief EMV preferred facial attempts field in the explicit BIOMETRIC_ATTEMPTS context. */
using biometric_attempts_preferred_facial_attempts_field =
    tlv::field<tlv::tag_constant<0xDF, 0x50>,
               biometric_attempts_preferred_facial_attempts_codec::value_type,
               biometric_attempts_preferred_facial_attempts_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BIOMETRIC_ATTEMPTS / DF51 independently of input tags; no context fallback.
 */
using biometric_attempts_preferred_finger_attempts_codec = detail::emv_dictionary_value_codec<
    uint64_t, detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BIOMETRIC_ATTEMPTS,
                                                    tlv::tag_constant<0xDF, 0x51>>>;
/** @brief EMV preferred finger attempts field in the explicit BIOMETRIC_ATTEMPTS context. */
using biometric_attempts_preferred_finger_attempts_field =
    tlv::field<tlv::tag_constant<0xDF, 0x51>,
               biometric_attempts_preferred_finger_attempts_codec::value_type,
               biometric_attempts_preferred_finger_attempts_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BIOMETRIC_ATTEMPTS / DF52 independently of input tags; no context fallback.
 */
using biometric_attempts_preferred_iris_attempts_codec = detail::emv_dictionary_value_codec<
    uint64_t, detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BIOMETRIC_ATTEMPTS,
                                                    tlv::tag_constant<0xDF, 0x52>>>;
/** @brief EMV preferred iris attempts field in the explicit BIOMETRIC_ATTEMPTS context. */
using biometric_attempts_preferred_iris_attempts_field =
    tlv::field<tlv::tag_constant<0xDF, 0x52>,
               biometric_attempts_preferred_iris_attempts_codec::value_type,
               biometric_attempts_preferred_iris_attempts_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BIOMETRIC_ATTEMPTS / DF53 independently of input tags; no context fallback.
 */
using biometric_attempts_preferred_palm_attempts_codec = detail::emv_dictionary_value_codec<
    uint64_t, detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BIOMETRIC_ATTEMPTS,
                                                    tlv::tag_constant<0xDF, 0x53>>>;
/** @brief EMV preferred palm attempts field in the explicit BIOMETRIC_ATTEMPTS context. */
using biometric_attempts_preferred_palm_attempts_field =
    tlv::field<tlv::tag_constant<0xDF, 0x53>,
               biometric_attempts_preferred_palm_attempts_codec::value_type,
               biometric_attempts_preferred_palm_attempts_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BIOMETRIC_ATTEMPTS / DF54 independently of input tags; no context fallback.
 */
using biometric_attempts_preferred_voice_attempts_codec = detail::emv_dictionary_value_codec<
    uint64_t, detail::emv_dictionary_codec_provider<TLV_EMV_CONTEXT_BIOMETRIC_ATTEMPTS,
                                                    tlv::tag_constant<0xDF, 0x54>>>;
/** @brief EMV preferred voice attempts field in the explicit BIOMETRIC_ATTEMPTS context. */
using biometric_attempts_preferred_voice_attempts_field =
    tlv::field<tlv::tag_constant<0xDF, 0x54>,
               biometric_attempts_preferred_voice_attempts_codec::value_type,
               biometric_attempts_preferred_voice_attempts_codec>;
/** @brief Value codec using the canonical dictionary descriptor and its existing constraints.
 * @note Selects BIOMETRIC_VERIFICATION / 81 independently of input tags; no context fallback.
 */
using biometric_verification_verification_biometric_type_codec = detail::emv_dictionary_value_codec<
    tlv_emv_biometric_type_t, detail::emv_dictionary_codec_provider<
                                  TLV_EMV_CONTEXT_BIOMETRIC_VERIFICATION, tlv::tag_constant<0x81>>>;
/** @brief EMV verification biometric type field in the explicit BIOMETRIC_VERIFICATION context. */
using biometric_verification_verification_biometric_type_field =
    tlv::field<tlv::tag_constant<0x81>,
               biometric_verification_verification_biometric_type_codec::value_type,
               biometric_verification_verification_biometric_type_codec>;
} // namespace emv
} // namespace tlv
#endif
