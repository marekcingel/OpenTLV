// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv++/tlv.hpp"
#include <gtest/gtest.h>
#include <array>
#include <cstring>

namespace {
tlv::bytes view(const uint8_t* data, size_t size) {
    return {reinterpret_cast<const tlv::byte*>(data), size};
}
template <typename Codec> void value_round_trip(tlv::bytes wire) {
    auto decoded = Codec::decode(wire);
    ASSERT_TRUE(decoded);
    auto measured = Codec::encode(*decoded, nullptr, 0);
    ASSERT_TRUE(measured);
    ASSERT_EQ(*measured, wire.size());
    std::array<tlv::byte, 128> output{};
    auto                       encoded = Codec::encode(*decoded, output.data(), output.size());
    ASSERT_TRUE(encoded);
    ASSERT_EQ(*encoded, wire.size());
    if (!wire.empty()) EXPECT_EQ(0, std::memcmp(output.data(), wire.data(), wire.size()));
    if (wire.size()) {
        auto short_output = Codec::encode(*decoded, output.data(), wire.size() - 1);
        ASSERT_FALSE(short_output);
        EXPECT_EQ(TLV_CODEC_ERR_BUFFER_TOO_SHORT, short_output.error());
    }
}
} // namespace

#if OPENTLV_FORMAT_BER
TEST(Unit_Tlvpp_BuiltinConvenience, BerIndefiniteFramingHelper) {
    const uint8_t children[] = {4, 1, 42};
    auto          size = tlv::measure(tlv::ber::indefinite_format{},
                                      {tlv::tag_bytes<0x30>(), tlv::value_view(view(children, 3))});
    ASSERT_TRUE(size);
    EXPECT_EQ(7u, size->total);
    auto empty_output = tlv::ber::write_indefinite({}, tlv::tag_bytes<0x30>(), view(children, 3));
    ASSERT_FALSE(empty_output);
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, empty_output.error().code);
    tlv::byte output[7]{};
    auto      result = tlv::ber::write_indefinite({output, sizeof(output)}, tlv::tag_bytes<0x30>(),
                                                  view(children, 3));
    ASSERT_TRUE(result);
    const uint8_t expected[] = {0x30, 0x80, 4, 1, 42, 0, 0};
    EXPECT_EQ(0, std::memcmp(expected, output, sizeof(expected)));
}

TEST(Unit_Tlvpp_BuiltinConvenience, Asn1ContentRulesAndBorrowing) {
    const uint8_t truth[] = {0xFF}, noncanonical[] = {1}, redundant_integer[] = {0, 1};
    value_round_trip<tlv::asn1::boolean_codec>(view(truth, sizeof(truth)));
    EXPECT_FALSE(tlv::asn1::boolean_codec::decode(view(noncanonical, sizeof(noncanonical))));
    EXPECT_FALSE(
        tlv::asn1::integer_codec::decode(view(redundant_integer, sizeof(redundant_integer))));
    const uint8_t bits[] = {3, 0xA8};
    auto          bit_value = tlv::asn1::bit_string_codec::decode(view(bits, sizeof(bits)));
    ASSERT_TRUE(bit_value);
    EXPECT_EQ(3, bit_value->unused_bits);
    EXPECT_EQ(view(bits + 1, 1).data(), bit_value->data.data());
    value_round_trip<tlv::asn1::bit_string_codec>(view(bits, sizeof(bits)));
    const uint8_t integer[] = {0x80}, oid[] = {0x2A, 0x03}, relative[] = {0x03};
    value_round_trip<tlv::asn1::integer_codec>(view(integer, sizeof(integer)));
    value_round_trip<tlv::asn1::enumerated_codec>(view(integer, sizeof(integer)));
    value_round_trip<tlv::asn1::oid_codec>(view(oid, sizeof(oid)));
    value_round_trip<tlv::asn1::relative_oid_codec>(view(relative, sizeof(relative)));
    value_round_trip<tlv::asn1::null_codec>({});
    const uint8_t text[] = {'A', '2'}, numeric[] = {'1', '2'}, bmp[] = {0, 'A'},
                  universal[] = {0, 0, 0, 'A'};
    auto          string = tlv::asn1::utf8_string_codec::decode(view(text, sizeof(text)));
    ASSERT_TRUE(string);
    EXPECT_EQ(view(text, sizeof(text)).data(), string->data());
    value_round_trip<tlv::asn1::utf8_string_codec>(view(text, sizeof(text)));
    value_round_trip<tlv::asn1::numeric_string_codec>(view(numeric, sizeof(numeric)));
    value_round_trip<tlv::asn1::printable_string_codec>(view(text, sizeof(text)));
    value_round_trip<tlv::asn1::ia5_string_codec>(view(text, sizeof(text)));
    value_round_trip<tlv::asn1::visible_string_codec>(view(text, sizeof(text)));
    value_round_trip<tlv::asn1::octet_string_codec>(view(text, sizeof(text)));
    value_round_trip<tlv::asn1::object_descriptor_codec>(view(text, sizeof(text)));
    value_round_trip<tlv::asn1::teletex_string_codec>(view(text, sizeof(text)));
    value_round_trip<tlv::asn1::videotex_string_codec>(view(text, sizeof(text)));
    value_round_trip<tlv::asn1::graphic_string_codec>(view(text, sizeof(text)));
    value_round_trip<tlv::asn1::general_string_codec>(view(text, sizeof(text)));
    value_round_trip<tlv::asn1::bmp_string_codec>(view(bmp, sizeof(bmp)));
    value_round_trip<tlv::asn1::universal_string_codec>(view(universal, sizeof(universal)));
    EXPECT_FALSE(tlv::asn1::bmp_string_codec::encode(tlv::value_view(view(text, 1)), nullptr, 0));
    const char utc[] = "261001120000Z", generalized[] = "20261001120000.25Z", date[] = "20261001",
               time[] = "120000", datetime[] = "20261001120000", duration[] = "2DT3H",
               absolute_iri[] = "/A/B", relative_iri[] = "A/B";
    value_round_trip<tlv::asn1::utc_time_codec>(
        view(reinterpret_cast<const uint8_t*>(utc), sizeof(utc) - 1));
    value_round_trip<tlv::asn1::generalized_time_codec>(
        view(reinterpret_cast<const uint8_t*>(generalized), sizeof(generalized) - 1));
    value_round_trip<tlv::asn1::date_codec>(
        view(reinterpret_cast<const uint8_t*>(date), sizeof(date) - 1));
    value_round_trip<tlv::asn1::time_of_day_codec>(
        view(reinterpret_cast<const uint8_t*>(time), sizeof(time) - 1));
    value_round_trip<tlv::asn1::date_time_codec>(
        view(reinterpret_cast<const uint8_t*>(datetime), sizeof(datetime) - 1));
    value_round_trip<tlv::asn1::time_codec>(
        view(reinterpret_cast<const uint8_t*>(time), sizeof(time) - 1));
    value_round_trip<tlv::asn1::duration_codec>(
        view(reinterpret_cast<const uint8_t*>(duration), sizeof(duration) - 1));
    value_round_trip<tlv::asn1::oid_iri_codec>(
        view(reinterpret_cast<const uint8_t*>(absolute_iri), sizeof(absolute_iri) - 1));
    value_round_trip<tlv::asn1::relative_oid_iri_codec>(
        view(reinterpret_cast<const uint8_t*>(relative_iri), sizeof(relative_iri) - 1));
    tlv::asn1::iri excessive{};
    excessive.count = TLV_ASN1_IRI_MAX_ARCS + 1;
    EXPECT_FALSE(tlv::asn1::oid_iri_codec::encode(excessive, nullptr, 0));
    EXPECT_EQ((tlv::tag_bytes<0x1F, 0x1F>()), tlv::asn1::date_field::tag());
}
#endif

#if OPENTLV_BLUETOOTH
TEST(Unit_Tlvpp_BuiltinConvenience, BluetoothAllValueCodecsAndTypedField) {
    const uint8_t flags[] = {6}, zero_flags[] = {0}, power[] = {0xFC}, bad_power[] = {0x80},
                  name[] = {'O', 'K'}, bad_utf8[] = {0xC0, 0x80};
    value_round_trip<tlv::bluetooth::flags_codec>(view(flags, sizeof(flags)));
    value_round_trip<tlv::bluetooth::tx_power_codec>(view(power, sizeof(power)));
    value_round_trip<tlv::bluetooth::local_name_codec>(view(name, sizeof(name)));
    EXPECT_FALSE(tlv::bluetooth::flags_codec::decode(view(zero_flags, 1)));
    EXPECT_FALSE(tlv::bluetooth::tx_power_codec::decode(view(bad_power, 1)));
    EXPECT_FALSE(tlv::bluetooth::local_name_codec::decode(view(bad_utf8, 2)));
    const uint8_t uuid16[] = {0x0F, 0x18}, uuid32[] = {4, 3, 2, 1},
                  uuid128[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    value_round_trip<tlv::bluetooth::uuid16_codec>(view(uuid16, 2));
    value_round_trip<tlv::bluetooth::uuid32_codec>(view(uuid32, 4));
    value_round_trip<tlv::bluetooth::uuid128_codec>(view(uuid128, 16));
    value_round_trip<tlv::bluetooth::uuid16_list_codec>(view(uuid16, 2));
    value_round_trip<tlv::bluetooth::uuid32_list_codec>(view(uuid32, 4));
    value_round_trip<tlv::bluetooth::uuid128_list_codec>(view(uuid128, 16));
    value_round_trip<tlv::bluetooth::service_data16_codec>(view(uuid16, 2));
    value_round_trip<tlv::bluetooth::service_data32_codec>(view(uuid32, 4));
    value_round_trip<tlv::bluetooth::service_data128_codec>(view(uuid128, 16));
    value_round_trip<tlv::bluetooth::manufacturer_data_codec>(view(uuid16, 2));
    auto uuid = tlv::bluetooth::uuid128_codec::decode(view(uuid128, 16));
    ASSERT_TRUE(uuid);
    EXPECT_EQ(16, uuid->bytes[0]);
    const uint8_t service[] = {0x0F, 0x18, 0xAA};
    auto          value = tlv::bluetooth::service_data16_codec::decode(view(service, 3));
    ASSERT_TRUE(value);
    EXPECT_EQ(0x180F, value->uuid);
    EXPECT_EQ(view(service + 2, 1).data(), value->payload.data());
    value->raw = {};
    auto size = tlv::bluetooth::service_data16_codec::encode(*value, nullptr, 0);
    ASSERT_TRUE(size);
    EXPECT_EQ(3u, *size);
    tlv::byte                           output[8]{}, scratch[1]{};
    tlv::writer<tlv::bluetooth::format> writer(output, sizeof(output));
    ASSERT_TRUE(writer.write<tlv::bluetooth::tx_power_field>(-4, {scratch, sizeof(scratch)}));
    for (auto element : tlv::bluetooth::parse({output, writer.size()})) {
        auto decoded = element.decode<tlv::bluetooth::tx_power_field>();
        ASSERT_TRUE(decoded);
        EXPECT_EQ(-4, *decoded);
    }
}
#endif

#if OPENTLV_LLDP
TEST(Unit_Tlvpp_BuiltinConvenience, LldpBorrowingAndSubtypeSemantics) {
    const uint8_t chassis[] = {4, 1, 2, 3, 4, 5, 6}, port[] = {3, 1, 2, 3, 4, 5, 6}, ttl[] = {0, 0},
                  capabilities[] = {0, 4, 0, 4},
                  management[] = {5, 1, 192, 0, 2, 1, 2, 0, 0, 0, 7, 0},
                  organisation[] = {0, 1, 2, 3, 0xFF}, text[] = {0xFF};
    value_round_trip<tlv::lldp::chassis_id_codec>(view(chassis, sizeof(chassis)));
    value_round_trip<tlv::lldp::port_id_codec>(view(port, sizeof(port)));
    value_round_trip<tlv::lldp::ttl_codec>(view(ttl, sizeof(ttl)));
    value_round_trip<tlv::lldp::capabilities_codec>(view(capabilities, sizeof(capabilities)));
    value_round_trip<tlv::lldp::management_address_codec>(view(management, sizeof(management)));
    value_round_trip<tlv::lldp::organisation_codec>(view(organisation, sizeof(organisation)));
    value_round_trip<tlv::lldp::text_codec>(view(text, sizeof(text)));
    auto address =
        tlv::lldp::management_address_codec::decode(view(management, sizeof(management)));
    ASSERT_TRUE(address);
    EXPECT_EQ(view(management + 2, 4).data(), address->address.data());
    EXPECT_EQ(7u, address->interface_number);
    auto invalid = tlv::lldp::capabilities_codec::encode({1, 2}, nullptr, 0);
    EXPECT_FALSE(invalid);
    tlv::byte                      output[8]{}, scratch[2]{};
    tlv::writer<tlv::lldp::format> writer(output, sizeof(output));
    ASSERT_TRUE(writer.write<tlv::lldp::ttl_field>(uint16_t{120}, {scratch, sizeof(scratch)}));
    EXPECT_EQ(0x06, reinterpret_cast<uint8_t*>(output)[0]);
    EXPECT_EQ(0x02, reinterpret_cast<uint8_t*>(output)[1]);
    for (auto element : tlv::lldp::parse({output, writer.size()})) {
        auto value = element.decode<tlv::lldp::ttl_field>();
        ASSERT_TRUE(value);
        EXPECT_EQ(120, *value);
    }
}
#endif

#if OPENTLV_DHCP
TEST(Unit_Tlvpp_BuiltinConvenience, DhcpUnknownMessageTypeIsPreserved) {
    const uint8_t unknown[] = {0xFF};
    value_round_trip<tlv::dhcp::message_type_codec>(view(unknown, 1));
    EXPECT_EQ(tlv::tag_bytes<53>(), tlv::dhcp::message_type_field::tag());
    const uint8_t options[] = {53, 1, 0xFF, 255, 0};
    auto          validated = tlv::dhcp::options_validate(view(options, sizeof(options)));
    ASSERT_TRUE(validated);
    EXPECT_EQ(4u, *validated);
    const uint8_t bad_tail[] = {255, 1};
    EXPECT_FALSE(tlv::dhcp::options_validate(view(bad_tail, sizeof(bad_tail))));
}
#endif

#if OPENTLV_EMV
TEST(Unit_Tlvpp_BuiltinConvenience, EmvDigitsNumbersDatesAndScopedFields) {
    const uint8_t pan[] = {0, 0x12, 0x3F}, currency[] = {0x09, 0x78},
                  amount[] = {0, 0, 0, 0, 0x12, 0x34}, date[] = {0x26, 0x10, 0x01},
                  invalid_date[] = {0x26, 0x02, 0x30}, afl[] = {8, 1, 2, 1};
    auto          digits = tlv::emv::pan_codec::decode(view(pan, sizeof(pan)));
    ASSERT_TRUE(digits);
    EXPECT_EQ("00123", *digits);
    value_round_trip<tlv::emv::pan_codec>(view(pan, sizeof(pan)));
    value_round_trip<tlv::emv::transaction_currency_code_codec>(view(currency, sizeof(currency)));
    value_round_trip<tlv::emv::amount_codec>(view(amount, sizeof(amount)));
    value_round_trip<tlv::emv::transaction_date_codec>(view(date, sizeof(date)));
    value_round_trip<tlv::emv::afl_codec>(view(afl, sizeof(afl)));
    EXPECT_FALSE(tlv::emv::pan_codec::encode(std::string("12X"), nullptr, 0));
    EXPECT_FALSE(
        tlv::emv::transaction_date_codec::decode(view(invalid_date, sizeof(invalid_date))));
    auto number =
        tlv::emv::transaction_currency_code_codec::decode(view(currency, sizeof(currency)));
    ASSERT_TRUE(number);
    EXPECT_EQ(978u, *number);
    tlv::byte                     output[16]{}, scratch[10]{};
    tlv::writer<tlv::emv::format> writer(output, sizeof(output));
    ASSERT_TRUE(writer.write<tlv::emv::pan_field>(*digits, {scratch, sizeof(scratch)}));
    for (auto element : tlv::emv::parse({output, writer.size()})) {
        auto value = element.decode<tlv::emv::pan_field>();
        ASSERT_TRUE(value);
        EXPECT_EQ(*digits, *value);
        EXPECT_FALSE(element.decode<tlv::emv::transaction_currency_code_field>());
    }
}
#endif

#if OPENTLV_EMV
namespace {
template <typename T> T emv_sample();
template <> uint64_t    emv_sample<uint64_t>() {
    return 1;
}
template <> std::string emv_sample<std::string>() {
    return "1234";
}
template <> tlv_emv_account_type_t emv_sample<tlv_emv_account_type_t>() {
    return TLV_EMV_ACCOUNT_DEFAULT;
}
template <> tlv_emv_biometric_type_t emv_sample<tlv_emv_biometric_type_t>() {
    return TLV_EMV_BIOMETRIC_FACIAL;
}
template <> tlv_emv_afl_t emv_sample<tlv_emv_afl_t>() {
    tlv_emv_afl_t value{};
    value.count = 1;
    value.entries[0] = {1, 1, 2, 1};
    return value;
}
template <> tlv_emv_cryptogram_info_t emv_sample<tlv_emv_cryptogram_info_t>() {
    return {TLV_EMV_CRYPTOGRAM_AAC, 3};
}
template <> tlv_emv_cvm_result_t emv_sample<tlv_emv_cvm_result_t>() {
    return {1, 2, 3};
}
template <> tlv_emv_date_t emv_sample<tlv_emv_date_t>() {
    return {26, 10, 1};
}
template <> tlv_emv_time_t emv_sample<tlv_emv_time_t>() {
    return {12, 0, 0};
}
template <> tlv_emv_number_list_t emv_sample<tlv_emv_number_list_t>() {
    tlv_emv_number_list_t value{};
    value.count = 1;
    value.values[0] = 1;
    return value;
}
template <> tlv_emv_track2_t emv_sample<tlv_emv_track2_t>() {
    tlv_emv_track2_t value{};
    std::strcpy(value.pan, "123456");
    value.expiration_year = 26;
    value.expiration_month = 10;
    value.service_code = 101;
    std::strcpy(value.discretionary_data, "12");
    return value;
}
template <typename T> const void* object_data(const T& value) {
    return &value;
}
const void* object_data(const std::string& value) {
    return value.c_str();
}
template <typename T> size_t object_size(const T&) {
    return sizeof(T);
}
size_t object_size(const std::string& value) {
    return value.size();
}

template <typename Field>
void emv_dictionary_round_trip(tlv_emv_context_t context, tlv::tag expected_tag) {
    using Codec = typename Field::codec_type;
    EXPECT_EQ(expected_tag, Field::tag());
    auto        raw_tag = tlv::detail::semantic_access::get(expected_tag);
    const auto* entry = tlv_emv_find(context, &raw_tag);
    ASSERT_NE(nullptr, entry);
    ASSERT_NE(nullptr, entry->codec);
    auto       value = emv_sample<typename Field::value_type>();
    uint8_t    c_output[128]{};
    size_t     c_size = 0;
    const auto rc = tlv_codec_encode(entry->codec, object_data(value), object_size(value), c_output,
                                     sizeof(c_output), &c_size);
    ASSERT_EQ(TLV_CODEC_OK, rc);
    auto measured = Codec::encode(value, nullptr, 0);
    ASSERT_TRUE(measured);
    EXPECT_EQ(c_size, *measured);
    tlv::byte output[128]{};
    auto      encoded = Codec::encode(value, output, sizeof(output));
    ASSERT_TRUE(encoded);
    ASSERT_EQ(c_size, *encoded);
    EXPECT_EQ(0, std::memcmp(c_output, output, c_size));
    value_round_trip<Codec>({output, *encoded});
}
} // namespace

TEST(Unit_Tlvpp_BuiltinConvenience, EveryEmvCodecBearingDictionaryField) {
    {
        SCOPED_TRACE("iin");
        emv_dictionary_round_trip<tlv::emv::iin_field>(TLV_EMV_CONTEXT_BASE,
                                                       tlv::tag_bytes<0x42>());
    }
    {
        SCOPED_TRACE("track2_equivalent_data");
        emv_dictionary_round_trip<tlv::emv::track2_equivalent_data_field>(TLV_EMV_CONTEXT_BASE,
                                                                          tlv::tag_bytes<0x57>());
    }
    {
        SCOPED_TRACE("pan");
        emv_dictionary_round_trip<tlv::emv::pan_field>(TLV_EMV_CONTEXT_BASE,
                                                       tlv::tag_bytes<0x5A>());
    }
    {
        SCOPED_TRACE("amount_authorised_binary");
        emv_dictionary_round_trip<tlv::emv::amount_authorised_binary_field>(TLV_EMV_CONTEXT_BASE,
                                                                            tlv::tag_bytes<0x81>());
    }
    {
        SCOPED_TRACE("aip");
        emv_dictionary_round_trip<tlv::emv::aip_field>(TLV_EMV_CONTEXT_BASE,
                                                       tlv::tag_bytes<0x82>());
    }
    {
        SCOPED_TRACE("application_priority_indicator");
        emv_dictionary_round_trip<tlv::emv::application_priority_indicator_field>(
            TLV_EMV_CONTEXT_BASE, tlv::tag_bytes<0x87>());
    }
    {
        SCOPED_TRACE("sfi");
        emv_dictionary_round_trip<tlv::emv::sfi_field>(TLV_EMV_CONTEXT_BASE,
                                                       tlv::tag_bytes<0x88>());
    }
    {
        SCOPED_TRACE("ca_public_key_index");
        emv_dictionary_round_trip<tlv::emv::ca_public_key_index_field>(TLV_EMV_CONTEXT_BASE,
                                                                       tlv::tag_bytes<0x8F>());
    }
    {
        SCOPED_TRACE("afl");
        emv_dictionary_round_trip<tlv::emv::afl_field>(TLV_EMV_CONTEXT_BASE,
                                                       tlv::tag_bytes<0x94>());
    }
    {
        SCOPED_TRACE("tvr");
        emv_dictionary_round_trip<tlv::emv::tvr_field>(TLV_EMV_CONTEXT_BASE,
                                                       tlv::tag_bytes<0x95>());
    }
    {
        SCOPED_TRACE("transaction_date");
        emv_dictionary_round_trip<tlv::emv::transaction_date_field>(TLV_EMV_CONTEXT_BASE,
                                                                    tlv::tag_bytes<0x9A>());
    }
    {
        SCOPED_TRACE("tsi");
        emv_dictionary_round_trip<tlv::emv::tsi_field>(TLV_EMV_CONTEXT_BASE,
                                                       tlv::tag_bytes<0x9B>());
    }
    {
        SCOPED_TRACE("transaction_type");
        emv_dictionary_round_trip<tlv::emv::transaction_type_field>(TLV_EMV_CONTEXT_BASE,
                                                                    tlv::tag_bytes<0x9C>());
    }
    {
        SCOPED_TRACE("application_expiration_date");
        emv_dictionary_round_trip<tlv::emv::application_expiration_date_field>(
            TLV_EMV_CONTEXT_BASE, tlv::tag_bytes<0x5F, 0x24>());
    }
    {
        SCOPED_TRACE("application_effective_date");
        emv_dictionary_round_trip<tlv::emv::application_effective_date_field>(
            TLV_EMV_CONTEXT_BASE, tlv::tag_bytes<0x5F, 0x25>());
    }
    {
        SCOPED_TRACE("issuer_country_code");
        emv_dictionary_round_trip<tlv::emv::issuer_country_code_field>(
            TLV_EMV_CONTEXT_BASE, tlv::tag_bytes<0x5F, 0x28>());
    }
    {
        SCOPED_TRACE("transaction_currency_code");
        emv_dictionary_round_trip<tlv::emv::transaction_currency_code_field>(
            TLV_EMV_CONTEXT_BASE, tlv::tag_bytes<0x5F, 0x2A>());
    }
    {
        SCOPED_TRACE("service_code");
        emv_dictionary_round_trip<tlv::emv::service_code_field>(TLV_EMV_CONTEXT_BASE,
                                                                tlv::tag_bytes<0x5F, 0x30>());
    }
    {
        SCOPED_TRACE("pan_sequence_number");
        emv_dictionary_round_trip<tlv::emv::pan_sequence_number_field>(
            TLV_EMV_CONTEXT_BASE, tlv::tag_bytes<0x5F, 0x34>());
    }
    {
        SCOPED_TRACE("transaction_currency_exponent");
        emv_dictionary_round_trip<tlv::emv::transaction_currency_exponent_field>(
            TLV_EMV_CONTEXT_BASE, tlv::tag_bytes<0x5F, 0x36>());
    }
    {
        SCOPED_TRACE("account_type");
        emv_dictionary_round_trip<tlv::emv::account_type_field>(TLV_EMV_CONTEXT_BASE,
                                                                tlv::tag_bytes<0x5F, 0x57>());
    }
    {
        SCOPED_TRACE("acquirer_identifier");
        emv_dictionary_round_trip<tlv::emv::acquirer_identifier_field>(
            TLV_EMV_CONTEXT_BASE, tlv::tag_bytes<0x9F, 0x01>());
    }
    {
        SCOPED_TRACE("amount_other");
        emv_dictionary_round_trip<tlv::emv::amount_other_field>(TLV_EMV_CONTEXT_BASE,
                                                                tlv::tag_bytes<0x9F, 0x03>());
    }
    {
        SCOPED_TRACE("amount_other_binary");
        emv_dictionary_round_trip<tlv::emv::amount_other_binary_field>(
            TLV_EMV_CONTEXT_BASE, tlv::tag_bytes<0x9F, 0x04>());
    }
    {
        SCOPED_TRACE("application_usage_control");
        emv_dictionary_round_trip<tlv::emv::application_usage_control_field>(
            TLV_EMV_CONTEXT_BASE, tlv::tag_bytes<0x9F, 0x07>());
    }
    {
        SCOPED_TRACE("application_version_card");
        emv_dictionary_round_trip<tlv::emv::application_version_card_field>(
            TLV_EMV_CONTEXT_BASE, tlv::tag_bytes<0x9F, 0x08>());
    }
    {
        SCOPED_TRACE("application_version_terminal");
        emv_dictionary_round_trip<tlv::emv::application_version_terminal_field>(
            TLV_EMV_CONTEXT_BASE, tlv::tag_bytes<0x9F, 0x09>());
    }
    {
        SCOPED_TRACE("iin_extended");
        emv_dictionary_round_trip<tlv::emv::iin_extended_field>(TLV_EMV_CONTEXT_BASE,
                                                                tlv::tag_bytes<0x9F, 0x0C>());
    }
    {
        SCOPED_TRACE("issuer_action_code_default");
        emv_dictionary_round_trip<tlv::emv::issuer_action_code_default_field>(
            TLV_EMV_CONTEXT_BASE, tlv::tag_bytes<0x9F, 0x0D>());
    }
    {
        SCOPED_TRACE("issuer_action_code_denial");
        emv_dictionary_round_trip<tlv::emv::issuer_action_code_denial_field>(
            TLV_EMV_CONTEXT_BASE, tlv::tag_bytes<0x9F, 0x0E>());
    }
    {
        SCOPED_TRACE("issuer_action_code_online");
        emv_dictionary_round_trip<tlv::emv::issuer_action_code_online_field>(
            TLV_EMV_CONTEXT_BASE, tlv::tag_bytes<0x9F, 0x0F>());
    }
    {
        SCOPED_TRACE("issuer_code_table_index");
        emv_dictionary_round_trip<tlv::emv::issuer_code_table_index_field>(
            TLV_EMV_CONTEXT_BASE, tlv::tag_bytes<0x9F, 0x11>());
    }
    {
        SCOPED_TRACE("last_online_atc");
        emv_dictionary_round_trip<tlv::emv::last_online_atc_field>(TLV_EMV_CONTEXT_BASE,
                                                                   tlv::tag_bytes<0x9F, 0x13>());
    }
    {
        SCOPED_TRACE("lower_consecutive_offline_limit");
        emv_dictionary_round_trip<tlv::emv::lower_consecutive_offline_limit_field>(
            TLV_EMV_CONTEXT_BASE, tlv::tag_bytes<0x9F, 0x14>());
    }
    {
        SCOPED_TRACE("merchant_category_code");
        emv_dictionary_round_trip<tlv::emv::merchant_category_code_field>(
            TLV_EMV_CONTEXT_BASE, tlv::tag_bytes<0x9F, 0x15>());
    }
    {
        SCOPED_TRACE("pin_try_counter");
        emv_dictionary_round_trip<tlv::emv::pin_try_counter_field>(TLV_EMV_CONTEXT_BASE,
                                                                   tlv::tag_bytes<0x9F, 0x17>());
    }
    {
        SCOPED_TRACE("token_requestor_id");
        emv_dictionary_round_trip<tlv::emv::token_requestor_id_field>(TLV_EMV_CONTEXT_BASE,
                                                                      tlv::tag_bytes<0x9F, 0x19>());
    }
    {
        SCOPED_TRACE("terminal_country_code");
        emv_dictionary_round_trip<tlv::emv::terminal_country_code_field>(
            TLV_EMV_CONTEXT_BASE, tlv::tag_bytes<0x9F, 0x1A>());
    }
    {
        SCOPED_TRACE("terminal_floor_limit");
        emv_dictionary_round_trip<tlv::emv::terminal_floor_limit_field>(
            TLV_EMV_CONTEXT_BASE, tlv::tag_bytes<0x9F, 0x1B>());
    }
    {
        SCOPED_TRACE("track2_discretionary_data");
        emv_dictionary_round_trip<tlv::emv::track2_discretionary_data_field>(
            TLV_EMV_CONTEXT_BASE, tlv::tag_bytes<0x9F, 0x20>());
    }
    {
        SCOPED_TRACE("transaction_time");
        emv_dictionary_round_trip<tlv::emv::transaction_time_field>(TLV_EMV_CONTEXT_BASE,
                                                                    tlv::tag_bytes<0x9F, 0x21>());
    }
    {
        SCOPED_TRACE("ca_public_key_index_terminal");
        emv_dictionary_round_trip<tlv::emv::ca_public_key_index_terminal_field>(
            TLV_EMV_CONTEXT_BASE, tlv::tag_bytes<0x9F, 0x22>());
    }
    {
        SCOPED_TRACE("upper_consecutive_offline_limit");
        emv_dictionary_round_trip<tlv::emv::upper_consecutive_offline_limit_field>(
            TLV_EMV_CONTEXT_BASE, tlv::tag_bytes<0x9F, 0x23>());
    }
    {
        SCOPED_TRACE("last4_pan");
        emv_dictionary_round_trip<tlv::emv::last4_pan_field>(TLV_EMV_CONTEXT_BASE,
                                                             tlv::tag_bytes<0x9F, 0x25>());
    }
    {
        SCOPED_TRACE("cryptogram_information_data");
        emv_dictionary_round_trip<tlv::emv::cryptogram_information_data_field>(
            TLV_EMV_CONTEXT_BASE, tlv::tag_bytes<0x9F, 0x27>());
    }
    {
        SCOPED_TRACE("icc_pin_public_key_exponent");
        emv_dictionary_round_trip<tlv::emv::icc_pin_public_key_exponent_field>(
            TLV_EMV_CONTEXT_BASE, tlv::tag_bytes<0x9F, 0x2E>());
    }
    {
        SCOPED_TRACE("biometric_terminal_capabilities");
        emv_dictionary_round_trip<tlv::emv::biometric_terminal_capabilities_field>(
            TLV_EMV_CONTEXT_BASE, tlv::tag_bytes<0x9F, 0x30>());
    }
    {
        SCOPED_TRACE("issuer_public_key_exponent");
        emv_dictionary_round_trip<tlv::emv::issuer_public_key_exponent_field>(
            TLV_EMV_CONTEXT_BASE, tlv::tag_bytes<0x9F, 0x32>());
    }
    {
        SCOPED_TRACE("terminal_capabilities");
        emv_dictionary_round_trip<tlv::emv::terminal_capabilities_field>(
            TLV_EMV_CONTEXT_BASE, tlv::tag_bytes<0x9F, 0x33>());
    }
    {
        SCOPED_TRACE("cvm_results");
        emv_dictionary_round_trip<tlv::emv::cvm_results_field>(TLV_EMV_CONTEXT_BASE,
                                                               tlv::tag_bytes<0x9F, 0x34>());
    }
    {
        SCOPED_TRACE("terminal_type");
        emv_dictionary_round_trip<tlv::emv::terminal_type_field>(TLV_EMV_CONTEXT_BASE,
                                                                 tlv::tag_bytes<0x9F, 0x35>());
    }
    {
        SCOPED_TRACE("atc");
        emv_dictionary_round_trip<tlv::emv::atc_field>(TLV_EMV_CONTEXT_BASE,
                                                       tlv::tag_bytes<0x9F, 0x36>());
    }
    {
        SCOPED_TRACE("pos_entry_mode");
        emv_dictionary_round_trip<tlv::emv::pos_entry_mode_field>(TLV_EMV_CONTEXT_BASE,
                                                                  tlv::tag_bytes<0x9F, 0x39>());
    }
    {
        SCOPED_TRACE("amount_reference_currency");
        emv_dictionary_round_trip<tlv::emv::amount_reference_currency_field>(
            TLV_EMV_CONTEXT_BASE, tlv::tag_bytes<0x9F, 0x3A>());
    }
    {
        SCOPED_TRACE("application_reference_currency");
        emv_dictionary_round_trip<tlv::emv::application_reference_currency_field>(
            TLV_EMV_CONTEXT_BASE, tlv::tag_bytes<0x9F, 0x3B>());
    }
    {
        SCOPED_TRACE("transaction_reference_currency_code");
        emv_dictionary_round_trip<tlv::emv::transaction_reference_currency_code_field>(
            TLV_EMV_CONTEXT_BASE, tlv::tag_bytes<0x9F, 0x3C>());
    }
    {
        SCOPED_TRACE("transaction_reference_currency_exponent");
        emv_dictionary_round_trip<tlv::emv::transaction_reference_currency_exponent_field>(
            TLV_EMV_CONTEXT_BASE, tlv::tag_bytes<0x9F, 0x3D>());
    }
    {
        SCOPED_TRACE("additional_terminal_capabilities");
        emv_dictionary_round_trip<tlv::emv::additional_terminal_capabilities_field>(
            TLV_EMV_CONTEXT_BASE, tlv::tag_bytes<0x9F, 0x40>());
    }
    {
        SCOPED_TRACE("transaction_sequence_counter");
        emv_dictionary_round_trip<tlv::emv::transaction_sequence_counter_field>(
            TLV_EMV_CONTEXT_BASE, tlv::tag_bytes<0x9F, 0x41>());
    }
    {
        SCOPED_TRACE("application_currency_code");
        emv_dictionary_round_trip<tlv::emv::application_currency_code_field>(
            TLV_EMV_CONTEXT_BASE, tlv::tag_bytes<0x9F, 0x42>());
    }
    {
        SCOPED_TRACE("application_reference_currency_exponent");
        emv_dictionary_round_trip<tlv::emv::application_reference_currency_exponent_field>(
            TLV_EMV_CONTEXT_BASE, tlv::tag_bytes<0x9F, 0x43>());
    }
    {
        SCOPED_TRACE("application_currency_exponent");
        emv_dictionary_round_trip<tlv::emv::application_currency_exponent_field>(
            TLV_EMV_CONTEXT_BASE, tlv::tag_bytes<0x9F, 0x44>());
    }
    {
        SCOPED_TRACE("icc_public_key_exponent");
        emv_dictionary_round_trip<tlv::emv::icc_public_key_exponent_field>(
            TLV_EMV_CONTEXT_BASE, tlv::tag_bytes<0x9F, 0x47>());
    }
    {
        SCOPED_TRACE("bht_biometric_header_version");
        emv_dictionary_round_trip<tlv::emv::bht_biometric_header_version_field>(
            TLV_EMV_CONTEXT_BHT, tlv::tag_bytes<0x80>());
    }
    {
        SCOPED_TRACE("bht_biometric_type");
        emv_dictionary_round_trip<tlv::emv::bht_biometric_type_field>(TLV_EMV_CONTEXT_BHT,
                                                                      tlv::tag_bytes<0x81>());
    }
    {
        SCOPED_TRACE("bht_biometric_subtype");
        emv_dictionary_round_trip<tlv::emv::bht_biometric_subtype_field>(TLV_EMV_CONTEXT_BHT,
                                                                         tlv::tag_bytes<0x82>());
    }
    {
        SCOPED_TRACE("bht_biometric_product_id");
        emv_dictionary_round_trip<tlv::emv::bht_biometric_product_id_field>(TLV_EMV_CONTEXT_BHT,
                                                                            tlv::tag_bytes<0x86>());
    }
    {
        SCOPED_TRACE("bht_biometric_format_owner");
        emv_dictionary_round_trip<tlv::emv::bht_biometric_format_owner_field>(
            TLV_EMV_CONTEXT_BHT, tlv::tag_bytes<0x87>());
    }
    {
        SCOPED_TRACE("bht_biometric_format_type");
        emv_dictionary_round_trip<tlv::emv::bht_biometric_format_type_field>(
            TLV_EMV_CONTEXT_BHT, tlv::tag_bytes<0x88>());
    }
    {
        SCOPED_TRACE("bht_format_bht_format_owner");
        emv_dictionary_round_trip<tlv::emv::bht_format_bht_format_owner_field>(
            TLV_EMV_CONTEXT_BHT_FORMAT, tlv::tag_bytes<0x87>());
    }
    {
        SCOPED_TRACE("bht_format_bht_format_type");
        emv_dictionary_round_trip<tlv::emv::bht_format_bht_format_type_field>(
            TLV_EMV_CONTEXT_BHT_FORMAT, tlv::tag_bytes<0x88>());
    }
    {
        SCOPED_TRACE("bit_group_bit_count");
        emv_dictionary_round_trip<tlv::emv::bit_group_bit_count_field>(TLV_EMV_CONTEXT_BIT_GROUP,
                                                                       tlv::tag_bytes<0x02>());
    }
    {
        SCOPED_TRACE("biometric_counters_facial_try_counter");
        emv_dictionary_round_trip<tlv::emv::biometric_counters_facial_try_counter_field>(
            TLV_EMV_CONTEXT_BIOMETRIC_COUNTERS, tlv::tag_bytes<0xDF, 0x50>());
    }
    {
        SCOPED_TRACE("biometric_counters_finger_try_counter");
        emv_dictionary_round_trip<tlv::emv::biometric_counters_finger_try_counter_field>(
            TLV_EMV_CONTEXT_BIOMETRIC_COUNTERS, tlv::tag_bytes<0xDF, 0x51>());
    }
    {
        SCOPED_TRACE("biometric_counters_iris_try_counter");
        emv_dictionary_round_trip<tlv::emv::biometric_counters_iris_try_counter_field>(
            TLV_EMV_CONTEXT_BIOMETRIC_COUNTERS, tlv::tag_bytes<0xDF, 0x52>());
    }
    {
        SCOPED_TRACE("biometric_counters_palm_try_counter");
        emv_dictionary_round_trip<tlv::emv::biometric_counters_palm_try_counter_field>(
            TLV_EMV_CONTEXT_BIOMETRIC_COUNTERS, tlv::tag_bytes<0xDF, 0x53>());
    }
    {
        SCOPED_TRACE("biometric_counters_voice_try_counter");
        emv_dictionary_round_trip<tlv::emv::biometric_counters_voice_try_counter_field>(
            TLV_EMV_CONTEXT_BIOMETRIC_COUNTERS, tlv::tag_bytes<0xDF, 0x54>());
    }
    {
        SCOPED_TRACE("biometric_attempts_preferred_facial_attempts");
        emv_dictionary_round_trip<tlv::emv::biometric_attempts_preferred_facial_attempts_field>(
            TLV_EMV_CONTEXT_BIOMETRIC_ATTEMPTS, tlv::tag_bytes<0xDF, 0x50>());
    }
    {
        SCOPED_TRACE("biometric_attempts_preferred_finger_attempts");
        emv_dictionary_round_trip<tlv::emv::biometric_attempts_preferred_finger_attempts_field>(
            TLV_EMV_CONTEXT_BIOMETRIC_ATTEMPTS, tlv::tag_bytes<0xDF, 0x51>());
    }
    {
        SCOPED_TRACE("biometric_attempts_preferred_iris_attempts");
        emv_dictionary_round_trip<tlv::emv::biometric_attempts_preferred_iris_attempts_field>(
            TLV_EMV_CONTEXT_BIOMETRIC_ATTEMPTS, tlv::tag_bytes<0xDF, 0x52>());
    }
    {
        SCOPED_TRACE("biometric_attempts_preferred_palm_attempts");
        emv_dictionary_round_trip<tlv::emv::biometric_attempts_preferred_palm_attempts_field>(
            TLV_EMV_CONTEXT_BIOMETRIC_ATTEMPTS, tlv::tag_bytes<0xDF, 0x53>());
    }
    {
        SCOPED_TRACE("biometric_attempts_preferred_voice_attempts");
        emv_dictionary_round_trip<tlv::emv::biometric_attempts_preferred_voice_attempts_field>(
            TLV_EMV_CONTEXT_BIOMETRIC_ATTEMPTS, tlv::tag_bytes<0xDF, 0x54>());
    }
    {
        SCOPED_TRACE("biometric_verification_verification_biometric_type");
        emv_dictionary_round_trip<
            tlv::emv::biometric_verification_verification_biometric_type_field>(
            TLV_EMV_CONTEXT_BIOMETRIC_VERIFICATION, tlv::tag_bytes<0x81>());
    }
}
#endif
