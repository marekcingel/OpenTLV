#include "tlv/builtins/lldp/codec.h"
#include <gtest/gtest.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <vector>

namespace {
template <typename T> T roundtrip(const tlv_codec_t& codec, const std::vector<uint8_t>& wire) {
    T value{};
    EXPECT_EQ(TLV_CODEC_OK,
              tlv_codec_decode(&codec, wire.data(), wire.size(), &value, sizeof(value)));
    size_t size = 999;
    EXPECT_EQ(TLV_CODEC_OK, tlv_codec_encode(&codec, &value, sizeof(value), nullptr, 0, &size));
    EXPECT_EQ(wire.size(), size);
    std::vector<uint8_t> encoded(wire.size() + 1, 0xCC);
    EXPECT_EQ(TLV_CODEC_OK,
              tlv_codec_encode(&codec, &value, sizeof(value), encoded.data(), wire.size(), &size));
    EXPECT_TRUE(std::equal(wire.begin(), wire.end(), encoded.begin()));
    EXPECT_EQ(0xCC, encoded.back());
    EXPECT_EQ(TLV_CODEC_ERR_BUFFER_TOO_SHORT,
              tlv_codec_decode(&codec, wire.data(), wire.size(), &value, sizeof(value) - 1));
    if (!wire.empty()) {
        encoded.assign(wire.size(), 0xCC);
        EXPECT_EQ(TLV_CODEC_ERR_BUFFER_TOO_SHORT,
                  tlv_codec_encode(&codec, &value, sizeof(value), encoded.data(), wire.size() - 1,
                                   &size));
        EXPECT_EQ(0u, size);
        for (uint8_t byte : encoded) EXPECT_EQ(0xCC, byte);
    }
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_encode(&codec, &value, sizeof(value) - 1, nullptr, 0, &size));
    return value;
}

template <typename T> void invalid(const tlv_codec_t& codec, const std::vector<uint8_t>& wire) {
    T value{};
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_decode(&codec, wire.data(), wire.size(), &value, sizeof(value)));
}
} // namespace

TEST(Unit_Tlv_LldpCodec, IdNamespacesAndBorrowing) {
    const std::vector<uint8_t> chassis = {4, 0, 1, 2, 3, 4, 5};
    auto                       id = roundtrip<tlv_lldp_id_t>(tlv_lldp_codec_chassis_id, chassis);
    EXPECT_EQ(4, id.subtype);
    EXPECT_EQ(chassis.data() + 1, id.identifier.data);
    EXPECT_EQ(6u, id.identifier.size);
    roundtrip<tlv_lldp_id_t>(tlv_lldp_codec_port_id, {3, 0, 1, 2, 3, 4, 5});
    roundtrip<tlv_lldp_id_t>(tlv_lldp_codec_chassis_id, {5, 1, 192, 0, 2, 1});
    roundtrip<tlv_lldp_id_t>(tlv_lldp_codec_port_id, {4, 1, 192, 0, 2, 1});
    for (auto codec : {&tlv_lldp_codec_chassis_id, &tlv_lldp_codec_port_id}) {
        roundtrip<tlv_lldp_id_t>(*codec, {7, 'a'});
        std::vector<uint8_t> largest(256, 'a');
        largest[0] = 7;
        roundtrip<tlv_lldp_id_t>(*codec, largest);
        largest.push_back('a');
        invalid<tlv_lldp_id_t>(*codec, largest);
        invalid<tlv_lldp_id_t>(*codec, {});
        invalid<tlv_lldp_id_t>(*codec, {7});
        invalid<tlv_lldp_id_t>(*codec, {0, 'a'});
        invalid<tlv_lldp_id_t>(*codec, {8, 'a'});
    }
    invalid<tlv_lldp_id_t>(tlv_lldp_codec_chassis_id, {4, 0, 1, 2, 3, 4});
    invalid<tlv_lldp_id_t>(tlv_lldp_codec_port_id, {3, 0, 1, 2, 3, 4, 5, 6});
    invalid<tlv_lldp_id_t>(tlv_lldp_codec_chassis_id, {5, 1, 192, 0, 2});
    invalid<tlv_lldp_id_t>(tlv_lldp_codec_port_id, {4, 0, 42});
    std::vector<uint8_t> ipv6(18, 0);
    ipv6[0] = 5;
    ipv6[1] = 2;
    roundtrip<tlv_lldp_id_t>(tlv_lldp_codec_chassis_id, ipv6);
}

TEST(Unit_Tlv_LldpCodec, TtlCapabilitiesAndText) {
    EXPECT_EQ(120, roundtrip<uint16_t>(tlv_lldp_codec_ttl, {0, 120}));
    EXPECT_EQ(0, roundtrip<uint16_t>(tlv_lldp_codec_ttl, {0, 0}));
    EXPECT_EQ(65535, roundtrip<uint16_t>(tlv_lldp_codec_ttl, {255, 255}));
    invalid<uint16_t>(tlv_lldp_codec_ttl, {0});
    invalid<uint16_t>(tlv_lldp_codec_ttl, {0, 0, 0});
    auto caps = roundtrip<tlv_lldp_capabilities_t>(tlv_lldp_codec_capabilities, {0, 0x14, 0, 4});
    EXPECT_EQ(0x14, caps.supported);
    EXPECT_EQ(4, caps.enabled);
    roundtrip<tlv_lldp_capabilities_t>(tlv_lldp_codec_capabilities, {0x80, 0, 0x80, 0});
    invalid<tlv_lldp_capabilities_t>(tlv_lldp_codec_capabilities, {0, 4, 0, 8});
    invalid<tlv_lldp_capabilities_t>(tlv_lldp_codec_capabilities, {0, 4, 0});
    roundtrip<tlv_value_t>(tlv_lldp_codec_text, {});
    const std::vector<uint8_t> text = {'a', 0, 0xFF};
    EXPECT_EQ(text.data(), roundtrip<tlv_value_t>(tlv_lldp_codec_text, text).data);
    roundtrip<tlv_value_t>(tlv_lldp_codec_text, std::vector<uint8_t>(255, 'x'));
    invalid<tlv_value_t>(tlv_lldp_codec_text, std::vector<uint8_t>(256, 'x'));
}

TEST(Unit_Tlv_LldpCodec, ManagementAddressInnerBoundsAndExactConsumption) {
    // Length includes family; IPv4; ifIndex 0x01020304; empty OID.
    const std::vector<uint8_t> wire = {5, 1, 192, 0, 2, 1, 2, 1, 2, 3, 4, 0};
    const auto                 address =
        roundtrip<tlv_lldp_management_address_t>(tlv_lldp_codec_management_address, wire);
    EXPECT_EQ(wire.data() + 2, address.address.data);
    EXPECT_EQ(4u, address.address.size);
    EXPECT_EQ(0x01020304u, address.interface_number);
    EXPECT_EQ(0u, address.oid.size);
    for (size_t count = 0; count < wire.size(); ++count)
        invalid<tlv_lldp_management_address_t>(tlv_lldp_codec_management_address,
                                               {wire.begin(), wire.begin() + count});
    for (size_t offset : {size_t(0), size_t(1), size_t(6), size_t(11)}) {
        auto bad = wire;
        bad[offset] = 255;
        if (offset != 1)
            invalid<tlv_lldp_management_address_t>(tlv_lldp_codec_management_address, bad);
        else
            roundtrip<tlv_lldp_management_address_t>(tlv_lldp_codec_management_address, bad);
    }
    auto extra = wire;
    extra.push_back(0);
    invalid<tlv_lldp_management_address_t>(tlv_lldp_codec_management_address, extra);
    std::vector<uint8_t> maximum(167, 0x55);
    maximum[0] = 32;
    maximum[1] = 250; // Unassigned family remains opaque.
    maximum[33] = 3;
    maximum[38] = 128;
    roundtrip<tlv_lldp_management_address_t>(tlv_lldp_codec_management_address, maximum);
    maximum[38] = 129;
    maximum.push_back(0);
    invalid<tlv_lldp_management_address_t>(tlv_lldp_codec_management_address, maximum);
    roundtrip<tlv_lldp_management_address_t>(tlv_lldp_codec_management_address,
                                             {2, 250, 42, 1, 0, 0, 0, 0, 0});
}

TEST(Unit_Tlv_LldpCodec, OrganisationalPrefixAndMaximumPayload) {
    const std::vector<uint8_t> wire = {0, 0x80, 0xC2, 1, 0, 42};
    auto org = roundtrip<tlv_lldp_organisation_t>(tlv_lldp_codec_organisation, wire);
    EXPECT_EQ(0x80, org.oui[1]);
    EXPECT_EQ(1, org.subtype);
    EXPECT_EQ(wire.data() + 4, org.payload.data);
    EXPECT_EQ(2u, org.payload.size);
    roundtrip<tlv_lldp_organisation_t>(tlv_lldp_codec_organisation, {0, 0, 0, 0});
    roundtrip<tlv_lldp_organisation_t>(tlv_lldp_codec_organisation, std::vector<uint8_t>(511, 255));
    invalid<tlv_lldp_organisation_t>(tlv_lldp_codec_organisation, std::vector<uint8_t>(512, 0));
    for (size_t count = 0; count < 4; ++count)
        invalid<tlv_lldp_organisation_t>(tlv_lldp_codec_organisation,
                                         std::vector<uint8_t>(count, 0));
}

TEST(Unit_Tlv_LldpCodec, EncodingRejectsInvalidAndOversizedRepresentations) {
    uint8_t     byte = 1;
    size_t      written = 999;
    tlv_value_t text = {nullptr, 1};
    EXPECT_EQ(TLV_CODEC_ERR_NULL_ARG,
              tlv_codec_encode(&tlv_lldp_codec_text, &text, sizeof(text), nullptr, 0, &written));
    EXPECT_EQ(0u, written);
    text = {&byte, UINT64_MAX};
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_encode(&tlv_lldp_codec_text, &text, sizeof(text), nullptr, 0, &written));
    tlv_lldp_id_t id = {4, {&byte, 1}};
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_encode(&tlv_lldp_codec_chassis_id, &id, sizeof(id), nullptr, 0, &written));
    tlv_lldp_capabilities_t caps = {4, 8};
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE, tlv_codec_encode(&tlv_lldp_codec_capabilities, &caps,
                                                            sizeof(caps), nullptr, 0, &written));
    tlv_lldp_organisation_t org = {{0, 0, 0}, 0, {&byte, 508}};
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE, tlv_codec_encode(&tlv_lldp_codec_organisation, &org,
                                                            sizeof(org), nullptr, 0, &written));
    tlv_lldp_management_address_t address = {250, {&byte, 1}, 4, 0, {nullptr, 0}};
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_encode(&tlv_lldp_codec_management_address, &address, sizeof(address),
                               nullptr, 0, &written));
    address.interface_subtype = 1;
    address.oid = {&byte, UINT64_MAX};
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_encode(&tlv_lldp_codec_management_address, &address, sizeof(address),
                               nullptr, 0, &written));
}
