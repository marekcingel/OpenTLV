#include "tlv/builtins/dhcp/dhcpv4.h"
#include "tlv/builtins/dhcp/options.h"
#include "tlv/config.h"
#include <gtest/gtest.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <vector>

TEST(Unit_Tlv_Dhcpv4, OptionDefinitionsMapUniqueOneByteCodes) {
    const struct {
        uint8_t     code;
        const char* name;
    } expected[] = {
        {0, "Pad"},
        {1, "Subnet Mask"},
        {3, "Router"},
        {6, "Domain Name Server"},
        {12, "Host Name"},
        {15, "Domain Name"},
        {50, "Requested IP Address"},
        {51, "IP Address Lease Time"},
        {53, "DHCP Message Type"},
        {54, "Server Identifier"},
        {55, "Parameter Request List"},
        {57, "Maximum DHCP Message Size"},
        {58, "Renewal Time Value"},
        {59, "Rebinding Time Value"},
        {60, "Vendor Class Identifier"},
        {61, "Client Identifier"},
        {255, "End"},
    };
    ASSERT_EQ(sizeof(expected) / sizeof(expected[0]), tlv_dhcpv4_options.count);
    for (const auto& entry : expected) {
        SCOPED_TRACE(entry.code);
        const auto  tag = tlv_tag(&entry.code, 1);
        const auto* definition = tlv_definition_find(&tlv_dhcpv4_options, &tag);
        ASSERT_NE(nullptr, definition);
        EXPECT_STREQ(entry.name, definition->name);
        EXPECT_EQ(1u, definition->tag.size);
        EXPECT_EQ(entry.code, definition->tag.data[0]);
    }
    for (size_t i = 0; i < tlv_dhcpv4_options.count; ++i) {
        for (size_t j = i + 1; j < tlv_dhcpv4_options.count; ++j) {
            EXPECT_FALSE(tlv_tag_equal(tlv_dhcpv4_options.entries[i].tag,
                                       tlv_dhcpv4_options.entries[j].tag));
        }
    }
    const uint8_t unknown = 0xE0;
    const auto    tag = tlv_tag(&unknown, 1);
    EXPECT_EQ(nullptr, tlv_definition_find(&tlv_dhcpv4_options, &tag));
    const uint8_t extended[] = {0, 53};
    const auto    wide_tag = tlv_tag(extended, sizeof(extended));
    EXPECT_EQ(nullptr, tlv_definition_find(&tlv_dhcpv4_options, &wide_tag));
}

TEST(Unit_Tlv_Dhcpv4, EveryCodeLengthsRangesAndPreservation) {
    EXPECT_EQ(1, tlv_config_dhcp());
    for (unsigned code = 0; code < 256; ++code) {
        const bool special = code == 0 || code == 255;
        for (size_t length : {size_t(0), size_t(1), size_t(255)}) {
            if (special && length) continue;
            SCOPED_TRACE(code);
            SCOPED_TRACE(length);
            const size_t         header = special ? 1 : 2;
            std::vector<uint8_t> wire(header + length, 0xA5);
            wire[0] = static_cast<uint8_t>(code);
            if (!special) wire[1] = static_cast<uint8_t>(length);
            tlv_decoded_t decoded{};
            ASSERT_EQ(TLV_OK, tlv_format_decode(&tlv_format_dhcpv4, wire.data(), wire.size(),
                                                &decoded, nullptr));
            EXPECT_EQ(wire.data(), decoded.element.tag.data);
            EXPECT_EQ(1u, decoded.element.tag.size);
            EXPECT_EQ(wire.data() + header, decoded.element.value.data);
            EXPECT_EQ(length, decoded.element.value.size);
            EXPECT_EQ(wire.size(), decoded.source.size);
            EXPECT_EQ(0u, decoded.source.header.offset);
            EXPECT_EQ(header, decoded.source.header.size);
            EXPECT_EQ(0u, decoded.source.tag.offset);
            EXPECT_EQ(1u, decoded.source.tag.size);
            EXPECT_EQ(!special, !!decoded.source.length.present);
            if (!special) {
                EXPECT_EQ(1u, decoded.source.length.offset);
                EXPECT_EQ(1u, decoded.source.length.size);
            }
            EXPECT_TRUE(decoded.source.value.present);
            EXPECT_EQ(header, decoded.source.value.offset);
            EXPECT_EQ(length, decoded.source.value.size);
            EXPECT_TRUE(decoded.source.trailer.present);
            EXPECT_EQ(wire.size(), decoded.source.trailer.offset);
            EXPECT_EQ(0u, decoded.source.trailer.size);
            tlv_encoding_t sizes{};
            ASSERT_EQ(TLV_OK,
                      tlv_format_measure(&tlv_format_dhcpv4, &decoded.element, &sizes, nullptr));
            EXPECT_EQ(header, sizes.header);
            EXPECT_EQ(length, sizes.value);
            EXPECT_EQ(0u, sizes.trailer);
            EXPECT_EQ(wire.size(), sizes.total);
            std::vector<uint8_t> output(wire.size() + 1, 0xCC);
            size_t               written = 0;
            ASSERT_EQ(TLV_OK, tlv_format_encode(&tlv_format_dhcpv4, &decoded.element, output.data(),
                                                wire.size(), &written, nullptr));
            EXPECT_EQ(wire.size(), written);
            EXPECT_TRUE(std::equal(wire.begin(), wire.end(), output.begin()));
            EXPECT_EQ(0xCC, output.back());
            std::fill(output.begin(), output.end(), 0xCC);
            ASSERT_EQ(TLV_OK, tlv_source_preserve(&decoded.source, &decoded.element, output.data(),
                                                  wire.size(), &written));
            EXPECT_TRUE(std::equal(wire.begin(), wire.end(), output.begin()));
            EXPECT_EQ(0xCC, output.back());
            std::fill(output.begin(), output.end(), 0xCC);
            EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
                      tlv_format_encode(&tlv_format_dhcpv4, &decoded.element, output.data(),
                                        wire.size() - 1, &written, nullptr));
            EXPECT_EQ(wire.size(), written);
            EXPECT_TRUE(
                std::all_of(output.begin(), output.end(), [](uint8_t b) { return b == 0xCC; }));
            uint8_t different = static_cast<uint8_t>(code ^ 1);
            auto    changed = decoded.element;
            changed.tag = tlv_tag(&different, 1);
            EXPECT_EQ(TLV_ERR_INVALID_ARG,
                      tlv_source_preserve(&decoded.source, &changed, output.data(), output.size(),
                                          &written));
            if (length) {
                auto altered = wire;
                altered[header] ^= 1;
                changed = decoded.element;
                changed.value.data = altered.data() + header;
                EXPECT_EQ(TLV_ERR_INVALID_ARG,
                          tlv_source_preserve(&decoded.source, &changed, output.data(),
                                              output.size(), &written));
            }
        }
    }
}

TEST(Unit_Tlv_Dhcpv4, RejectsUnrepresentableElementsWithoutWriting) {
    std::array<uint8_t, 256> value{};
    std::array<uint8_t, 260> output;
    const uint8_t            codes[] = {0, 255, 53};
    for (uint8_t code : codes) {
        const size_t       length = code == 53 ? 256 : 1;
        tlv_element_t      element{tlv_tag(&code, 1), {value.data(), length}};
        tlv_encoding_t     sizes{9, 9, 9, 27};
        tlv_format_error_t error{};
        EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
                  tlv_format_measure(&tlv_format_dhcpv4, &element, &sizes, &error));
        EXPECT_EQ(27u, sizes.total);
        output.fill(0xCC);
        size_t written = 999;
        EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
                  tlv_format_encode(&tlv_format_dhcpv4, &element, output.data(), output.size(),
                                    &written, nullptr));
        EXPECT_EQ(999u, written);
        EXPECT_TRUE(std::all_of(output.begin(), output.end(), [](uint8_t b) { return b == 0xCC; }));
    }
    for (size_t width : {size_t(0), size_t(2)}) {
        tlv_element_t  element{tlv_tag(codes, width), {nullptr, 0}};
        tlv_encoding_t sizes{};
        EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE,
                  tlv_format_measure(&tlv_format_dhcpv4, &element, &sizes, nullptr));
    }
    tlv_element_t  element{tlv_tag(codes + 2, 1), {nullptr, 255}};
    tlv_encoding_t sizes{};
    EXPECT_EQ(TLV_OK, tlv_format_measure(&tlv_format_dhcpv4, &element, &sizes, nullptr));
    EXPECT_EQ(257u, sizes.total);
}

TEST(Unit_Tlv_Dhcpv4, TruncationDiagnosticsAndUnchangedDecodeOutput) {
    const uint8_t wire[] = {53, 3, 1, 2, 3};
    for (size_t size = 0; size < sizeof(wire); ++size) {
        tlv_decoded_t decoded{};
        decoded.source.size = 999;
        tlv_format_error_t error{};
        EXPECT_EQ(size ? TLV_ERR_BUFFER_TOO_SHORT : TLV_ERR_END_OF_BUFFER,
                  tlv_format_decode(&tlv_format_dhcpv4, wire, size, &decoded, &error));
        EXPECT_EQ(999u, decoded.source.size);
        if (size) {
            EXPECT_EQ(size == 1 ? TLV_REGION_LENGTH : TLV_REGION_VALUE, error.region);
            EXPECT_EQ(size == 1 ? 1u : 2u, error.offset);
            EXPECT_TRUE(error.has_offset);
        }
    }
}
