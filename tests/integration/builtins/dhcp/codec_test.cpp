#include "tlv/schema/schema.h"
#include "tlv/builtins/dhcp/codec.h"
#include "tlv/builtins/dhcp/dhcpv4.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#include <gtest/gtest.h>
#include <cstring>

TEST(Integration_Tlv_DhcpCodecs, MessageTypeRoundTripAndOpaqueFraming) {
    for (unsigned code = 0; code <= 255; ++code) {
        const uint8_t wire[] = {53, 1, static_cast<uint8_t>(code)};
        tlv_reader_t  reader{};
        tlv_element_t element{};
        ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, wire, sizeof(wire), &tlv_format_dhcpv4));
        ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
        EXPECT_EQ(wire + 2, element.value.data);
        size_t length = 0;
        ASSERT_EQ(TLV_OK, tlv_size_to_native(element.value.size, &length));
        uint8_t type = 0;
        ASSERT_EQ(TLV_CODEC_OK, tlv_codec_decode(&tlv_dhcpv4_codec_message_type, element.value.data,
                                                 length, &type, sizeof(type)));
        EXPECT_EQ(code, type);
        if (code == 3) EXPECT_EQ(TLV_DHCPV4_REQUEST, type);
        size_t written = 0;
        ASSERT_EQ(TLV_CODEC_OK, tlv_codec_encode(&tlv_dhcpv4_codec_message_type, &type,
                                                 sizeof(type), nullptr, 0, &written));
        EXPECT_EQ(1u, written);
        uint8_t value = 0;
        ASSERT_EQ(TLV_CODEC_OK, tlv_codec_encode(&tlv_dhcpv4_codec_message_type, &type,
                                                 sizeof(type), &value, sizeof(value), &written));
        element.value = {&value, written};
        uint8_t      output[sizeof(wire)] = {};
        tlv_writer_t writer{};
        ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, output, sizeof(output), &tlv_format_dhcpv4));
        ASSERT_EQ(TLV_OK, tlv_writer_copy_element(&writer, &element));
        EXPECT_EQ(0, std::memcmp(wire, output, sizeof(wire)));
    }
}

TEST(Integration_Tlv_DhcpCodecs, MessageTypeRejectsMalformedRepresentations) {
    uint8_t     wire[] = {3, 4};
    uint8_t     type = 0;
    const auto* codec = &tlv_dhcpv4_codec_message_type;
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE, tlv_codec_decode(codec, wire, 0, &type, sizeof(type)));
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE, tlv_codec_decode(codec, wire, 2, &type, sizeof(type)));
    EXPECT_EQ(TLV_CODEC_ERR_BUFFER_TOO_SHORT, tlv_codec_decode(codec, wire, 1, &type, 0));
    size_t written = 99;
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE, tlv_codec_encode(codec, &type, 0, nullptr, 0, &written));
    EXPECT_EQ(0u, written);
    EXPECT_EQ(TLV_CODEC_ERR_BUFFER_TOO_SHORT,
              tlv_codec_encode(codec, &type, sizeof(type), wire, 0, &written));
    EXPECT_EQ(0u, written);
}

TEST(Integration_Tlv_DhcpCodecs, MessageTypeIsGenericWithCallerOwnedSchema) {
    EXPECT_EQ(&tlv_codec_uint8, &tlv_dhcpv4_codec_message_type);
    const tlv_schema_entry_t field = {TLV_TAG(53), 1, 1, 0, "message_type", 0};
    EXPECT_EQ(TLV_OK, tlv_schema_validate_length(&field, 1));
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_schema_validate_length(&field, 0));
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_schema_validate_length(&field, 2));
}
