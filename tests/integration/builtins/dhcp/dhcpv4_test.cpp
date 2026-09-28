#include "tlv/builtins/dhcp/dhcpv4.h"
#include "tlv/builtins/dhcp/options.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#include <gtest/gtest.h>
#include <cstring>

TEST(Integration_Tlv_Dhcpv4, DefinitionsLeaveKnownAndUnknownValuesOpaque) {
    const uint8_t wire[] = {0x35, 0x01, 0x03, 0xE0, 0x02, 0xAA, 0xBB};
    uint8_t       output[sizeof(wire)] = {};
    tlv_reader_t  reader{};
    tlv_writer_t  writer{};
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, wire, sizeof(wire), &tlv_format_dhcpv4));
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, output, sizeof(output), &tlv_format_dhcpv4));
    tlv_element_t element{};
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
    ASSERT_EQ(1u, element.tag.size);
    EXPECT_EQ(0x35, element.tag.data[0]);
    ASSERT_EQ(1u, element.value.size);
    EXPECT_EQ(0x03, element.value.data[0]);
    const auto* definition = tlv_definition_find(&tlv_dhcpv4_options, &element.tag);
    ASSERT_NE(nullptr, definition);
    EXPECT_STREQ("DHCP Message Type", definition->name);
    ASSERT_EQ(TLV_OK, tlv_writer_copy_element(&writer, &element));

    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
    ASSERT_EQ(1u, element.tag.size);
    EXPECT_EQ(0xE0, element.tag.data[0]);
    EXPECT_EQ(nullptr, tlv_definition_find(&tlv_dhcpv4_options, &element.tag));
    ASSERT_EQ(2u, element.value.size);
    EXPECT_EQ(wire + 5, element.value.data);
    EXPECT_EQ(0xAA, element.value.data[0]);
    EXPECT_EQ(0xBB, element.value.data[1]);
    ASSERT_EQ(TLV_OK, tlv_writer_copy_element(&writer, &element));
    EXPECT_TRUE(tlv_reader_at_end(&reader));
    EXPECT_EQ(sizeof(wire), tlv_writer_size(&writer));
    EXPECT_EQ(0, std::memcmp(wire, output, sizeof(wire)));
}

TEST(Integration_Tlv_Dhcpv4, ReaderWriterExposePadAndContinuePastEnd) {
    const uint8_t wire[] = {0, 53, 1, 1, 254, 0, 255, 0, 42, 1, 7};
    const uint8_t codes[] = {0, 53, 254, 255, 0, 42};
    const size_t  lengths[] = {0, 1, 0, 0, 0, 1};
    uint8_t       output[sizeof(wire)] = {};
    tlv_reader_t  reader{};
    tlv_writer_t  writer{};
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, wire, sizeof(wire), &tlv_format_dhcpv4));
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, output, sizeof(output), &tlv_format_dhcpv4));
    size_t offset = 0;
    for (size_t i = 0; i < sizeof(codes); ++i) {
        tlv_element_t element{};
        ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
        EXPECT_EQ(codes[i], element.tag.data[0]);
        EXPECT_EQ(lengths[i], element.value.size);
        ASSERT_EQ(TLV_OK, tlv_writer_copy_element(&writer, &element));
        tlv_source_t source{};
        size_t       consumed = 0;
        ASSERT_EQ(TLV_OK,
                  tlv_read_source_diag(wire + offset, sizeof(wire) - offset, &tlv_format_dhcpv4,
                                       &element, &consumed, &source, nullptr));
        EXPECT_EQ(consumed, source.size);
        offset += consumed;
    }
    EXPECT_TRUE(tlv_reader_at_end(&reader));
    EXPECT_EQ(sizeof(wire), offset);
    EXPECT_EQ(sizeof(wire), tlv_writer_size(&writer));
    EXPECT_EQ(0, std::memcmp(wire, output, sizeof(wire)));
    tlv_element_t element{};
    EXPECT_EQ(TLV_ERR_END_OF_BUFFER, tlv_reader_next(&reader, &element));
}
