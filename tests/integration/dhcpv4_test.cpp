#include "tlv/builtins/dhcp/dhcpv4.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#include <gtest/gtest.h>
#include <cstring>

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
