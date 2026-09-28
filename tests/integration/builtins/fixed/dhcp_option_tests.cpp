#include "tlv/formats/fixed.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"

#include <gtest/gtest.h>

namespace {
const tlv_fixed_format_t fixed_config = {1, 1, TLV_BYTE_ORDER_BIG_ENDIAN, TLV_ELEMENT_ORDER_TLV,
                                         TLV_LENGTH_SCOPE_VALUE};
const tlv_format_t       fixed_format = [] {
    tlv_format_t format{};
    (void)tlv_fixed_format_init(&format, &fixed_config);
    return format;
}();
} // namespace

TEST(Integration_Tlv, DhcpOption1) {
    const uint8_t data[] = {0x01, 0x04, 0xFF, 0xFF, 0xFF, 0x00};

    tlv_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data), &fixed_format));

    tlv_element_t element;
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
    ASSERT_EQ(1, element.tag.size);
    ASSERT_EQ(0x01, element.tag.data[0]);
    ASSERT_EQ(4, element.value.size);
}

TEST(Integration_Tlv, DhcpOption3) {
    const uint8_t data[] = {0x03, 0x04, 0xC0, 0xA8, 0x01, 0x01};

    tlv_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data), &fixed_format));

    tlv_element_t element;
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
    ASSERT_EQ(1, element.tag.size);
    ASSERT_EQ(0x03, element.tag.data[0]);
    ASSERT_EQ(4, element.value.size);
}

TEST(Integration_Tlv, DhcpOption6) {
    const uint8_t data[] = {0x06, 0x08, 0x08, 0x08, 0x08, 0x08, 0x01, 0x01, 0x01, 0x01};

    tlv_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data), &fixed_format));

    tlv_element_t element;
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
    ASSERT_EQ(1, element.tag.size);
    ASSERT_EQ(0x06, element.tag.data[0]);
    ASSERT_EQ(8, element.value.size);
}

TEST(Integration_Tlv, DhcpOption12) {
    const uint8_t data[] = {0x0C, 0x09, 0x6D, 0x79, 0x2D, 0x72, 0x6F, 0x75, 0x74, 0x65, 0x72};

    tlv_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data), &fixed_format));

    tlv_element_t element;
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
    ASSERT_EQ(1, element.tag.size);
    ASSERT_EQ(0x0C, element.tag.data[0]);
    ASSERT_EQ(9, element.value.size);
}
