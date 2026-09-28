#include "tlv/builtins/bluetooth/ad_codec.h"
#include "tlv/config.h"
#include <gtest/gtest.h>

#if OPENTLV_FORMAT_BLUETOOTH_LTV
#include "tlv/builtins/bluetooth/bluetooth_ltv.h"
#include "tlv/reader/reader.h"
#include <cstring>

TEST(Integration_Tlv_BluetoothAdCodec, Story346DecodesValuesAndPreservesRawBytes) {
    const uint8_t wire[] = {0x02, 0x01, 0x06, 0x02, 0x0A, 0xFC, 0x07,
                            0x09, 0x53, 0x65, 0x6E, 0x73, 0x6F, 0x72};
    tlv_reader_t  reader = {};
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, wire, sizeof(wire), &tlv_format_bluetooth_ltv));
    tlv_element_t element = {};
    tlv_value_t   flags = {}, name = {};
    int8_t        power = 0;
    size_t        length = 0;
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
    ASSERT_EQ(TLV_OK, tlv_size_to_native(element.value.size, &length));
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_decode(&tlv_bluetooth_ad_codec_flags, element.value.data,
                                             length, &flags, sizeof(flags)));
    EXPECT_EQ(wire + 2, flags.data);
    EXPECT_EQ(0x06, flags.data[0]);
    EXPECT_TRUE(tlv_bluetooth_ad_flags_test(&flags, TLV_BLUETOOTH_AD_FLAG_LE_GENERAL_DISCOVERABLE));
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
    ASSERT_EQ(TLV_OK, tlv_size_to_native(element.value.size, &length));
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_decode(&tlv_bluetooth_ad_codec_tx_power, element.value.data,
                                             length, &power, sizeof(power)));
    EXPECT_EQ(-4, power);
    EXPECT_EQ(wire + 5, element.value.data);
    EXPECT_EQ(0xFC, element.value.data[0]);
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
    EXPECT_EQ(0x09, element.tag.data[0]);
    ASSERT_EQ(TLV_OK, tlv_size_to_native(element.value.size, &length));
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_decode(&tlv_bluetooth_ad_codec_local_name, element.value.data,
                                             length, &name, sizeof(name)));
    EXPECT_EQ(wire + 8, name.data);
    EXPECT_EQ(6u, name.size);
    EXPECT_EQ(0, std::memcmp(name.data, "Sensor", 6));
    EXPECT_TRUE(tlv_reader_at_end(&reader));
}

TEST(Integration_Tlv_BluetoothAdCodec, BothNameTypesUseTheSameCodec) {
    for (uint8_t type : {uint8_t(0x08), uint8_t(0x09)}) {
        const uint8_t wire[] = {3, type, 'H', 'i'};
        tlv_element_t element = {};
        size_t        consumed = 0, length = 0;
        ASSERT_EQ(TLV_OK,
                  tlv_read(wire, sizeof(wire), &tlv_format_bluetooth_ltv, &element, &consumed));
        ASSERT_EQ(TLV_OK, tlv_size_to_native(element.value.size, &length));
        tlv_value_t name = {};
        ASSERT_EQ(TLV_CODEC_OK, tlv_codec_decode(&tlv_bluetooth_ad_codec_local_name,
                                                 element.value.data, length, &name, sizeof(name)));
        EXPECT_EQ(wire + 2, name.data);
        EXPECT_EQ(2u, name.size);
        EXPECT_EQ(type, element.tag.data[0]);
    }
}

TEST(Integration_Tlv_BluetoothAdCodec, InvalidSemanticValueRemainsAvailableAfterParsing) {
    const uint8_t wire[] = {2, 0x0A, 0x80};
    tlv_element_t element = {};
    size_t        consumed = 0;
    ASSERT_EQ(TLV_OK, tlv_read(wire, sizeof(wire), &tlv_format_bluetooth_ltv, &element, &consumed));
    int8_t     power = 0;
    const auto result = tlv_codec_decode(&tlv_bluetooth_ad_codec_tx_power, element.value.data, 1,
                                         &power, sizeof(power));
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE, result);
    EXPECT_STREQ("Invalid codec value", tlv_codec_strerror(result));
    EXPECT_EQ(wire + 2, element.value.data);
    EXPECT_EQ(0x80, element.value.data[0]);
    EXPECT_EQ(1u, element.value.size);
}
#endif
