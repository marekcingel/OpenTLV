#include "tlv/builtins/bluetooth/manufacturer_data.h"
#include "tlv/builtins/bluetooth/company_ids.h"
#include "tlv/builtins/bluetooth/ad_types.h"
#include "tlv/config.h"
#include <gtest/gtest.h>

#if OPENTLV_BLUETOOTH
#include "tlv/builtins/bluetooth/bluetooth_ltv.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#include <cstring>

TEST(Integration_Tlv_BluetoothManufacturerData, Story349PreservesOpaqueVendorData) {
    const uint8_t wire[27] = {0x1A, 0xFF, 0x4C, 0x00, 0x02, 0x15};
    tlv_element_t element = {};
    size_t        consumed = 0, native = 0;
    ASSERT_EQ(TLV_OK, tlv_read(wire, sizeof(wire), &tlv_format_bluetooth_ltv, &element, &consumed));
    EXPECT_EQ(sizeof(wire), consumed);
    const auto* type = tlv_definition_find(&tlv_bluetooth_ad_types, &element.tag);
    ASSERT_NE(nullptr, type);
    EXPECT_STREQ("Manufacturer Specific Data", type->name);
    ASSERT_EQ(TLV_OK, tlv_size_to_native(element.value.size, &native));
    tlv_bluetooth_manufacturer_data_t value = {};
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_decode(&tlv_bluetooth_codec_manufacturer_data,
                                             element.value.data, native, &value, sizeof(value)));
    EXPECT_EQ(0x004C, value.company_id);
    EXPECT_EQ(wire + 4, value.payload.data);
    EXPECT_EQ(23u, value.payload.size);
    EXPECT_EQ(0x02, value.payload.data[0]);
    EXPECT_EQ(0x15, value.payload.data[1]);
    EXPECT_EQ(element.value.data, value.raw.data);
    EXPECT_EQ(element.value.size, value.raw.size);
    const tlv_tag_t key = {value.raw.data, 2};
    const auto*     company = tlv_definition_find(&tlv_bluetooth_company_ids, &key);
    ASSERT_NE(nullptr, company);
    EXPECT_STREQ("Apple, Inc.", company->name);
    uint8_t encoded_value[25] = {}, output[27] = {};
    size_t  written = 0;
    ASSERT_EQ(TLV_CODEC_OK,
              tlv_codec_encode(&tlv_bluetooth_codec_manufacturer_data, &value, sizeof(value),
                               encoded_value, sizeof(encoded_value), &written));
    ASSERT_EQ(TLV_OK, tlv_write(output, sizeof(output), &tlv_format_bluetooth_ltv, element.tag,
                                encoded_value, written, &written));
    EXPECT_EQ(sizeof(wire), written);
    EXPECT_EQ(0, std::memcmp(wire, output, sizeof(wire)));

    // Framing accepts an incomplete Company Identifier; codec validation is separate.
    const uint8_t short_wire[] = {0x02, 0xFF, 0x4C};
    ASSERT_EQ(TLV_OK, tlv_read(short_wire, sizeof(short_wire), &tlv_format_bluetooth_ltv, &element,
                               &consumed));
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_decode(&tlv_bluetooth_codec_manufacturer_data, element.value.data, 1,
                               &value, sizeof(value)));
    EXPECT_EQ(short_wire + 2, element.value.data);
    EXPECT_EQ(1u, element.value.size);
}
#endif
