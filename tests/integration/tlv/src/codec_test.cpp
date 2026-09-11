#include "tlv/formats/fixed/fixed_1byte.h"
#include <gtest/gtest.h>
#include "tlv/codec/codec.h"
#include "tlv/endian.h"
#include "tlv/types.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"

namespace {
tlv_codec_result_t decode_u16(const void* context, const uint8_t* data,
                             size_t size, void* value, size_t capacity) {
    if (size != 2) return TLV_CODEC_ERR_INVALID_VALUE;
    if (capacity < sizeof(uint16_t)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    *static_cast<uint16_t*>(value) = *static_cast<const bool*>(context)
        ? tlv_read_u16_be(data) : tlv_read_u16_le(data);
    return TLV_CODEC_OK;
}
tlv_codec_result_t encode_u16(const void* context, const void* value,
                             size_t size, uint8_t* data, size_t capacity,
                             size_t* written) {
    if (size != sizeof(uint16_t)) return TLV_CODEC_ERR_INVALID_VALUE;
    if (data) {
        if (capacity < 2) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
        if (*static_cast<const bool*>(context))
            tlv_write_u16_be(data, *static_cast<const uint16_t*>(value));
        else tlv_write_u16_le(data, *static_cast<const uint16_t*>(value));
    }
    *written = 2;
    return TLV_CODEC_OK;
}
const bool big_endian = true;
const tlv_codec_t scalar = {&big_endian, decode_u16, encode_u16};


}

TEST(Integration_Codec, ExplicitConversionBetweenFramingOperations) {
    uint16_t value = 0x1234, decoded = 0;
    uint8_t raw[2], framed[4];
    size_t raw_size = 0, framed_size = 0, consumed = 0;
    tlv_tag_t tag = {};
    tag.size = 1;
    tag.data[0] = 1;
    ASSERT_EQ(tlv_codec_encode(&scalar, &value, sizeof(value), raw, sizeof(raw), &raw_size), TLV_CODEC_OK);
    ASSERT_EQ(tlv_write(framed, sizeof(framed), &tlv_writer_format_fixed_1byte,
                        tag, raw, raw_size, &framed_size), TLV_OK);
    tlv_view_t view = {};
    ASSERT_EQ(tlv_read(framed, framed_size, &tlv_reader_format_fixed_1byte, &view, &consumed), TLV_OK);
    EXPECT_EQ(consumed, framed_size);
    EXPECT_EQ(view.value.data, framed + 2);
    ASSERT_EQ(tlv_codec_decode(&scalar, view.value.data, view.value.length,
                               &decoded, sizeof(decoded)), TLV_CODEC_OK);
    EXPECT_EQ(decoded, value);
    // Framing also accepts values that this codec rejects.
    framed[1] = 1;
    ASSERT_EQ(tlv_read(framed, 3, &tlv_reader_format_fixed_1byte, &view, &consumed), TLV_OK);
    EXPECT_EQ(tlv_codec_decode(&scalar, view.value.data, view.value.length,
                               &decoded, sizeof(decoded)), TLV_CODEC_ERR_INVALID_VALUE);
}

