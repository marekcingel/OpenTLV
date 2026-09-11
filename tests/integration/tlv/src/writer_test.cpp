#include "tlv/formats/default/default.h"
#include "tlv/formats/fixed/fixed_1byte.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#include <gtest/gtest.h>
#include <cstring>
#include <limits>
#include <vector>

namespace {
const tlv_tag_t tag = {{0xFF}, 1};
}

TEST(Integration_Writer, SizesWireEncodingAndRoundTripsAtLengthBoundaries) {
    for (const auto* format : {&tlv_writer_format_fixed_1byte, &tlv_writer_format_default}) {
        const auto* reader_format = format == &tlv_writer_format_fixed_1byte
            ? &tlv_reader_format_fixed_1byte : &tlv_reader_format_default;
        for (size_t length : {0u, 1u, 127u, 128u, 255u, 256u, 65535u}) {
            if (format == &tlv_writer_format_fixed_1byte && length > 255) continue;
            SCOPED_TRACE(length);
            std::vector<uint8_t> value(length);
            for (size_t i = 0; i < length; ++i) value[i] = static_cast<uint8_t>(i);
            size_t required = 0;
            ASSERT_EQ(TLV_OK, tlv_encoded_size(tag, length, format, &required));
            const size_t length_bytes = format == &tlv_writer_format_fixed_1byte || length < 128
                ? 1 : (length <= 255 ? 2 : 3);
            EXPECT_EQ(1 + length_bytes + length, required);
            std::vector<uint8_t> data(required + 1, 0xEE);
            size_t written = 99;
            ASSERT_EQ(TLV_OK, tlv_write(data.data(), required, format, tag,
                                        length ? value.data() : nullptr, length, &written));
            EXPECT_EQ(required, written);
            EXPECT_EQ(0xEE, data[required]);
            EXPECT_EQ(0xFF, data[0]);
            EXPECT_EQ(length_bytes == 1 ? length : 0x80 + length_bytes - 1, data[1]);
            if (length_bytes == 2) EXPECT_EQ(length, data[2]);
            if (length_bytes == 3) {
                EXPECT_EQ(length >> 8, data[2]);
                EXPECT_EQ(length & 255, data[3]);
            }
            tlv_view_t view{};
            size_t consumed = 0;
            ASSERT_EQ(TLV_OK, tlv_read(data.data(), written, reader_format, &view, &consumed));
            EXPECT_EQ(written, consumed);
            EXPECT_EQ(tag.data[0], view.tag.data[0]);
            EXPECT_EQ(length, view.value.length);
            if (length) EXPECT_EQ(0, std::memcmp(value.data(), view.value.data, length));
        }
    }
}

