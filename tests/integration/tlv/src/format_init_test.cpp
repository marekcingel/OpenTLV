#include "tlv/formats/format.h"
#include "tlv/config.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#include <gtest/gtest.h>
#include <cstring>
#include <type_traits>
#if OPENTLV_FORMAT_DEFAULT
#include "tlv/formats/default/default.h"
#include <vector>
#endif

#if OPENTLV_FORMAT_DEFAULT
TEST(Integration_FormatDefault, IndependentReferenceInputsAndOutputs) {
    struct reference { size_t length; std::vector<uint8_t> header; };
    const reference cases[] = {
        {0, {0x9F, 0}}, {127, {0x9F, 0x7F}}, {128, {0x9F, 0x81, 0x80}},
        {255, {0x9F, 0x81, 0xFF}}, {256, {0x9F, 0x82, 1, 0}},
        {65535, {0x9F, 0x82, 0xFF, 0xFF}}
    };
    for (const auto& item : cases) {
        SCOPED_TRACE(item.length);
        auto wire = item.header;
        wire.resize(wire.size() + item.length, 0xAB);
        tlv_view_t view{};
        size_t consumed = 0;
        ASSERT_EQ(TLV_OK, tlv_read(wire.data(), wire.size(), &tlv_reader_format_default,
                                   &view, &consumed));
        EXPECT_EQ(wire.size(), consumed);
        EXPECT_EQ(1, view.tag.size); // 9F is a single raw tag, not BER high-tag form.
        EXPECT_EQ(0x9F, view.tag.data[0]);
        EXPECT_EQ(item.length, view.value.length);
        EXPECT_EQ(wire.data() + item.header.size(), view.value.data);

        std::vector<uint8_t> output(wire.size());
        std::vector<uint8_t> value(item.length, 0xAB);
        size_t written = 0;
        ASSERT_EQ(TLV_OK, tlv_write(output.data(), output.size(), &tlv_writer_format_default,
            tlv_tag_t{{0x9F}, 1}, value.data(), value.size(), &written));
        EXPECT_EQ(wire.size(), written);
        EXPECT_EQ(wire, output);
    }
    size_t size = 123;
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_writer_format_default.length_size(nullptr, 65536, &size));
    const uint8_t too_large[] = {0x9F, 0x83, 1, 0, 0};
    tlv_view_t view{};
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_read(too_large, sizeof(too_large),
        &tlv_reader_format_default, &view, &size));
}
#endif
