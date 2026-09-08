// Keep this translation unit separate: low-level headers must not import codecs.
#include "tlv++/reader.hpp"
#include "tlv++/writer.hpp"
#include "tlv++/walker.hpp"
#include "tlv++/schema.hpp"
#if defined(OPENTLV_TLVPP_CODEC_HPP) || defined(OPENTLV_CODEC_H)
#error Low-level APIs must not depend on the codec layer
#endif
#include "tlv/formats/default.h"
#include "tlv++/structure.hpp"
#include <gtest/gtest.h>

TEST(TLV_CPP, LayeredTraversalAndSchema) {
    const uint8_t data[] = {1, 1, 42, 2, 0};
    tlv::bytes bytes(reinterpret_cast<const tlv::byte*>(data), sizeof(data));
    size_t visits = 0;
    auto result = tlv::walk_tree(bytes, tlv_format_default, 0, 2,
        [&visits](const tlv::entry& item, size_t depth, size_t offset) {
            EXPECT_EQ(0u, depth);
            EXPECT_EQ(visits ? 3u : 0u, offset);
            EXPECT_EQ(visits ? 2 : 1, item.tag.data[0]);
            ++visits; return TLV_VISIT_CONTINUE;
        });
    ASSERT_TRUE(result); EXPECT_EQ(2u, visits);
    const tlv_structure_rule_t rule = {{{{1},1},1,1,0},1,1,TLV_SCHEMA_PRIMITIVE,nullptr};
    const tlv_structure_schema_t schema = {&rule, 1, 1};
    EXPECT_TRUE(tlv::validate(bytes, tlv_format_default, schema, 0, 2));
}

namespace {
struct pair_value { uint8_t first, second; };
tlv_codec_result_t decode_pair(const void*, const tlv_format_t* format,
                               const uint8_t* data, size_t size, void* out, size_t capacity) {
    if (capacity < sizeof(pair_value)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    tlv_view_t a{}, b{}; size_t used = 0, second_used = 0;
    if (tlv_read(data, size, format, &a, &used) != TLV_OK ||
        tlv_read(data + used, size - used, format, &b, &second_used) != TLV_OK ||
        a.value.length != 1 || b.value.length != 1 || a.tag.data[0] != 1 ||
        b.tag.data[0] != 2 || used + second_used != size)
        return TLV_CODEC_ERR_INVALID_VALUE;
    *static_cast<pair_value*>(out) = pair_value{a.value.data[0], b.value.data[0]};
    return TLV_CODEC_OK;
}
tlv_codec_result_t encode_pair(const void*, const tlv_format_t* format,
                               const void* value, size_t size, uint8_t* data,
                               size_t capacity, size_t* written) {
    if (size != sizeof(pair_value)) return TLV_CODEC_ERR_INVALID_VALUE;
    const auto& pair = *static_cast<const pair_value*>(value);
    if (!data) { *written = 6; return TLV_CODEC_OK; }
    size_t first = 0, second = 0;
    if (tlv_write(data, capacity, format, tlv_tag_t{{1},1}, &pair.first, 1, &first) != TLV_OK ||
        tlv_write(data + first, capacity - first, format, tlv_tag_t{{2},1}, &pair.second, 1, &second) != TLV_OK)
        return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    *written = first + second; return TLV_CODEC_OK;
}
}

TEST(TLV_CPP, StructureCodecUsesCallerOwnedStorage) {
    const tlv_structure_codec_t codec = {nullptr, &tlv_format_default, nullptr, 0, 2, decode_pair, encode_pair};
    const pair_value value{42, 7};
    tlv::byte data[6]{};
    auto size = tlv::encode_structure(codec, value, nullptr, 0);
    ASSERT_TRUE(size); EXPECT_EQ(6u, *size);
    auto written = tlv::encode_structure(codec, value, data, sizeof(data));
    ASSERT_TRUE(written);
    auto result = tlv::decode_structure<pair_value>(codec, tlv::bytes(data, *written));
    ASSERT_TRUE(result); EXPECT_EQ(42, result->first); EXPECT_EQ(7, result->second);
    auto failed = tlv::decode_structure<pair_value>(codec, tlv::bytes(data, *written - 1));
    ASSERT_FALSE(failed); EXPECT_EQ(TLV_CODEC_ERR_INVALID_STRUCTURE, failed.error());
}
