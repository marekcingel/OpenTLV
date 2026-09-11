#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#include "tlv/reader/walker.h"
#include "tlv/reader/scanner.h"
#include "tlv/codec/structure.h"
#include "tlv/config.h"
#if OPENTLV_FORMAT_BER
#include "tlv/formats/asn1/ber.h"
#include "tlv/copy.h"
#endif
#if OPENTLV_PROFILE_EMV
#include "tlv/profiles/emv.h"
#endif
#include <gtest/gtest.h>
#include <cstring>
#include <vector>

namespace {
// Deliberately different from BER: bit 7 identifies a container.
tlv_result_t tag_read(const void*, const uint8_t* data, size_t size,
                      tlv_tag_t* tag, size_t* used) {
    if (!size) return TLV_ERR_BUFFER_TOO_SHORT;
    *tag = tlv_tag_t{{data[0]}, 1}; *used = 1; return TLV_OK;
}
tlv_result_t tag_write(const void*, uint8_t* data, size_t capacity,
                       const tlv_tag_t* tag, size_t* used) {
    if (tag->size != 1) return TLV_ERR_INVALID_TAG;
    *used = 1;
    if (!data) return TLV_OK;
    if (!capacity) return TLV_ERR_BUFFER_TOO_SHORT;
    data[0] = tag->data[0]; return TLV_OK;
}
tlv_result_t length_read(const void*, const uint8_t* data, size_t size,
                         size_t* length, size_t* used) {
    if (!size) return TLV_ERR_BUFFER_TOO_SHORT;
    *length = data[0]; *used = 1; return TLV_OK;
}
tlv_result_t length_size(const void*, size_t length, size_t* used) {
    if (length > 255) return TLV_ERR_INVALID_LENGTH;
    *used = 1; return TLV_OK;
}
tlv_result_t length_write(const void* ctx, uint8_t* data, size_t capacity,
                          size_t length, size_t* used) {
    if (length_size(ctx, length, used) != TLV_OK) return TLV_ERR_INVALID_LENGTH;
    if (!capacity) return TLV_ERR_BUFFER_TOO_SHORT;
    data[0] = static_cast<uint8_t>(length); return TLV_OK;
}
int constructed(const void*, const tlv_tag_t* tag) { return (tag->data[0] & 0x80) != 0; }
const tlv_reader_format_t format = {nullptr, tag_read, length_read, nullptr};
const tlv_writer_format_t writer_format = {nullptr, tag_write, length_write, length_size};
const tlv_structure_rule_t child_rules[] = {
    {{{{1}, 1}, 1, 1, 0}, 1, 1, TLV_SCHEMA_PRIMITIVE, nullptr},
    {{{{2}, 1}, 1, 1, 0}, 0, 2, TLV_SCHEMA_PRIMITIVE, nullptr}
};
const tlv_structure_schema_t children = {child_rules, 2, 0};
TEST(Unit_Architecture, GenericValueBoundsAndTrailerValidation) {
    struct Bounds { size_t header, value, trailer; tlv_result_t rc; };
    Bounds bounds = {1, 1, 2, TLV_OK};
    tlv_reader_format_t framed = format;
    framed.context = &bounds;
    framed.read_value_bounds = [](const void* ctx, const tlv_tag_t*, const uint8_t*, size_t,
                                  size_t* header, size_t* value, size_t* trailer) {
        const auto& b = *static_cast<const Bounds*>(ctx);
        *header = b.header; *value = b.value; *trailer = b.trailer; return b.rc;
    };
    const uint8_t wire[] = {1, 0xFF, 42, 0xAB, 0xCD};
    tlv_view_t view{}; size_t used = 0;
    ASSERT_EQ(TLV_OK, tlv_read(wire, sizeof(wire), &framed, &view, &used));
    EXPECT_EQ(5u, used); EXPECT_EQ(wire + 2, view.value.data); EXPECT_EQ(1u, view.value.length);
    const Bounds failures[] = {
        {SIZE_MAX, 1, 2, TLV_OK}, {1, SIZE_MAX, 2, TLV_OK},
        {1, 1, SIZE_MAX, TLV_OK}, {1, 1, 3, TLV_OK}, {1, 1, 2, TLV_ERR_LIMIT}
    };
    for (const auto& failure : failures) {
        bounds = failure;
        view = tlv_view_t{tlv_tag_t{{0xEE},1},{nullptr,42}}; used = 999;
        EXPECT_NE(TLV_OK, tlv_read(wire, sizeof(wire), &framed, &view, &used));
        EXPECT_EQ(999u, used); EXPECT_EQ(0xEE, view.tag.data[0]);
        EXPECT_EQ(nullptr, view.value.data); EXPECT_EQ(42u, view.value.length);
    }
    ASSERT_EQ(TLV_OK, tlv_reader_format_init(&framed, nullptr, tag_read, length_read));
    EXPECT_EQ(nullptr, framed.read_value_bounds);
}

TEST(Unit_Architecture, SchemaUnknownPolicyKindsAndInvalidTables) {
    const uint8_t wire[] = {1, 1, 42, 3, 0};
    tlv_structure_schema_t open = children; open.allow_unknown = 1;
    EXPECT_EQ(TLV_OK, tlv_schema_validate(wire, sizeof(wire), &format, constructed, &open, 0, 2, nullptr));
    tlv_structure_rule_t rule = child_rules[0]; rule.kind = TLV_SCHEMA_CONSTRUCTED;
    tlv_structure_schema_t bad = {&rule, 1, 1};
    EXPECT_EQ(TLV_ERR_SCHEMA, tlv_schema_validate(wire, sizeof(wire), &format, constructed, &bad, 0, 2, nullptr));
    rule.kind = TLV_SCHEMA_PRIMITIVE; rule.min_occurs = 2; rule.max_occurs = 1;
    EXPECT_EQ(TLV_ERR_SCHEMA, tlv_schema_validate(wire, sizeof(wire), &format, constructed, &bad, 0, 2, nullptr));
    tlv_structure_rule_t duplicates[] = {child_rules[0], child_rules[0]};
    bad.rules = duplicates; bad.count = 2;
    EXPECT_EQ(TLV_ERR_SCHEMA, tlv_schema_validate(wire, sizeof(wire), &format, constructed, &bad, 0, 2, nullptr));
}

struct object { uint8_t first, second; };
tlv_codec_result_t object_decode(const void*, const tlv_reader_format_t* selected,
                                const uint8_t* data, size_t size, void* value, size_t capacity) {
    if (capacity < sizeof(object)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    tlv_reader_t reader{}; tlv_view_t view{}; object result{};
    if (tlv_reader_init(&reader, data, size, selected) != TLV_OK) return TLV_CODEC_ERR_INVALID_VALUE;
    while (!tlv_reader_at_end(&reader)) {
        if (tlv_reader_next(&reader, &view) != TLV_OK) return TLV_CODEC_ERR_INVALID_VALUE;
        if (view.tag.data[0] == 1) result.first = view.value.data[0];
        else result.second = view.value.data[0];
    }
    std::memcpy(value, &result, sizeof(result)); return TLV_CODEC_OK;
}
tlv_codec_result_t object_encode(const void*, const tlv_writer_format_t* selected,
                                const void* value, size_t size, uint8_t* data,
                                size_t capacity, size_t* written) {
    if (size != sizeof(object)) return TLV_CODEC_ERR_INVALID_VALUE;
    if (!data) { *written = 6; return TLV_CODEC_OK; }
    if (capacity < 6) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    object input{}; std::memcpy(&input, value, sizeof(input));
    tlv_writer_t writer{};
    if (tlv_writer_init(&writer, data, capacity, selected) != TLV_OK ||
        tlv_writer_write(&writer, tlv_tag_t{{1},1}, &input.first, 1) != TLV_OK ||
        tlv_writer_write(&writer, tlv_tag_t{{2},1}, &input.second, 1) != TLV_OK)
        return TLV_CODEC_ERR_INVALID_VALUE;
    *written = tlv_writer_size(&writer); return TLV_CODEC_OK;
}

TEST(Unit_Architecture, StructureCodecValidatesArgumentsDirectionsAndCallbackCounts) {
    tlv_structure_codec_t codec = {nullptr, &format, &writer_format, constructed, nullptr, 0, 2, nullptr, nullptr};
    object value{};
    uint8_t wire[6]{}; size_t used = 99;
    EXPECT_EQ(TLV_CODEC_ERR_UNSUPPORTED, tlv_structure_decode(&codec, nullptr, 0, &value, sizeof(value)));
    EXPECT_EQ(TLV_CODEC_ERR_UNSUPPORTED, tlv_structure_encode(&codec, &value, sizeof(value), wire, sizeof(wire), &used));
    EXPECT_EQ(0u, used);
    EXPECT_EQ(TLV_CODEC_ERR_NULL_ARG, tlv_structure_encode(nullptr, &value, sizeof(value), wire, sizeof(wire), &used));
    EXPECT_EQ(TLV_CODEC_ERR_NULL_ARG, tlv_structure_decode(&codec, nullptr, 1, &value, sizeof(value)));
    codec.max_depth = TLV_WALK_MAX_DEPTH + 1;
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE, tlv_structure_decode(&codec, nullptr, 0, &value, sizeof(value)));
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE, tlv_structure_encode(&codec, &value, sizeof(value), wire, sizeof(wire), &used));
    codec.max_depth = 0;
    codec.encode = [](const void*, const tlv_writer_format_t*, const void*, size_t,
                      uint8_t*, size_t capacity, size_t* count) {
        *count = capacity + 1; return TLV_CODEC_OK;
    };
    EXPECT_EQ(TLV_CODEC_ERR_BUFFER_TOO_SHORT, tlv_structure_encode(&codec, &value, sizeof(value), wire, sizeof(wire), &used));
    EXPECT_EQ(0u, used);
}

TEST(Unit_Architecture, StructureCodecDecodesWithoutWriterAndChecksEncoderFormat) {
    tlv_structure_codec_t codec = {nullptr, &format, nullptr, constructed,
                                   &children, 0, 2, object_decode, object_encode};
    const uint8_t wire[] = {1, 1, 42, 2, 1, 7};
    object value{};
    ASSERT_EQ(TLV_CODEC_OK, tlv_structure_decode(&codec, wire, sizeof(wire), &value, sizeof(value)));
    EXPECT_EQ(42, value.first);
    EXPECT_EQ(7, value.second);
    size_t used = 99;
    EXPECT_EQ(TLV_CODEC_ERR_NULL_ARG,
        tlv_structure_encode(&codec, &value, sizeof(value), nullptr, 0, &used));
    EXPECT_EQ(0u, used);
    for (int missing = 0; missing < 3; ++missing) {
        auto incomplete = writer_format;
        if (missing == 0) incomplete.write_tag = nullptr;
        if (missing == 1) incomplete.write_length = nullptr;
        if (missing == 2) incomplete.length_size = nullptr;
        codec.writer_format = &incomplete;
        EXPECT_EQ(TLV_CODEC_ERR_NULL_ARG,
            tlv_structure_encode(&codec, &value, sizeof(value), nullptr, 0, &used));
        EXPECT_EQ(0u, used);
    }
}

#if OPENTLV_PROFILE_EMV
TEST(Unit_Architecture, EmvDictionaryAndCodecWorkWithoutBuiltinWireFormats) {
    EXPECT_GT(tlv_emv_schema.count, 0u);
    uint64_t input = 123456, output = 0;
    uint8_t bytes[6]{}; size_t written = 0;
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_encode(&tlv_emv_codec_amount, &input, sizeof(input),
                                            bytes, sizeof(bytes), &written));
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_decode(&tlv_emv_codec_amount, bytes, written,
                                            &output, sizeof(output)));
    EXPECT_EQ(input, output);
}
#endif
} // namespace
