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
const tlv_structure_rule_t parent_rules[] = {
    {{{{0x80}, 1}, 0, 255, 0}, 1, 1, TLV_SCHEMA_CONSTRUCTED, &children}
};
const tlv_structure_schema_t schema = {parent_rules, 1, 0};

#if OPENTLV_FORMAT_BER
TEST(Architecture, BerIndefiniteTraversalSchemaRecoveryAndCopies) {
    // Outer indefinite -> definite -> indefinite -> primitive; then siblings.
    const uint8_t wire[] = {0x30, 0x80, 0x30, 7, 0x30, 0x80, 4, 1, 42, 0, 0,
                           4, 0, 0, 0, 4, 0};
    std::vector<size_t> visits;
    auto visitor = [](const tlv_view_t*, size_t depth, size_t pos, void* context) {
        auto& out = *static_cast<std::vector<size_t>*>(context);
        out.push_back(depth); out.push_back(pos); return TLV_VISIT_CONTINUE;
    };
    EXPECT_EQ(TLV_OK, tlv_walk_tree(wire, sizeof(wire), &tlv_reader_format_ber,
        tlv_ber_is_constructed, 3, 6, visitor, &visits, nullptr));
    EXPECT_EQ((std::vector<size_t>{0,0,1,2,2,4,3,6,1,11,0,15}), visits);
    tlv_structure_schema_t recursive{};
    const tlv_structure_rule_t rules[] = {
        {{{{0x30},1},0,100,0},0,1,TLV_SCHEMA_CONSTRUCTED,&recursive},
        {{{{4},1},0,1,0},0,1,TLV_SCHEMA_PRIMITIVE,nullptr}
    };
    recursive = tlv_structure_schema_t{rules, 2, 0};
    EXPECT_EQ(TLV_OK, tlv_schema_validate(wire, sizeof(wire), &tlv_reader_format_ber,
        tlv_ber_is_constructed, &recursive, 3, 6, nullptr));
    size_t offset = 999;
    EXPECT_EQ(TLV_ERR_LIMIT, tlv_walk_tree(wire, sizeof(wire), &tlv_reader_format_ber,
        tlv_ber_is_constructed, 2, 6, nullptr, nullptr, &offset));
    EXPECT_EQ(6u, offset);
    tlv_view_t view{}; size_t used = 0;
    ASSERT_EQ(TLV_OK, tlv_scan(wire, sizeof(wire), 0, &tlv_reader_format_ber,
        nullptr, &view, &offset, &used));
    EXPECT_EQ(0u, offset); EXPECT_EQ(15u, used); EXPECT_EQ(11u, view.value.length);
    uint8_t copied[sizeof(wire)]; size_t written = 0;
    ASSERT_EQ(TLV_OK, tlv_copy_view(&view, &tlv_writer_format_ber, copied, sizeof(copied), &written));
    EXPECT_EQ(13u, written); EXPECT_EQ(11, copied[1]);
    EXPECT_EQ(0, std::memcmp(wire + 2, copied + 2, 11));
    EXPECT_EQ(TLV_OK, tlv_walk_tree(copied, written, &tlv_reader_format_ber,
        tlv_ber_is_constructed, 3, 5, nullptr, nullptr, nullptr));
    ASSERT_EQ(TLV_OK, tlv_copy_encoded(tlv_buffer_t{wire, used}, copied, sizeof(copied), &written));
    EXPECT_EQ(15u, written); EXPECT_EQ(0, std::memcmp(wire, copied, written));
    // An empty indefinite scope still enforces required children.
    const uint8_t empty[] = {0x30, 0x80, 0, 0};
    const tlv_structure_rule_t required = {{{{4},1},0,1,0},1,1,TLV_SCHEMA_PRIMITIVE,nullptr};
    const tlv_structure_schema_t child = {&required, 1, 0};
    const tlv_structure_rule_t parent = {{{{0x30},1},0,100,0},1,1,TLV_SCHEMA_CONSTRUCTED,&child};
    const tlv_structure_schema_t root = {&parent, 1, 0};
    EXPECT_EQ(TLV_ERR_SCHEMA, tlv_schema_validate(empty, sizeof(empty), &tlv_reader_format_ber,
        tlv_ber_is_constructed, &root, 0, 1, &offset));
    EXPECT_EQ(2u, offset);
}
#endif

TEST(Architecture, GenericValueBoundsAndTrailerValidation) {
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

TEST(Architecture, GenericVisitorUsesFormatNestingAndAbsoluteOffsets) {
    const uint8_t wire[] = {0x80, 5, 1, 1, 42, 0x81, 0, 2, 0};
    std::vector<size_t> visits;
    size_t offset = 999;
    auto visitor = [](const tlv_view_t*, size_t depth, size_t pos, void* ctx) {
        auto& out = *static_cast<std::vector<size_t>*>(ctx);
        out.push_back(depth); out.push_back(pos); return TLV_VISIT_CONTINUE;
    };
    EXPECT_EQ(TLV_OK, tlv_walk_tree(wire, sizeof(wire), &format, constructed, 1, 4,
                                   visitor, &visits, &offset));
    EXPECT_EQ((std::vector<size_t>{0,0,1,2,1,5,0,7}), visits);
    EXPECT_EQ(999u, offset);
    EXPECT_EQ(TLV_ERR_LIMIT, tlv_walk_tree(wire, sizeof(wire), &format, constructed, 0, 4,
                                          nullptr, nullptr, &offset));
    EXPECT_EQ(2u, offset);
    EXPECT_EQ(TLV_ERR_LIMIT, tlv_walk_tree(wire, sizeof(wire), &format, constructed, 1, 3,
                                          nullptr, nullptr, &offset));
    EXPECT_EQ(7u, offset);
    tlv_reader_format_t opaque = format;
    EXPECT_EQ(TLV_OK, tlv_walk_tree(wire, sizeof(wire), &opaque, nullptr, 0, 2,
                                   nullptr, nullptr, nullptr));
}

TEST(Architecture, TreeRejectsTruncatedChildrenAndSupportsEarlyStop) {
    const uint8_t wire[] = {0x80, 2, 1, 9, 2, 0};
    size_t offset = 99;
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_walk_tree(wire, sizeof(wire), &format, constructed,
        2, 10, nullptr, nullptr, &offset));
    EXPECT_EQ(2u, offset);
    auto stop = [](const tlv_view_t*, size_t, size_t, void*) { return TLV_VISIT_STOP; };
    EXPECT_EQ(TLV_OK, tlv_walk_tree(wire, sizeof(wire), &format, constructed, 2, 10, stop, nullptr, nullptr));
    auto fail = [](const tlv_view_t*, size_t, size_t, void*) { return TLV_VISIT_ERROR; };
    EXPECT_EQ(TLV_ERR_VISITOR, tlv_walk_tree(wire, sizeof(wire), &format, constructed, 2, 10, fail, nullptr, nullptr));
    EXPECT_EQ(TLV_OK, tlv_walk_tree(nullptr, 0, &format, constructed, 0, 0, nullptr, nullptr, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_walk_tree(nullptr, 1, &format, constructed, 0, 0, nullptr, nullptr, nullptr));
    EXPECT_EQ(TLV_ERR_LIMIT, tlv_walk_tree(nullptr, 0, &format, constructed, TLV_WALK_MAX_DEPTH+1,
                                         0, nullptr, nullptr, nullptr));
}

TEST(Architecture, SchemaChecksRequiredRepeatedAndNestedMembership) {
    const uint8_t good[] = {0x80, 9, 1, 1, 42, 2, 1, 7, 2, 1, 8};
    EXPECT_EQ(TLV_OK, tlv_schema_validate(good, sizeof(good), &format, constructed, &schema, 1, 4, nullptr));
    const uint8_t empty[] = {0x80, 0};
    size_t offset = 99;
    EXPECT_EQ(TLV_ERR_SCHEMA, tlv_schema_validate(empty, sizeof(empty), &format, constructed, &schema, 0, 1, &offset));
    EXPECT_EQ(2u, offset);
    const uint8_t duplicate[] = {0x80, 6, 1, 1, 42, 1, 1, 7};
    EXPECT_EQ(TLV_ERR_SCHEMA, tlv_schema_validate(duplicate, sizeof(duplicate), &format, constructed, &schema, 1, 3, &offset));
    EXPECT_EQ(5u, offset);
    const uint8_t unknown[] = {0x80, 6, 1, 1, 42, 3, 1, 7};
    EXPECT_EQ(TLV_ERR_SCHEMA, tlv_schema_validate(unknown, sizeof(unknown), &format, constructed, &schema, 1, 3, &offset));
    EXPECT_EQ(5u, offset);
    const uint8_t bad_length[] = {0x80, 2, 1, 0};
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_schema_validate(bad_length, sizeof(bad_length), &format, constructed, &schema, 1, 2, nullptr));
    EXPECT_EQ(TLV_ERR_SCHEMA, tlv_schema_validate(nullptr, 0, &format, constructed, &schema, 0, 0, nullptr));
}

TEST(Architecture, SchemaUnknownPolicyKindsAndInvalidTables) {
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

TEST(Architecture, MaximumDepthAndEmptyChildSchemaUseTheSameBoundary) {
    std::vector<uint8_t> wire;
    for (size_t i = 0; i <= TLV_WALK_MAX_DEPTH; ++i) {
        wire.push_back(0x80);
        wire.push_back(static_cast<uint8_t>(2 * (TLV_WALK_MAX_DEPTH - i)));
    }
    tlv_structure_schema_t recursive{};
    tlv_structure_rule_t rule = {{{{0x80},1},0,255,0},0,1,TLV_SCHEMA_CONSTRUCTED,&recursive};
    recursive.rules = &rule; recursive.count = 1;
    EXPECT_EQ(TLV_OK, tlv_schema_validate(wire.data(), wire.size(), &format, constructed, &recursive,
                                          TLV_WALK_MAX_DEPTH, TLV_WALK_MAX_DEPTH+1, nullptr));
    size_t offset = 0;
    EXPECT_EQ(TLV_ERR_LIMIT, tlv_schema_validate(wire.data(), wire.size(), &format, constructed, &recursive,
        TLV_WALK_MAX_DEPTH-1, TLV_WALK_MAX_DEPTH+1, &offset));
    EXPECT_EQ(2u * TLV_WALK_MAX_DEPTH, offset);
    rule.min_occurs = 1;
    EXPECT_EQ(TLV_ERR_SCHEMA, tlv_schema_validate(wire.data(), wire.size(), &format, constructed, &recursive,
        TLV_WALK_MAX_DEPTH, TLV_WALK_MAX_DEPTH+1, &offset));
    EXPECT_EQ(wire.size(), offset);
}

TEST(Architecture, RecoveryAndSequentialTraversalRemainDistinct) {
    const uint8_t noisy[] = {0x33, 0xff, 1, 1, 42};
    tlv_schema_entry_t entry = child_rules[0].entry;
    tlv_schema_t recovery = {&entry, 1};
    tlv_view_t view{}; size_t offset = 0, used = 0;
    EXPECT_EQ(TLV_OK, tlv_scan(noisy, sizeof(noisy), 0, &format, &recovery, &view, &offset, &used));
    EXPECT_EQ(2u, offset); EXPECT_EQ(3u, used); EXPECT_EQ(42, view.value.data[0]);
    auto visit = [](const tlv_view_t*, void*) { return TLV_VISIT_CONTINUE; };
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_walk(noisy, sizeof(noisy), &format, visit, nullptr));
    EXPECT_EQ(TLV_OK, tlv_walk(noisy + offset, used, &format, visit, nullptr));
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

TEST(Architecture, WholeObjectCodecRoundtripAndValidationBeforeMapping) {
    const tlv_structure_codec_t codec = {nullptr, &format, &writer_format, constructed, &children, 0, 2, object_decode, object_encode};
    object value = {42, 7}, result = {99, 99};
    uint8_t wire[6]{}; size_t used = 0;
    EXPECT_EQ(TLV_CODEC_OK, tlv_structure_encode(&codec, &value, sizeof(value), nullptr, 0, &used));
    EXPECT_EQ(6u, used);
    EXPECT_EQ(TLV_CODEC_ERR_BUFFER_TOO_SHORT, tlv_structure_encode(&codec, &value, sizeof(value), wire, 5, &used));
    EXPECT_EQ(0u, used);
    EXPECT_EQ(TLV_CODEC_OK, tlv_structure_encode(&codec, &value, sizeof(value), wire, sizeof(wire), &used));
    EXPECT_EQ(TLV_CODEC_OK, tlv_structure_decode(&codec, wire, used, &result, sizeof(result)));
    EXPECT_EQ(42, result.first); EXPECT_EQ(7, result.second);
    wire[3] = 1; result.first = 99;
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_STRUCTURE, tlv_structure_decode(&codec, wire, used, &result, sizeof(result)));
    EXPECT_EQ(99, result.first);
    tlv_structure_codec_t bad = codec; bad.schema = &schema;
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_STRUCTURE, tlv_structure_encode(&bad, &value, sizeof(value), wire, sizeof(wire), &used));
    EXPECT_EQ(0u, used);
}

TEST(Architecture, StructureCodecValidatesArgumentsDirectionsAndCallbackCounts) {
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

TEST(Architecture, StructureCodecDecodesWithoutWriterAndChecksEncoderFormat) {
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
TEST(Architecture, EmvDictionaryAndCodecWorkWithoutBuiltinWireFormats) {
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
