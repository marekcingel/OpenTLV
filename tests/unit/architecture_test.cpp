// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/formats/compose.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#include "tlv/reader/visitor.h"
#include "tlv/codec/structure.h"
#include "tlv/config.h"
#if OPENTLV_FORMAT_BER
#include "tlv/builtins/asn1/ber.h"
#include "tlv/copy.h"
#endif
#if OPENTLV_EMV
#include "tlv/builtins/emv/emv.h"
#endif
#include <gtest/gtest.h>
#include <cstring>
#include <vector>

namespace {
// Deliberately different from BER: bit 7 identifies a container.
tlv_result_t tag_read(const void*, const uint8_t* data, size_t size, tlv_tag_t* tag, size_t* used) {
    if (!size) return TLV_ERR_BUFFER_TOO_SHORT;
    *tag = tlv_tag(data, 1);
    *used = 1;
    return TLV_OK;
}
tlv_result_t tag_write(const void*, uint8_t* data, size_t capacity, const tlv_tag_t* tag,
                       size_t* used) {
    if (tag->size != 1) return TLV_ERR_INVALID_TAG_SIZE;
    *used = 1;
    if (!data) return TLV_OK;
    if (!capacity) return TLV_ERR_BUFFER_TOO_SHORT;
    data[0] = tag->data[0];
    return TLV_OK;
}
tlv_result_t length_read(const void*, const uint8_t* data, size_t size, tlv_size_t* length,
                         size_t* used) {
    if (!size) return TLV_ERR_BUFFER_TOO_SHORT;
    *length = data[0];
    *used = 1;
    return TLV_OK;
}
tlv_result_t length_size(const void*, tlv_size_t length, size_t* used) {
    if (length > 255) return TLV_ERR_INVALID_LENGTH;
    *used = 1;
    return TLV_OK;
}
tlv_result_t length_write(const void* ctx, uint8_t* data, size_t capacity, tlv_size_t length,
                          size_t* used) {
    if (length_size(ctx, length, used) != TLV_OK) return TLV_ERR_INVALID_LENGTH;
    if (!capacity) return TLV_ERR_BUFFER_TOO_SHORT;
    data[0] = static_cast<uint8_t>(length);
    return TLV_OK;
}
int constructed(const void*, const tlv_tag_t* tag) {
    return (tag->data[0] & 0x80) != 0;
}
const tlv_field_composition_t format_layout = {nullptr,
                                               tag_read,
                                               length_read,
                                               nullptr,
                                               nullptr,
                                               nullptr,
                                               nullptr,
                                               TLV_ELEMENT_ORDER_TLV,
                                               TLV_LENGTH_SCOPE_VALUE};
const tlv_format_t format = {&format_layout, tlv_fields_decode, nullptr, nullptr, nullptr};
const tlv_field_composition_t full_format_layout = {nullptr,
                                                    tag_read,
                                                    length_read,
                                                    nullptr,
                                                    tag_write,
                                                    length_write,
                                                    length_size,
                                                    TLV_ELEMENT_ORDER_TLV,
                                                    TLV_LENGTH_SCOPE_VALUE};
const tlv_format_t full_format = {&full_format_layout, tlv_fields_decode, tlv_fields_measure,
                                  tlv_fields_encode, nullptr};
const tlv_field_composition_t constructed_format_layout = {nullptr,
                                                           tag_read,
                                                           length_read,
                                                           nullptr,
                                                           nullptr,
                                                           nullptr,
                                                           nullptr,
                                                           TLV_ELEMENT_ORDER_TLV,
                                                           TLV_LENGTH_SCOPE_VALUE};
const tlv_format_t constructed_format = {&constructed_format_layout, tlv_fields_decode, nullptr,
                                         nullptr, constructed};
const tlv_field_composition_t constructed_full_format_layout = {nullptr,
                                                                tag_read,
                                                                length_read,
                                                                nullptr,
                                                                tag_write,
                                                                length_write,
                                                                length_size,
                                                                TLV_ELEMENT_ORDER_TLV,
                                                                TLV_LENGTH_SCOPE_VALUE};
const tlv_format_t constructed_full_format = {&constructed_full_format_layout, tlv_fields_decode,
                                              tlv_fields_measure, tlv_fields_encode, constructed};
const tlv_schema_entry_t   child_rules_fields[] = {{TLV_TAG(1), 1, 1, 0, nullptr, 0},
                                                   {TLV_TAG(2), 1, 1, 0, nullptr, 0}};
const tlv_structure_rule_t child_rules[] = {
    {&child_rules_fields[0], 1, 1, TLV_SCHEMA_PRIMITIVE, nullptr, 0},
    {&child_rules_fields[1], 0, 2, TLV_SCHEMA_PRIMITIVE, nullptr, 0}};
const tlv_structure_schema_t children = {child_rules, 2, 0, nullptr, 0, TLV_SCHEMA_ORDER_ANY};
TEST(Unit_Tlv_Architecture, GenericValueBoundsAndTrailerValidation) {
    struct Bounds {
        size_t       header, value, trailer;
        tlv_result_t rc;
    };
    Bounds                  bounds = {1, 1, 2, TLV_OK};
    tlv_format_t            framed = format;
    tlv_field_composition_t layout = format_layout;
    layout.context = &bounds;
    framed.context = &layout;
    layout.resolve = [](const void* ctx, const tlv_tag_t*, const uint8_t*, size_t, size_t* header,
                        tlv_size_t* value, size_t* trailer, tlv_format_error_t*) {
        const auto& b = *static_cast<const Bounds*>(ctx);
        *header = b.header;
        *value = b.value;
        *trailer = b.trailer;
        return b.rc;
    };
    const uint8_t wire[] = {1, 0xFF, 42, 0xAB, 0xCD};
    tlv_element_t element{};
    size_t        used = 0;
    ASSERT_EQ(TLV_OK, tlv_read(wire, sizeof(wire), &framed, &element, &used));
    EXPECT_EQ(5u, used);
    EXPECT_EQ(wire + 2, element.value.data);
    EXPECT_EQ(1u, element.value.size);
    const Bounds failures[] = {{SIZE_MAX, 1, 2, TLV_OK},
                               {1, SIZE_MAX, 2, TLV_OK},
                               {1, 1, SIZE_MAX, TLV_OK},
                               {1, 1, 3, TLV_OK},
                               {1, 1, 2, TLV_ERR_LIMIT}};
    for (const auto& failure : failures) {
        bounds = failure;
        element = tlv_element_t{TLV_TAG(0xEE), {nullptr, 42}};
        used = 999;
        EXPECT_NE(TLV_OK, tlv_read(wire, sizeof(wire), &framed, &element, &used));
        EXPECT_EQ(999u, used);
        EXPECT_EQ(0xEE, element.tag.data[0]);
        EXPECT_EQ(nullptr, element.value.data);
        EXPECT_EQ(42u, element.value.size);
    }
    ASSERT_EQ(TLV_OK, tlv_fields_format_init(&framed, &format_layout));
    EXPECT_EQ(&format_layout, framed.context);
}

TEST(Unit_Tlv_Architecture, SchemaUnknownPolicyKindsAndInvalidTables) {
    const uint8_t          wire[] = {1, 1, 42, 3, 0};
    tlv_structure_schema_t open = children;
    open.allow_unknown = 1;
    EXPECT_EQ(TLV_OK,
              tlv_schema_validate(wire, sizeof(wire), &constructed_format, &open, 0, 2, nullptr));
    tlv_structure_rule_t rule = child_rules[0];
    rule.kind = TLV_SCHEMA_CONSTRUCTED;
    tlv_structure_schema_t bad = {&rule, 1, 1, nullptr, 0, TLV_SCHEMA_ORDER_ANY};
    EXPECT_EQ(TLV_ERR_SCHEMA,
              tlv_schema_validate(wire, sizeof(wire), &constructed_format, &bad, 0, 2, nullptr));
    rule.kind = TLV_SCHEMA_PRIMITIVE;
    rule.min_occurs = 2;
    rule.max_occurs = 1;
    EXPECT_EQ(TLV_ERR_SCHEMA,
              tlv_schema_validate(wire, sizeof(wire), &constructed_format, &bad, 0, 2, nullptr));
    tlv_structure_rule_t duplicates[] = {child_rules[0], child_rules[0]};
    bad.rules = duplicates;
    bad.count = 2;
    EXPECT_EQ(TLV_ERR_SCHEMA,
              tlv_schema_validate(wire, sizeof(wire), &constructed_format, &bad, 0, 2, nullptr));
}

TEST(Unit_Tlv_Architecture, SchemaGroupTableValidity) {
    const uint8_t wire[] = {1, 1, 42, 3, 0};
    // A rule referencing a group id absent from the schema's groups table is invalid.
    tlv_structure_rule_t grouped = child_rules[1];
    grouped.group = 1;
    tlv_structure_schema_t dangling_group = {&grouped, 1, 1, nullptr, 0, TLV_SCHEMA_ORDER_ANY};
    EXPECT_EQ(TLV_ERR_SCHEMA, tlv_schema_validate(wire, sizeof(wire), &constructed_format,
                                                  &dangling_group, 0, 2, nullptr));

    // A grouped rule's own min_occurs must be 0; requiredness belongs to the group.
    const tlv_structure_group_t groups[] = {{1, 0, 1, nullptr}};
    tlv_structure_rule_t        required_member = grouped;
    required_member.min_occurs = 1;
    tlv_structure_schema_t bad_member = {&required_member, 1, 1, groups, 1, TLV_SCHEMA_ORDER_ANY};
    EXPECT_EQ(TLV_ERR_SCHEMA, tlv_schema_validate(wire, sizeof(wire), &constructed_format,
                                                  &bad_member, 0, 2, nullptr));

    // A group with no member rule can never be satisfied and is rejected outright.
    const tlv_structure_group_t orphan_groups[] = {{2, 0, 1, nullptr}};
    tlv_structure_schema_t orphan = {child_rules, 2, 0, orphan_groups, 1, TLV_SCHEMA_ORDER_ANY};
    EXPECT_EQ(TLV_ERR_SCHEMA,
              tlv_schema_validate(wire, sizeof(wire), &constructed_format, &orphan, 0, 2, nullptr));

    // An out-of-range order value is likewise an invalid table.
    tlv_structure_schema_t bad_order = children;
    bad_order.order = static_cast<tlv_schema_order_t>(2);
    EXPECT_EQ(TLV_ERR_SCHEMA, tlv_schema_validate(wire, sizeof(wire), &constructed_format,
                                                  &bad_order, 0, 2, nullptr));
}

struct object {
    uint8_t first, second;
};
tlv_codec_result_t object_decode(const void*, const tlv_format_t* selected, const uint8_t* data,
                                 size_t size, void* value, size_t capacity) {
    if (capacity < sizeof(object)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    tlv_reader_t  reader{};
    tlv_element_t element{};
    object        result{};
    if (tlv_reader_init(&reader, data, size, selected) != TLV_OK)
        return TLV_CODEC_ERR_INVALID_VALUE;
    while (!tlv_reader_at_end(&reader)) {
        if (tlv_reader_next(&reader, &element) != TLV_OK) return TLV_CODEC_ERR_INVALID_VALUE;
        if (element.tag.data[0] == 1)
            result.first = element.value.data[0];
        else
            result.second = element.value.data[0];
    }
    std::memcpy(value, &result, sizeof(result));
    return TLV_CODEC_OK;
}
tlv_codec_result_t object_encode(const void*, const tlv_format_t* selected, const void* value,
                                 size_t size, uint8_t* data, size_t capacity, size_t* written) {
    if (size != sizeof(object)) return TLV_CODEC_ERR_INVALID_VALUE;
    if (!data) {
        *written = 6;
        return TLV_CODEC_OK;
    }
    if (capacity < 6) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    object input{};
    std::memcpy(&input, value, sizeof(input));
    tlv_writer_t writer{};
    if (tlv_writer_init(&writer, data, capacity, selected) != TLV_OK ||
        tlv_writer_write(&writer, TLV_TAG(1), &input.first, 1) != TLV_OK ||
        tlv_writer_write(&writer, TLV_TAG(2), &input.second, 1) != TLV_OK)
        return TLV_CODEC_ERR_INVALID_VALUE;
    *written = tlv_writer_size(&writer);
    return TLV_CODEC_OK;
}

TEST(Unit_Tlv_Architecture, StructureCodecValidatesArgumentsDirectionsAndCallbackCounts) {
    tlv_structure_codec_t codec = {nullptr, &constructed_full_format, nullptr, 0, 2, nullptr,
                                   nullptr};
    object                value{};
    uint8_t               wire[6]{};
    size_t                used = 99;
    EXPECT_EQ(TLV_CODEC_ERR_UNSUPPORTED,
              tlv_structure_decode(&codec, nullptr, 0, &value, sizeof(value)));
    EXPECT_EQ(TLV_CODEC_ERR_UNSUPPORTED,
              tlv_structure_encode(&codec, &value, sizeof(value), wire, sizeof(wire), &used));
    EXPECT_EQ(0u, used);
    EXPECT_EQ(TLV_CODEC_ERR_NULL_ARG,
              tlv_structure_encode(nullptr, &value, sizeof(value), wire, sizeof(wire), &used));
    EXPECT_EQ(TLV_CODEC_ERR_NULL_ARG,
              tlv_structure_decode(&codec, nullptr, 1, &value, sizeof(value)));
    codec.max_depth = TLV_TREE_DEFAULT_DEPTH + 1;
    EXPECT_EQ(TLV_CODEC_ERR_UNSUPPORTED,
              tlv_structure_decode(&codec, nullptr, 0, &value, sizeof(value)));
    EXPECT_EQ(TLV_CODEC_ERR_UNSUPPORTED,
              tlv_structure_encode(&codec, &value, sizeof(value), wire, sizeof(wire), &used));
    codec.max_depth = 0;
    codec.encode = [](const void*, const tlv_format_t*, const void*, size_t, uint8_t*,
                      size_t capacity, size_t* count) {
        *count = capacity + 1;
        return TLV_CODEC_OK;
    };
    EXPECT_EQ(TLV_CODEC_ERR_BUFFER_TOO_SHORT,
              tlv_structure_encode(&codec, &value, sizeof(value), wire, sizeof(wire), &used));
    EXPECT_EQ(0u, used);
}

TEST(Unit_Tlv_Architecture, StructureCodecDecodesWithoutWriterAndChecksEncoderFormat) {
    // `constructed_format` can only read, so this codec is decode-only, as
    // tlv_structure_codec_t's documentation describes for a format with unset write callbacks.
    tlv_structure_codec_t codec = {nullptr, &constructed_format, &children,    0,
                                   2,       object_decode,       object_encode};
    const uint8_t         wire[] = {1, 1, 42, 2, 1, 7};
    object                value{};
    ASSERT_EQ(TLV_CODEC_OK,
              tlv_structure_decode(&codec, wire, sizeof(wire), &value, sizeof(value)));
    EXPECT_EQ(42, value.first);
    EXPECT_EQ(7, value.second);
    size_t used = 99;
    EXPECT_EQ(TLV_CODEC_ERR_NULL_ARG,
              tlv_structure_encode(&codec, &value, sizeof(value), nullptr, 0, &used));
    EXPECT_EQ(0u, used);
    for (int missing = 0; missing < 3; ++missing) {
        auto incomplete = full_format;
        if (missing == 0) incomplete.encode = nullptr;
        if (missing == 1) incomplete.encode = nullptr;
        if (missing == 2) incomplete.measure = nullptr;
        codec.format = &incomplete;
        EXPECT_EQ(TLV_CODEC_ERR_NULL_ARG,
                  tlv_structure_encode(&codec, &value, sizeof(value), nullptr, 0, &used));
        EXPECT_EQ(0u, used);
    }
}

#if OPENTLV_EMV
TEST(Unit_Tlv_Architecture, EmvDictionaryAndCodecWorkWithoutBuiltinWireFormats) {
    EXPECT_GT(tlv_emv_schema.count, 0u);
    uint64_t input = 123456, output = 0;
    uint8_t  bytes[6]{};
    size_t   written = 0;
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_encode(&tlv_emv_codec_amount, &input, sizeof(input), bytes,
                                             sizeof(bytes), &written));
    ASSERT_EQ(TLV_CODEC_OK,
              tlv_codec_decode(&tlv_emv_codec_amount, bytes, written, &output, sizeof(output)));
    EXPECT_EQ(input, output);
}
#endif
} // namespace
