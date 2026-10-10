// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "../diagnostic_assertions.h"
#include "visitor_input.h"
#include "tlv/formats/compose.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#include "tlv/reader/visitor.h"
#include "tlv/codec/structure.h"
#include "tlv/config.h"
#include "tlv/formats/fixed.h"
#include "tlv/query/query.h"
#if OPENTLV_DHCP
#include "tlv/builtins/dhcp/dhcpv4.h"
#endif
#if OPENTLV_LLDP
#include "tlv/builtins/lldp/lldp.h"
#endif
#if OPENTLV_BLUETOOTH
#include "tlv/builtins/bluetooth/bluetooth_ltv.h"
#endif
#if OPENTLV_DOCUMENT
#include "tlv/document/document.h"
#endif
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
#include <memory>
#include "tlv/writer/tree.h"

namespace {
// Deliberately different from BER: bit 7 identifies a container.
tlv_result_t tag_read(const void*, const uint8_t* data, size_t size, tlv_tag_t* tag, size_t* used) {
    if (!size) return TLV_ERR_TRUNCATED;
    *tag = tlv_tag(data, 1);
    *used = 1;
    return TLV_OK;
}
tlv_result_t tag_write(const void*, const tlv_tag_t* tag, uint8_t* data, size_t capacity,
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
    if (!size) return TLV_ERR_TRUNCATED;
    *length = data[0];
    *used = 1;
    return TLV_OK;
}
tlv_result_t length_size(const void*, tlv_size_t length, size_t* used) {
    if (length > 255) return TLV_ERR_INVALID_LENGTH;
    *used = 1;
    return TLV_OK;
}
tlv_result_t length_write(const void* ctx, tlv_size_t length, uint8_t* data, size_t capacity,
                          size_t* used) {
    if (length_size(ctx, length, used) != TLV_OK) return TLV_ERR_INVALID_LENGTH;
    if (!data) return TLV_OK;
    if (!capacity) return TLV_ERR_BUFFER_TOO_SHORT;
    data[0] = static_cast<uint8_t>(length);
    return TLV_OK;
}
int constructed(const void*, const tlv_tag_t* tag) {
    return (tag->data[0] & 0x80) != 0;
}
const tlv_field_composition_t format_layout = {
    nullptr, tag_read, length_read,           nullptr,
    nullptr, nullptr,  TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
const tlv_format_t format = {&format_layout, tlv_fields_decode, nullptr, nullptr, nullptr};
const tlv_field_composition_t constructed_format_layout = {
    nullptr, tag_read, length_read,           nullptr,
    nullptr, nullptr,  TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
const tlv_format_t constructed_format = {&constructed_format_layout, tlv_fields_decode, nullptr,
                                         nullptr, constructed};
const tlv_field_composition_t constructed_full_format_layout = {
    nullptr,   tag_read,     length_read,           nullptr,
    tag_write, length_write, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
const tlv_format_t constructed_full_format = {&constructed_full_format_layout, tlv_fields_decode,
                                              tlv_fields_measure, tlv_fields_encode, constructed};

#if OPENTLV_DOCUMENT
struct PipelineFormat {
    mutable size_t decodes = 0, measures = 0, encodes = 0;
    tlv_format_t   descriptor;
    PipelineFormat() : descriptor{this, decode, measure, encode, constructed} {}
    static tlv_result_t decode(const void* ctx, const uint8_t* data, size_t size,
                               tlv_decoded_t* out, tlv_format_error_t* error) {
        ++static_cast<const PipelineFormat*>(ctx)->decodes;
        return tlv_fields_decode(&constructed_full_format_layout, data, size, out, error);
    }
    static tlv_result_t measure(const void* ctx, const tlv_element_t* element, tlv_encoding_t* out,
                                tlv_format_error_t* error) {
        ++static_cast<const PipelineFormat*>(ctx)->measures;
        return tlv_fields_measure(&constructed_full_format_layout, element, out, error);
    }
    static tlv_result_t encode(const void* ctx, const tlv_element_t* element, uint8_t* data,
                               size_t capacity, size_t* used, tlv_format_error_t* error) {
        ++static_cast<const PipelineFormat*>(ctx)->encodes;
        return tlv_fields_encode(&constructed_full_format_layout, element, data, capacity, used,
                                 error);
    }
};

TEST(Integration_Tlv_Pipeline, IncrementalSelectionMutationAndEncodingAtEverySplit) {
    // A prefix, nested selection, another child, and a following root.
    const uint8_t wire[] = {1, 0, 0x80, 7, 0x81, 3, 2, 1, 42, 3, 0, 4, 0};
    for (size_t split = 0; split <= sizeof(wire); ++split) {
        SCOPED_TRACE(split);
        PipelineFormat    format;
        tlv_tree_frame_t  frames[2]{};
        tlv_tree_reader_t reader{};
        ASSERT_EQ(TLV_OK, tlv_tree_reader_init_incremental(&reader, wire, split, &format.descriptor,
                                                           frames, 2, 2, 6));
        tlv_query_t         query{};
        tlv_query_matcher_t matcher{};
        ASSERT_EQ(TLV_OK, tlv_query_parse("80/81", &query, nullptr));
        ASSERT_EQ(TLV_OK, tlv_query_matcher_init(&matcher, &query));
        tlv_tree_item_t item{};
        bool            replaced = false;
        for (;;) {
            auto rc = tlv_tree_reader_next(&reader, &item);
            if (rc == TLV_NEED_MORE_DATA) {
                ASSERT_FALSE(replaced);
                // Drop the already consumed prefix; offsets must remain absolute.
                const size_t discard = tlv_tree_reader_consumed(&reader);
                ASSERT_EQ(TLV_OK, tlv_tree_reader_set_input(&reader, wire + discard,
                                                            sizeof(wire) - discard, discard, 1));
                replaced = true;
                continue;
            }
            ASSERT_EQ(TLV_OK, rc);
            EXPECT_EQ(wire + item.offset + item.source.value.offset, item.element.value.data);
            if (tlv_query_matcher_visit(&matcher, &item.element.tag, item.depth)) break;
        }
        EXPECT_EQ(4u, item.offset);
        EXPECT_EQ(1u, item.depth);
        const size_t           decoded = format.decodes;
        tlv_document_options_t options{};
        ASSERT_EQ(TLV_OK, tlv_document_options_init(&options, &format.descriptor));
        options.max_depth = 1;
        options.max_elements = 2;
        tlv_document_builder_t* raw_builder = nullptr;
        ASSERT_EQ(TLV_OK, tlv_document_builder_create(&options, &reader, &item, &raw_builder));
        std::unique_ptr<tlv_document_builder_t, decltype(&tlv_document_builder_free)> builder(
            raw_builder, tlv_document_builder_free);
        tlv_document_t* raw = nullptr;
        ASSERT_EQ(TLV_OK, tlv_document_builder_consume(builder.get(), &raw, nullptr));
        std::unique_ptr<tlv_document_t, decltype(&tlv_document_free)> doc(raw, tlv_document_free);
        EXPECT_EQ(decoded + 1, format.decodes); // Only the selected descendant is decoded.
        EXPECT_EQ(9u, tlv_tree_reader_offset(&reader));
        const uint8_t changed[] = {7, 8};
        ASSERT_EQ(TLV_OK,
                  tlv_node_set_value(tlv_node_first_child(tlv_document_first(raw)), changed, 2));
        size_t size = 0;
        ASSERT_EQ(TLV_OK, tlv_document_encoded_size(raw, &size));
        EXPECT_GT(format.measures, 0u);
        EXPECT_GT(format.encodes, 0u); // Exact measurement stages actual bytes.
        std::vector<uint8_t> output(size, 0xCC);
        size_t               used = 0;
        EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
                  tlv_document_encode(raw, output.data(), size - 1, &used));
        EXPECT_EQ(size, used);
        EXPECT_EQ(std::vector<uint8_t>(size, 0xCC), output);
        ASSERT_EQ(TLV_OK, tlv_document_encode(raw, output.data(), output.size(), &used));
        EXPECT_EQ((std::vector<uint8_t>{0x81, 4, 2, 2, 7, 8}), output);
        EXPECT_EQ(42, wire[8]); // Mutation owns its data, never changes borrowed input.
        ASSERT_EQ(TLV_OK, tlv_tree_reader_next(&reader, &item));
        EXPECT_EQ(9u, item.offset);
        EXPECT_EQ(3, item.element.tag.data[0]);
        if (!replaced)
            ASSERT_EQ(TLV_OK, tlv_tree_reader_set_input(&reader, wire, sizeof(wire), 0, 1));
        ASSERT_EQ(TLV_OK, tlv_tree_reader_next(&reader, &item));
        EXPECT_EQ(11u, item.offset);
        EXPECT_TRUE(tlv_tree_reader_at_end(&reader));
    }
}

TEST(Integration_Tlv_Pipeline, BuilderPreservesAbsoluteDiagnosticsAndReaderLimits) {
    const uint8_t wire[] = {1, 0, 0x80, 2, 2, 2};
    for (bool limited : {false, true}) {
        tlv_tree_reader_t reader{};
        tlv_tree_frame_t  frame{};
        ASSERT_EQ(TLV_OK,
                  tlv_tree_reader_init(&reader, wire, sizeof(wire), &constructed_full_format,
                                       &frame, 1, 1, limited ? 2 : 3));
        tlv_tree_item_t root{};
        ASSERT_EQ(TLV_OK, tlv_tree_reader_next(&reader, &root));
        ASSERT_EQ(TLV_OK, tlv_tree_reader_set_input(&reader, wire + 2, sizeof(wire) - 2, 2, 1));
        ASSERT_EQ(TLV_OK, tlv_tree_reader_next(&reader, &root));
        tlv_document_options_t options{};
        ASSERT_EQ(TLV_OK, tlv_document_options_init(&options, &constructed_full_format));
        tlv_document_builder_t* raw = nullptr;
        ASSERT_EQ(TLV_OK, tlv_document_builder_create(&options, &reader, &root, &raw));
        std::unique_ptr<tlv_document_builder_t, decltype(&tlv_document_builder_free)> builder(
            raw, tlv_document_builder_free);
        tlv_document_t*         doc = nullptr;
        tlv_reader_diagnostic_t diagnostic;
        std::memset(&diagnostic, 0, sizeof diagnostic);
        diagnostic.diagnostic.code = TLV_ERR_VISITOR;
        auto rc = tlv_document_builder_consume(raw, &doc, &diagnostic);
        EXPECT_EQ(limited ? TLV_ERR_LIMIT : TLV_ERR_TRUNCATED, rc);
        diagnostic_test::result(rc, diagnostic);
        if (limited) EXPECT_EQ(TLV_LOCATION_UNKNOWN, diagnostic.diagnostic.location.kind);
        EXPECT_EQ(nullptr, doc);
        if (!limited) {
            EXPECT_TRUE(diagnostic.diagnostic.location.kind);
            // Builder reports the offending element; detailed diagnostics point
            // at its missing Value, both in absolute stream coordinates.
            EXPECT_EQ(6u, diagnostic.diagnostic.location.begin);
        }
    }
}
#endif
const tlv_schema_entry_t   child_rules_fields[] = {{TLV_TAG(1), 1, 1, 0, nullptr, 0},
                                                   {TLV_TAG(2), 1, 1, 0, nullptr, 0}};
const tlv_structure_rule_t child_rules[] = {
    {&child_rules_fields[0], 1, 1, TLV_SCHEMA_PRIMITIVE, nullptr, 0},
    {&child_rules_fields[1], 0, 2, TLV_SCHEMA_PRIMITIVE, nullptr, 0}};
const tlv_structure_schema_t children = {child_rules, 2, 0, nullptr, 0, TLV_SCHEMA_ORDER_ANY};
const tlv_schema_entry_t     parent_rules_fields[] = {{TLV_TAG(0x80), 0, 255, 0, nullptr, 0}};
const tlv_structure_rule_t   parent_rules[] = {
    {&parent_rules_fields[0], 1, 1, TLV_SCHEMA_CONSTRUCTED, &children, 0}};
const tlv_structure_schema_t schema = {parent_rules, 1, 0, nullptr, 0, TLV_SCHEMA_ORDER_ANY};

#if OPENTLV_FORMAT_BER
TEST(Integration_Tlv_Architecture, BerIndefiniteTraversalSchemaAndCopies) {
    // Outer indefinite -> definite -> indefinite -> primitive; then siblings.
    const uint8_t wire[] = {0x30, 0x80, 0x30, 7, 0x30, 0x80, 4, 1, 42, 0, 0, 4, 0, 0, 0, 4, 0};
    std::vector<size_t> visits;
    auto visitor = [](const tlv_element_t*, size_t depth, size_t pos, void* context) {
        auto& out = *static_cast<std::vector<size_t>*>(context);
        out.push_back(depth);
        out.push_back(pos);
        return TLV_VISIT_CONTINUE;
    };
    EXPECT_EQ(TLV_OK, visit_tree_input(wire, sizeof(wire), &tlv_format_ber, 3, 6, visitor, &visits,
                                       nullptr));
    EXPECT_EQ((std::vector<size_t>{0, 0, 1, 2, 2, 4, 3, 6, 1, 11, 0, 15}), visits);
    tlv_structure_schema_t     recursive{};
    const tlv_schema_entry_t   rules_fields[] = {{TLV_TAG(0x30), 0, 100, 0, nullptr, 0},
                                                 {TLV_TAG(4), 0, 1, 0, nullptr, 0}};
    const tlv_structure_rule_t rules[] = {
        {&rules_fields[0], 0, 1, TLV_SCHEMA_CONSTRUCTED, &recursive, 0},
        {&rules_fields[1], 0, 1, TLV_SCHEMA_PRIMITIVE, nullptr, 0}};
    recursive = tlv_structure_schema_t{rules, 2, 0, nullptr, 0, TLV_SCHEMA_ORDER_ANY};
    EXPECT_EQ(TLV_OK,
              tlv_schema_validate(wire, sizeof(wire), &tlv_format_ber, &recursive, 3, 6, nullptr));

    tlv_schema_diagnostic_t offset{};
    EXPECT_EQ(TLV_ERR_LIMIT, visit_tree_input(wire, sizeof(wire), &tlv_format_ber, 2, 6, nullptr,
                                              nullptr, &offset.diagnostic.location.begin));
    EXPECT_EQ(TLV_LOCATION_UNKNOWN, offset.diagnostic.location.kind);
    tlv_element_t element{};
    size_t        used = 0;
    ASSERT_EQ(TLV_OK, tlv_read(wire, sizeof(wire), &tlv_format_ber, &element, &used));
    EXPECT_EQ(15u, used);
    EXPECT_EQ(11u, element.value.size);
    uint8_t copied[sizeof(wire)];
    size_t  written = 0;
    ASSERT_EQ(TLV_OK,
              tlv_copy_element(&element, &tlv_format_ber, copied, sizeof(copied), &written));
    EXPECT_EQ(13u, written);
    EXPECT_EQ(11, copied[1]);
    EXPECT_EQ(0, std::memcmp(wire + 2, copied + 2, 11));
    EXPECT_EQ(TLV_OK,
              visit_tree_input(copied, written, &tlv_format_ber, 3, 5, nullptr, nullptr, nullptr));
    ASSERT_EQ(TLV_OK, tlv_copy_encoded(wire, used, copied, sizeof(copied), &written));
    EXPECT_EQ(15u, written);
    EXPECT_EQ(0, std::memcmp(wire, copied, written));
    // An empty indefinite scope still enforces required children.
    const uint8_t                empty[] = {0x30, 0x80, 0, 0};
    const tlv_schema_entry_t     required_fields[] = {{TLV_TAG(4), 0, 1, 0, nullptr, 0}};
    const tlv_structure_rule_t   required = {&required_fields[0],  1,       1,
                                             TLV_SCHEMA_PRIMITIVE, nullptr, 0};
    const tlv_structure_schema_t child = {&required, 1, 0, nullptr, 0, TLV_SCHEMA_ORDER_ANY};
    const tlv_schema_entry_t     parent_fields[] = {{TLV_TAG(0x30), 0, 100, 0, nullptr, 0}};
    const tlv_structure_rule_t   parent = {&parent_fields[0],      1,      1,
                                           TLV_SCHEMA_CONSTRUCTED, &child, 0};
    const tlv_structure_schema_t root = {&parent, 1, 0, nullptr, 0, TLV_SCHEMA_ORDER_ANY};
    EXPECT_EQ(TLV_ERR_SCHEMA,
              tlv_schema_validate(empty, sizeof(empty), &tlv_format_ber, &root, 0, 1, &offset));
    EXPECT_EQ(2u, offset.diagnostic.location.begin);
}
#endif

TEST(Integration_Tlv_Architecture, GenericVisitorUsesFormatNestingAndAbsoluteOffsets) {
    const uint8_t       wire[] = {0x80, 5, 1, 1, 42, 0x81, 0, 2, 0};
    std::vector<size_t> visits;
    size_t              offset = 999;
    auto                visitor = [](const tlv_element_t*, size_t depth, size_t pos, void* ctx) {
        auto& out = *static_cast<std::vector<size_t>*>(ctx);
        out.push_back(depth);
        out.push_back(pos);
        return TLV_VISIT_CONTINUE;
    };
    EXPECT_EQ(TLV_OK, visit_tree_input(wire, sizeof(wire), &constructed_format, 1, 4, visitor,
                                       &visits, &offset));
    EXPECT_EQ((std::vector<size_t>{0, 0, 1, 2, 1, 5, 0, 7}), visits);
    EXPECT_EQ(999u, offset);
    EXPECT_EQ(TLV_ERR_LIMIT, visit_tree_input(wire, sizeof(wire), &constructed_format, 0, 4,
                                              nullptr, nullptr, &offset));
    EXPECT_EQ(2u, offset);
    EXPECT_EQ(TLV_ERR_LIMIT, visit_tree_input(wire, sizeof(wire), &constructed_format, 1, 3,
                                              nullptr, nullptr, &offset));
    EXPECT_EQ(7u, offset);
    // `format` has no is_constructed, so every value is opaque.
    EXPECT_EQ(TLV_OK,
              visit_tree_input(wire, sizeof(wire), &format, 0, 2, nullptr, nullptr, nullptr));
}

TEST(Integration_Tlv_Architecture, TreeRejectsTruncatedChildrenAndSupportsEarlyStop) {
    const uint8_t wire[] = {0x80, 2, 1, 9, 2, 0};
    size_t        offset = 99;
    EXPECT_EQ(TLV_ERR_TRUNCATED, visit_tree_input(wire, sizeof(wire), &constructed_format, 2, 10,
                                                  nullptr, nullptr, &offset));
    EXPECT_EQ(2u, offset);
    auto stop = [](const tlv_element_t*, size_t, size_t, void*) { return TLV_VISIT_STOP; };
    EXPECT_EQ(TLV_OK, visit_tree_input(wire, sizeof(wire), &constructed_format, 2, 10, stop,
                                       nullptr, nullptr));
    auto fail = [](const tlv_element_t*, size_t, size_t, void*) { return TLV_VISIT_ERROR; };
    EXPECT_EQ(TLV_ERR_VISITOR, visit_tree_input(wire, sizeof(wire), &constructed_format, 2, 10,
                                                fail, nullptr, nullptr));
    EXPECT_EQ(TLV_OK,
              visit_tree_input(nullptr, 0, &constructed_format, 0, 0, nullptr, nullptr, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              visit_tree_input(nullptr, 1, &constructed_format, 0, 0, nullptr, nullptr, nullptr));
    EXPECT_EQ(TLV_OK, visit_tree_input(nullptr, 0, &constructed_format, TLV_TREE_DEFAULT_DEPTH + 1,
                                       0, nullptr, nullptr, nullptr));
}

TEST(Integration_Tlv_Architecture, SchemaChecksRequiredRepeatedAndNestedMembership) {
    const uint8_t good[] = {0x80, 9, 1, 1, 42, 2, 1, 7, 2, 1, 8};
    EXPECT_EQ(TLV_OK,
              tlv_schema_validate(good, sizeof(good), &constructed_format, &schema, 1, 4, nullptr));
    const uint8_t empty[] = {0x80, 0};

    tlv_schema_diagnostic_t offset{};
    EXPECT_EQ(TLV_ERR_SCHEMA, tlv_schema_validate(empty, sizeof(empty), &constructed_format,
                                                  &schema, 0, 1, &offset));
    EXPECT_EQ(2u, offset.diagnostic.location.begin);
    const uint8_t duplicate[] = {0x80, 6, 1, 1, 42, 1, 1, 7};
    EXPECT_EQ(TLV_ERR_SCHEMA, tlv_schema_validate(duplicate, sizeof(duplicate), &constructed_format,
                                                  &schema, 1, 3, &offset));
    EXPECT_EQ(5u, offset.diagnostic.location.begin);
    const uint8_t unknown[] = {0x80, 6, 1, 1, 42, 3, 1, 7};
    EXPECT_EQ(TLV_ERR_SCHEMA, tlv_schema_validate(unknown, sizeof(unknown), &constructed_format,
                                                  &schema, 1, 3, &offset));
    EXPECT_EQ(5u, offset.diagnostic.location.begin);
    const uint8_t bad_length[] = {0x80, 2, 1, 0};
    EXPECT_EQ(TLV_ERR_SCHEMA, tlv_schema_validate(bad_length, sizeof(bad_length),
                                                  &constructed_format, &schema, 1, 2, nullptr));
    EXPECT_EQ(TLV_ERR_SCHEMA,
              tlv_schema_validate(nullptr, 0, &constructed_format, &schema, 0, 0, nullptr));
}

TEST(Integration_Tlv_Architecture, MaximumDepthAndEmptyChildSchemaUseTheSameBoundary) {
    std::vector<uint8_t> wire;
    for (size_t i = 0; i <= TLV_TREE_DEFAULT_DEPTH; ++i) {
        wire.push_back(0x80);
        wire.push_back(static_cast<uint8_t>(2 * (TLV_TREE_DEFAULT_DEPTH - i)));
    }
    tlv_structure_schema_t   recursive{};
    const tlv_schema_entry_t rule_fields[] = {{TLV_TAG(0x80), 0, 255, 0, nullptr, 0}};
    tlv_structure_rule_t     rule = {&rule_fields[0], 0, 1, TLV_SCHEMA_CONSTRUCTED, &recursive, 0};
    recursive.rules = &rule;
    recursive.count = 1;
    EXPECT_EQ(TLV_OK,
              tlv_schema_validate(wire.data(), wire.size(), &constructed_format, &recursive,
                                  TLV_TREE_DEFAULT_DEPTH, TLV_TREE_DEFAULT_DEPTH + 1, nullptr));

    tlv_schema_diagnostic_t offset{};
    EXPECT_EQ(TLV_ERR_LIMIT,
              tlv_schema_validate(wire.data(), wire.size(), &constructed_format, &recursive,
                                  TLV_TREE_DEFAULT_DEPTH - 1, TLV_TREE_DEFAULT_DEPTH + 1, &offset));
    EXPECT_EQ(TLV_LOCATION_UNKNOWN, offset.diagnostic.location.kind);
    rule.min_occurs = 1;
    EXPECT_EQ(TLV_ERR_SCHEMA,
              tlv_schema_validate(wire.data(), wire.size(), &constructed_format, &recursive,
                                  TLV_TREE_DEFAULT_DEPTH, TLV_TREE_DEFAULT_DEPTH + 1, &offset));
    EXPECT_EQ(wire.size(), offset.diagnostic.location.begin);
}

TEST(Integration_Tlv_Architecture, TreeCursorDiagnosticsKeepAbsoluteOffsetsAndParentBounds) {
    // The child declares two bytes, but its parent contains only one. A later
    // top-level sibling must not supply the missing child byte.
    const uint8_t           data[] = {1, 0, 0x80, 3, 1, 2, 0xAA, 2, 0};
    size_t                  error_offset = 99;
    tlv_reader_diagnostic_t diagnostic{};
    ASSERT_EQ(TLV_ERR_TRUNCATED,
              visit_tree_input_diag(data, sizeof(data), &constructed_format, 8, 8, nullptr, nullptr,
                                    &error_offset, &diagnostic));
    EXPECT_EQ(4u, error_offset);
    EXPECT_EQ(TLV_READER_OP_VALUE, diagnostic.detail.operation);
    EXPECT_EQ(6u, diagnostic.diagnostic.location.begin);
    EXPECT_EQ(4u, diagnostic.detail.tag_offset);
    EXPECT_EQ(5u, diagnostic.detail.length_offset);
    EXPECT_EQ(6u, diagnostic.detail.value_offset);
    EXPECT_EQ(7u, diagnostic.detail.enclosing_end);
    EXPECT_EQ(1u, diagnostic.detail.available);
    EXPECT_EQ(2u, diagnostic.detail.declared_length);
}

TEST(Integration_Tlv_Architecture, SequentialTraversalDoesNotRecoverPastInvalidInput) {
    const uint8_t noisy[] = {0x33, 0xff, 1, 1, 42};
    tlv_element_t element{};
    tlv_reader_t  reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, noisy, sizeof(noisy), &format));
    EXPECT_EQ(TLV_ERR_TRUNCATED, tlv_reader_next(&reader, &element));
    EXPECT_EQ(0u, reader.pos);
    auto visit = [](const tlv_element_t*, void*) { return TLV_VISIT_CONTINUE; };
    EXPECT_EQ(TLV_ERR_TRUNCATED, visit_input(noisy, sizeof(noisy), &format, visit, nullptr));
    EXPECT_EQ(TLV_OK, visit_input(noisy + 2, sizeof(noisy) - 2, &format, visit, nullptr));
}

struct object {
    uint8_t first, second;
};
tlv_result_t object_decode(const void*, const tlv_format_t* selected, const uint8_t* data,
                           size_t size, void* value, size_t capacity,
                           tlv_codec_diagnostic_t* diagnostic) {
    tlv_codec_diagnostic_init(diagnostic, TLV_CODEC_OP_DECODE);
    if (capacity < sizeof(object))
        return tlv_codec_diagnostic_result(diagnostic, TLV_ERR_BUFFER_TOO_SHORT);
    tlv_reader_t  reader{};
    tlv_element_t element{};
    object        result{};
    if (tlv_reader_init(&reader, data, size, selected) != TLV_OK)
        return tlv_codec_diagnostic_result(diagnostic, TLV_ERR_INVALID_VALUE);
    while (!tlv_reader_at_end(&reader)) {
        if (tlv_reader_next(&reader, &element) != TLV_OK)
            return tlv_codec_diagnostic_result(diagnostic, TLV_ERR_INVALID_VALUE);
        if (element.tag.data[0] == 1)
            result.first = element.value.data[0];
        else
            result.second = element.value.data[0];
    }
    std::memcpy(value, &result, sizeof(result));
    return tlv_codec_diagnostic_result(diagnostic, TLV_OK);
}
tlv_result_t object_encode(const void*, const tlv_format_t* selected, const void* value,
                           size_t size, uint8_t* data, size_t capacity, size_t* written,
                           tlv_codec_diagnostic_t* diagnostic) {
    tlv_codec_diagnostic_init(diagnostic, TLV_CODEC_OP_ENCODE);
    if (size != sizeof(object))
        return tlv_codec_diagnostic_result(diagnostic, TLV_ERR_INVALID_VALUE);
    if (!data) {
        *written = 6;
        return tlv_codec_diagnostic_result(diagnostic, TLV_OK);
    }
    if (capacity < 6) return tlv_codec_diagnostic_result(diagnostic, TLV_ERR_BUFFER_TOO_SHORT);
    object input{};
    std::memcpy(&input, value, sizeof(input));
    tlv_writer_t writer{};
    if (tlv_writer_init(&writer, data, capacity, selected) != TLV_OK ||
        tlv_writer_write(&writer, TLV_TAG(1), &input.first, 1) != TLV_OK ||
        tlv_writer_write(&writer, TLV_TAG(2), &input.second, 1) != TLV_OK)
        return tlv_codec_diagnostic_result(diagnostic, TLV_ERR_INVALID_VALUE);
    *written = tlv_writer_size(&writer);
    return tlv_codec_diagnostic_result(diagnostic, TLV_OK);
}

TEST(Integration_Tlv_Architecture, WholeObjectCodecRoundtripAndValidationBeforeMapping) {
    const tlv_structure_codec_t codec = {
        nullptr, &constructed_full_format, &children, 0, 2, object_decode, object_encode};
    object  value = {42, 7}, result = {99, 99};
    uint8_t wire[6]{};
    size_t  used = 0;
    EXPECT_EQ(TLV_OK, tlv_structure_encode(&codec, &value, sizeof(value), nullptr, 0, &used, NULL));
    EXPECT_EQ(6u, used);
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              tlv_structure_encode(&codec, &value, sizeof(value), wire, 5, &used, NULL));
    EXPECT_EQ(0u, used);
    EXPECT_EQ(TLV_OK,
              tlv_structure_encode(&codec, &value, sizeof(value), wire, sizeof(wire), &used, NULL));
    EXPECT_EQ(TLV_OK, tlv_structure_decode(&codec, wire, used, &result, sizeof(result), NULL));
    EXPECT_EQ(42, result.first);
    EXPECT_EQ(7, result.second);
    wire[3] = 1;
    result.first = 99;
    EXPECT_EQ(TLV_ERR_SCHEMA,
              tlv_structure_decode(&codec, wire, used, &result, sizeof(result), NULL));
    EXPECT_EQ(99, result.first);
    tlv_structure_codec_t bad = codec;
    bad.schema = &schema;
    EXPECT_EQ(TLV_ERR_SCHEMA,
              tlv_structure_encode(&bad, &value, sizeof(value), wire, sizeof(wire), &used, NULL));
    EXPECT_EQ(0u, used);
}

} // namespace

TEST(Integration_Tlv_Architecture, WireFamiliesShareCanonicalElementAndGenericOperations) {
    const tlv_fixed_format_t config{
        {1}, {1, TLV_BYTE_ORDER_BIG_ENDIAN}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
    tlv_format_t fixed{};
    ASSERT_EQ(TLV_OK, tlv_fixed_format_init(&fixed, &config));
    struct Case {
        const char*          name;
        const tlv_format_t*  format;
        std::vector<uint8_t> wire;
    };
    const Case cases[] = {
        {"Fixed TLV", &fixed, {0, 0, 53, 1, 3, 127, 0}},
#if OPENTLV_DHCP
        {"DHCP identifier-dependent", &tlv_format_dhcpv4, {0, 53, 1, 3, 127, 0}},
#endif
#if OPENTLV_LLDP
        {"LLDP packed", &tlv_format_lldp, {0, 0, 106, 1, 3, 254, 0}},
#endif
#if OPENTLV_BLUETOOTH
        {"Bluetooth LTV", &tlv_format_bluetooth_ltv, {1, 0, 2, 53, 3, 1, 127}},
#endif
    };
    const uint8_t tags[] = {0, 53, 127};
    const size_t  lengths[] = {0, 1, 0};
    // Only descriptors and reference bytes vary; consumers have no protocol branches.
    for (const auto& test : cases) {
        SCOPED_TRACE(test.name);
        tlv_reader_t         reader{};
        tlv_writer_t         writer{};
        std::vector<uint8_t> output(test.wire.size());
        ASSERT_EQ(TLV_OK,
                  tlv_reader_init(&reader, test.wire.data(), test.wire.size(), test.format));
        ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, output.data(), output.size(), test.format));
        size_t message_offset = 0;
        for (size_t i = 0; i < 3; ++i) {
            const size_t start = reader.pos;
            if (i == 1) message_offset = start;
            tlv_element_t element{};
            ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
            ASSERT_EQ(1u, element.tag.size);
            EXPECT_EQ(tags[i], element.tag.data[0]);
            ASSERT_EQ(lengths[i], element.value.size);
            if (lengths[i]) EXPECT_EQ(3, element.value.data[0]);
            ASSERT_EQ(TLV_OK, tlv_writer_copy_element(&writer, &element));
            tlv_decoded_t decoded{};
            ASSERT_EQ(TLV_OK, tlv_format_decode(test.format, test.wire.data() + start,
                                                test.wire.size() - start, &decoded, nullptr));
            EXPECT_EQ(reader.pos - start, decoded.source.size);
            EXPECT_TRUE(tlv_tag_equal(element.tag, decoded.element.tag));
            EXPECT_EQ(element.value.data, decoded.element.value.data);
            std::vector<uint8_t> preserved(decoded.source.size);
            size_t               written = 0;
            ASSERT_EQ(TLV_OK, tlv_source_preserve(&decoded.source, &element, preserved.data(),
                                                  preserved.size(), &written));
            EXPECT_EQ(preserved.size(), written);
            EXPECT_EQ(0, std::memcmp(test.wire.data() + start, preserved.data(), written));
        }
        EXPECT_TRUE(tlv_reader_at_end(&reader));
        EXPECT_EQ(test.wire.size(), tlv_writer_size(&writer));
        EXPECT_EQ(test.wire, output);
        tlv_query_t query{};
        ASSERT_EQ(TLV_OK, tlv_query_parse("35", &query, nullptr));
        std::vector<size_t> matches;
        auto visit = [](const tlv_element_t* element, size_t, size_t offset, void* context) {
            EXPECT_TRUE(tlv_tag_equal(TLV_TAG(53), element->tag));
            EXPECT_EQ(1u, element->value.size);
            static_cast<std::vector<size_t>*>(context)->push_back(offset);
            return TLV_VISIT_CONTINUE;
        };
        ASSERT_EQ(TLV_OK, tlv_query_visit_buffer(test.wire.data(), test.wire.size(), test.format,
                                                 &query, 0, 3, visit, &matches, nullptr));
        ASSERT_EQ(1u, matches.size());
        EXPECT_EQ(message_offset, matches[0]);
#if OPENTLV_DOCUMENT
        tlv_document_options_t options{};
        ASSERT_EQ(TLV_OK, tlv_document_options_init(&options, test.format));
        tlv_document_t* raw = nullptr;
        ASSERT_EQ(TLV_OK,
                  tlv_document_parse(test.wire.data(), test.wire.size(), &options, &raw, nullptr));
        std::unique_ptr<tlv_document_t, decltype(&tlv_document_free)> doc(raw, tlv_document_free);
        EXPECT_EQ(3u, tlv_document_count(doc.get()));
        tlv_node_t* node = nullptr;
        ASSERT_EQ(TLV_OK, tlv_document_find_path(doc.get(), &query, &node));
        ASSERT_NE(nullptr, node);
        ASSERT_EQ(1u, tlv_node_value_size(node));
        EXPECT_EQ(3, tlv_node_value_data(node)[0]);
        size_t written = 0;
        ASSERT_EQ(TLV_OK, tlv_document_encode(doc.get(), output.data(), output.size(), &written));
        EXPECT_EQ(test.wire.size(), written);
        EXPECT_EQ(test.wire, output);
#endif
    }
}
