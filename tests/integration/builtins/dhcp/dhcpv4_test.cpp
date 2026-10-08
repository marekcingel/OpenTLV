// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "../../../diagnostic_assertions.h"
#include "tlv/builtins/dhcp/dhcpv4.h"
#include "tlv/builtins/dhcp/options.h"
#include "tlv/builtins/dhcp/container.h"
#include "tlv/config.h"
#include "tlv/query/query.h"
#include "tlv/schema/schema.h"
#if OPENTLV_DOCUMENT
#include "tlv/document/document.h"
#endif
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#include <gtest/gtest.h>
#include <cstring>
#include <memory>
#include <vector>

TEST(Integration_Tlv_Dhcpv4, DefinitionsLeaveKnownAndUnknownValuesOpaque) {
    const uint8_t wire[] = {0x35, 0x01, 0x03, 0xE0, 0x02, 0xAA, 0xBB};
    uint8_t       output[sizeof(wire)] = {};
    tlv_reader_t  reader{};
    tlv_writer_t  writer{};
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, wire, sizeof(wire), &tlv_format_dhcpv4));
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, output, sizeof(output), &tlv_format_dhcpv4));
    tlv_element_t element{};
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
    ASSERT_EQ(1u, element.tag.size);
    EXPECT_EQ(0x35, element.tag.data[0]);
    ASSERT_EQ(1u, element.value.size);
    EXPECT_EQ(0x03, element.value.data[0]);
    const auto* definition = tlv_definition_find(&tlv_dhcpv4_options, &element.tag);
    ASSERT_NE(nullptr, definition);
    EXPECT_STREQ("DHCP Message Type", definition->name);
    ASSERT_EQ(TLV_OK, tlv_writer_copy_element(&writer, &element));

    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
    ASSERT_EQ(1u, element.tag.size);
    EXPECT_EQ(0xE0, element.tag.data[0]);
    EXPECT_EQ(nullptr, tlv_definition_find(&tlv_dhcpv4_options, &element.tag));
    ASSERT_EQ(2u, element.value.size);
    EXPECT_EQ(wire + 5, element.value.data);
    EXPECT_EQ(0xAA, element.value.data[0]);
    EXPECT_EQ(0xBB, element.value.data[1]);
    ASSERT_EQ(TLV_OK, tlv_writer_copy_element(&writer, &element));
    EXPECT_TRUE(tlv_reader_at_end(&reader));
    EXPECT_EQ(sizeof(wire), tlv_writer_size(&writer));
    EXPECT_EQ(0, std::memcmp(wire, output, sizeof(wire)));
}

TEST(Integration_Tlv_Dhcpv4, ReaderWriterExposePadAndContinuePastEnd) {
    const uint8_t wire[] = {0, 53, 1, 1, 254, 0, 255, 0, 42, 1, 7};
    const uint8_t codes[] = {0, 53, 254, 255, 0, 42};
    const size_t  lengths[] = {0, 1, 0, 0, 0, 1};
    uint8_t       output[sizeof(wire)] = {};
    tlv_reader_t  reader{};
    tlv_writer_t  writer{};
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, wire, sizeof(wire), &tlv_format_dhcpv4));
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, output, sizeof(output), &tlv_format_dhcpv4));
    size_t offset = 0;
    for (size_t i = 0; i < sizeof(codes); ++i) {
        tlv_element_t element{};
        ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
        EXPECT_EQ(codes[i], element.tag.data[0]);
        EXPECT_EQ(lengths[i], element.value.size);
        ASSERT_EQ(TLV_OK, tlv_writer_copy_element(&writer, &element));
        tlv_source_t source{};
        size_t       consumed = 0;
        ASSERT_EQ(TLV_OK,
                  tlv_read_source_diag(wire + offset, sizeof(wire) - offset, &tlv_format_dhcpv4,
                                       &element, &consumed, &source, nullptr));
        EXPECT_EQ(consumed, source.size);
        offset += consumed;
    }
    EXPECT_TRUE(tlv_reader_at_end(&reader));
    EXPECT_EQ(sizeof(wire), offset);
    EXPECT_EQ(sizeof(wire), tlv_writer_size(&writer));
    EXPECT_EQ(0, std::memcmp(wire, output, sizeof(wire)));
    tlv_element_t element{};
    EXPECT_EQ(TLV_ERR_END_OF_BUFFER, tlv_reader_next(&reader, &element));
}

TEST(Integration_Tlv_Dhcpv4, QueryAndDocumentTreatPadAndEndAsOrdinaryElements) {
    // The option after End is intentional: only container validation stops there.
    const uint8_t                          wire[] = {0, 0x35, 1, 3, 255, 0, 0xE0, 0};
    const char*                            paths[] = {"00", "35", "FF", "E0"};
    const std::vector<std::vector<size_t>> offsets = {{0, 5}, {1}, {4}, {6}};
    const size_t                           lengths[] = {0, 1, 0, 0};
#if OPENTLV_DOCUMENT
    tlv_document_options_t options{};
    ASSERT_EQ(TLV_OK, tlv_document_options_init(&options, &tlv_format_dhcpv4));
    tlv_document_t* raw = nullptr;
    ASSERT_EQ(TLV_OK, tlv_document_parse(wire, sizeof(wire), &options, &raw, nullptr));
    std::unique_ptr<tlv_document_t, decltype(&tlv_document_free)> doc(raw, tlv_document_free);
    EXPECT_EQ(5u, tlv_document_count(doc.get()));
#endif
    for (size_t i = 0; i < 4; ++i) {
        SCOPED_TRACE(paths[i]);
        tlv_query_t query{};
        ASSERT_EQ(TLV_OK, tlv_query_parse(paths[i], &query, nullptr));
        std::vector<size_t> matches;
        auto visit = [](const tlv_element_t*, size_t depth, size_t offset, void* context) {
            EXPECT_EQ(0u, depth);
            static_cast<std::vector<size_t>*>(context)->push_back(offset);
            return TLV_VISIT_CONTINUE;
        };
        ASSERT_EQ(TLV_OK, tlv_query_visit_buffer(wire, sizeof(wire), &tlv_format_dhcpv4, &query, 0,
                                                 5, visit, &matches, nullptr));
        EXPECT_EQ(offsets[i], matches);
#if OPENTLV_DOCUMENT
        auto* node = tlv_document_find_path(doc.get(), &query);
        ASSERT_NE(nullptr, node);
        EXPECT_EQ(lengths[i], tlv_node_value_size(node));
        EXPECT_EQ(0, tlv_node_is_constructed(node));
        EXPECT_EQ(wire[offsets[i][0]], tlv_node_tag(node).data[0]);
        if (lengths[i]) EXPECT_EQ(3, tlv_node_value_data(node)[0]);
        if (i == 0) {
            auto* second_pad = tlv_node_next_same_tag(node);
            ASSERT_NE(nullptr, second_pad);
            EXPECT_EQ(0u, tlv_node_value_size(second_pad));
            EXPECT_EQ(nullptr, tlv_node_next_same_tag(second_pad));
        }
#endif
    }
#if OPENTLV_DOCUMENT
    uint8_t output[sizeof(wire)]{};
    size_t  written = 0;
    ASSERT_EQ(TLV_OK, tlv_document_encode(doc.get(), output, sizeof(output), &written));
    EXPECT_EQ(sizeof(wire), written);
    EXPECT_EQ(0, std::memcmp(wire, output, sizeof(wire)));
#else
    (void)lengths;
#endif
    size_t           significant = 999;
    tlv_diagnostic_t diagnostic{};
    EXPECT_EQ(TLV_ERR_SCHEMA, TLV_DIAGNOSTIC_RESULT(diagnostic, tlv_dhcpv4_options_validate(
                                                                    wire, sizeof(wire), nullptr, 5,
                                                                    &significant, &diagnostic)));
    EXPECT_EQ(6u, diagnostic.offset);
}

TEST(Integration_Tlv_Dhcpv4, GenericSchemaKeepsValueConstraintsSeparateFromContainerPolicy) {
    const tlv_schema_entry_t   rules_fields[] = {{TLV_TAG(0), 0, 0, 0, "Pad", 0},
                                                 {TLV_TAG(53), 1, 1, 0, "Message Type", 0},
                                                 {TLV_TAG(255), 0, 0, 0, "End", 0}};
    const tlv_structure_rule_t rules[] = {
        {&rules_fields[0], 0, SIZE_MAX, TLV_SCHEMA_PRIMITIVE, nullptr, 0},
        {&rules_fields[1], 1, 1, TLV_SCHEMA_PRIMITIVE, nullptr, 0},
        {&rules_fields[2], 1, 1, TLV_SCHEMA_PRIMITIVE, nullptr, 0}};
    const tlv_structure_schema_t schema{rules, 3, 1, nullptr, 0, TLV_SCHEMA_ORDER_ANY};
    const uint8_t                valid[] = {0, 53, 1, 3, 255, 0, 224, 0};
    EXPECT_EQ(TLV_OK, tlv_schema_validate(valid, sizeof(valid), &tlv_format_dhcpv4, &schema, 0, 6,
                                          nullptr));
    const uint8_t invalid[] = {0, 53, 0, 255};
    tlv_reader_t  reader{};
    tlv_element_t element{};
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, invalid, sizeof(invalid), &tlv_format_dhcpv4));
    while (!tlv_reader_at_end(&reader)) ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
    size_t offset = 999;
    EXPECT_EQ(
        TLV_ERR_INVALID_LENGTH,
        tlv_schema_validate(invalid, sizeof(invalid), &tlv_format_dhcpv4, &schema, 0, 3, &offset));
    EXPECT_EQ(1u, offset);
    size_t significant = 0;
    EXPECT_EQ(TLV_OK, tlv_dhcpv4_options_validate(invalid, sizeof(invalid), nullptr, 3,
                                                  &significant, nullptr));
    EXPECT_EQ(sizeof(invalid), significant);
}

TEST(Integration_Tlv_Dhcpv4, ReaderTruncationReportsAbsoluteOffsetsWithoutAdvancing) {
    const uint8_t wire[] = {0, 255, 224, 0, 53, 2, 3};
    for (size_t size = 5; size <= sizeof(wire); ++size) {
        SCOPED_TRACE(size);
        tlv_reader_t  reader{};
        tlv_element_t element{};
        ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, wire, size, &tlv_format_dhcpv4));
        for (int i = 0; i < 3; ++i) ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
        const auto              previous = element;
        tlv_reader_diagnostic_t error{};
        EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
                  TLV_DIAGNOSTIC_RESULT(error, tlv_reader_next_diag(&reader, &element, &error)));
        EXPECT_EQ(4u, reader.pos);
        EXPECT_TRUE(tlv_tag_equal(previous.tag, element.tag));
        EXPECT_EQ(previous.value.data, element.value.data);
        EXPECT_EQ(previous.value.size, element.value.size);
        EXPECT_TRUE(error.diagnostic.has_offset);
        EXPECT_EQ(size == 5 ? 5u : 6u, error.diagnostic.offset);
        EXPECT_EQ(size == 5 ? TLV_READER_OP_LENGTH : TLV_READER_OP_VALUE, error.operation);
        EXPECT_TRUE(error.has_tag);
        EXPECT_TRUE(tlv_tag_equal(TLV_TAG(53), error.tag));
        EXPECT_EQ(4u, error.tag_offset);
        if (size > 5) {
            EXPECT_TRUE(error.has_declared_length);
            EXPECT_EQ(2u, error.declared_length);
            EXPECT_TRUE(error.has_raw_length);
            ASSERT_EQ(1u, error.raw_length.size);
            EXPECT_EQ(wire + 5, error.raw_length.data);
        }
    }
}
