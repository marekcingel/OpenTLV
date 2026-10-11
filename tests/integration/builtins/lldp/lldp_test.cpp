// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "../../../diagnostic_assertions.h"
#include "tlv/builtins/lldp/lldp.h"
#include "tlv/builtins/lldp/codec.h"
#include "tlv/builtins/lldp/schema.h"
#include "tlv/schema/number.h"
#include "tlv/config.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#include "tlv/query/query.h"
#if OPENTLV_DOCUMENT
#include "tlv/document/document.h"
#endif
#include <gtest/gtest.h>
#include <array>
#include <cstring>
#include <memory>
#include <vector>

namespace {
// Hand-authored base LLDPDU reference: local Chassis/Port identifiers and TTL 120.
const std::vector<uint8_t> base_lldpdu = {2, 2, 7, 'c', 4, 2, 7, 'p', 6, 2, 0, 120};
} // namespace

TEST(Integration_Tlv_Lldp, StructuralRulesCanBorrowExistingFieldSchemas) {
    std::vector<tlv_structure_rule_t> rules(tlv_lldp_schema.rules,
                                            tlv_lldp_schema.rules + tlv_lldp_schema.count);
    tlv_structure_schema_t            schema = tlv_lldp_schema;
    schema.rules = rules.data();
    EXPECT_EQ(TLV_OK, tlv_schema_validate(base_lldpdu.data(), base_lldpdu.size(), &tlv_format_lldp,
                                          &schema, 8, 100, nullptr));
    auto invalid = base_lldpdu;
    invalid[9] = 1;
    invalid.pop_back();
    EXPECT_EQ(TLV_ERR_SCHEMA, tlv_schema_validate(invalid.data(), invalid.size(), &tlv_format_lldp,
                                                  &schema, 8, 100, nullptr));
    // Explicit uint64_t composition, not the builtin TTL's uint16_t representation.
    const tlv_schema_number_t ttl = {rules[3].entry, {TLV_NUMBER_BINARY_BE, 0, 0}};
    const auto                codec = tlv_schema_number_codec(&ttl);
    const uint64_t            seconds = 120;
    uint8_t                   bytes[2] = {};
    size_t                    written = 0;
    EXPECT_EQ(TLV_OK, tlv_codec_encode(&codec, &seconds, sizeof(seconds), bytes, sizeof(bytes),
                                       &written, NULL));
    EXPECT_EQ(2u, written);
    EXPECT_EQ(0, bytes[0]);
    EXPECT_EQ(120, bytes[1]);
}

TEST(Integration_Tlv_Lldp, SchemaMandatoryPrefixOptionalEndAndDiagnostics) {
    tlv_schema_diagnostic_t diagnostic{};
    EXPECT_EQ(TLV_OK, tlv_lldp_validate(base_lldpdu.data(), base_lldpdu.size(), 3, &diagnostic));
    EXPECT_EQ(TLV_OK, diagnostic.diagnostic.code);
    EXPECT_FALSE(diagnostic.diagnostic.location.kind);
    auto wire = base_lldpdu;
    wire.insert(wire.end(), {0, 0});
    EXPECT_EQ(TLV_OK, tlv_lldp_validate(wire.data(), wire.size(), 4, nullptr));
    wire.insert(wire.end(), {10, 0});
    EXPECT_EQ(TLV_ERR_SCHEMA,
              TLV_DIAGNOSTIC_RESULT(diagnostic,
                                    tlv_lldp_validate(wire.data(), wire.size(), 5, &diagnostic)));
    EXPECT_EQ(14u, diagnostic.diagnostic.location.begin);
    EXPECT_STREQ("end of region after End TLV", diagnostic.diagnostic.expected);
    wire = base_lldpdu;
    wire[0] = 4;
    wire[4] = 2;
    EXPECT_EQ(TLV_ERR_SCHEMA,
              TLV_DIAGNOSTIC_RESULT(diagnostic,
                                    tlv_lldp_validate(wire.data(), wire.size(), 3, &diagnostic)));
    EXPECT_EQ(0u, diagnostic.diagnostic.location.begin);
    EXPECT_STREQ("Chassis ID, Port ID, TTL prefix", diagnostic.diagnostic.expected);
    EXPECT_EQ(TLV_SCHEMA_ISSUE_ORDER, diagnostic.detail.kind);
    EXPECT_EQ(TLV_ERR_SCHEMA,
              TLV_DIAGNOSTIC_RESULT(diagnostic,
                                    tlv_lldp_validate(base_lldpdu.data(), 8, 3, &diagnostic)));
    EXPECT_EQ(8u, diagnostic.diagnostic.location.begin);
    EXPECT_EQ(TLV_SCHEMA_ISSUE_MISSING, diagnostic.detail.kind);
    EXPECT_EQ(TLV_LOCATION_SCOPE_END, diagnostic.diagnostic.location.kind);
    EXPECT_EQ(TLV_ERR_SCHEMA,
              TLV_DIAGNOSTIC_RESULT(diagnostic, tlv_lldp_validate(nullptr, 0, 3, &diagnostic)));
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              TLV_DIAGNOSTIC_RESULT(diagnostic, tlv_lldp_validate(nullptr, 1, 3, &diagnostic)));
    EXPECT_EQ(TLV_ERR_LIMIT, TLV_DIAGNOSTIC_RESULT(diagnostic, tlv_lldp_validate(base_lldpdu.data(),
                                                                                 base_lldpdu.size(),
                                                                                 2, &diagnostic)));
    EXPECT_EQ(TLV_LOCATION_UNKNOWN, diagnostic.diagnostic.location.kind);
    EXPECT_EQ(TLV_ERR_LIMIT, tlv_lldp_validate(base_lldpdu.data(), base_lldpdu.size(), 0, nullptr));
}

TEST(Integration_Tlv_Lldp, SchemaOptionalOrderUnknownsAndRepeatedExtensions) {
    auto wire = base_lldpdu;
    // Optional Types need not be numerically sorted. Unknown Type 9 is accepted.
    wire.insert(wire.end(), {12,  0, 10, 0,    8,    0, 18,  0,  254, 4,   0,  0x80, 0xC2, 1,
                             254, 4, 0,  0x80, 0xC2, 1, 16,  9,  2,   250, 42, 1,    0,    0,
                             0,   0, 0,  16,   9,    2, 250, 43, 1,   0,   0,  0,    0,    0});
    EXPECT_EQ(TLV_OK, tlv_lldp_validate(wire.data(), wire.size(), 20, nullptr));
    wire.insert(wire.begin(), {18, 0});
    EXPECT_EQ(TLV_ERR_SCHEMA, tlv_lldp_validate(wire.data(), wire.size(), 20, nullptr));
}

TEST(Integration_Tlv_Lldp, SchemaRejectsDuplicatesLengthsAndTruncation) {
    for (const std::vector<uint8_t>& extra : {std::vector<uint8_t>{2, 2, 7, 'd'},
                                              {4, 2, 7, 'q'},
                                              {6, 2, 0, 0},
                                              {8, 0, 8, 0},
                                              {10, 0, 10, 0},
                                              {12, 0, 12, 0},
                                              {14, 4, 0, 0, 0, 0, 14, 4, 0, 0, 0, 0},
                                              {0, 0, 0, 0}}) {
        auto wire = base_lldpdu;
        wire.insert(wire.end(), extra.begin(), extra.end());
        EXPECT_EQ(TLV_ERR_SCHEMA, tlv_lldp_validate(wire.data(), wire.size(), 20, nullptr));
    }
    for (const std::vector<uint8_t>& extra : {std::vector<uint8_t>{0, 1, 0},
                                              {14, 3, 0, 0, 0},
                                              {254, 3, 0, 0, 0},
                                              {16, 8, 0, 0, 0, 0, 0, 0, 0, 0}}) {
        auto wire = base_lldpdu;
        wire.insert(wire.end(), extra.begin(), extra.end());
        tlv_schema_diagnostic_t diagnostic{};
        EXPECT_EQ(TLV_ERR_SCHEMA,
                  TLV_DIAGNOSTIC_RESULT(
                      diagnostic, tlv_lldp_validate(wire.data(), wire.size(), 20, &diagnostic)));
        EXPECT_EQ(base_lldpdu.size(), diagnostic.diagnostic.location.begin);
    }
    auto wire = base_lldpdu;
    wire.push_back(0xFE);
    EXPECT_EQ(TLV_ERR_TRUNCATED, tlv_lldp_validate(wire.data(), wire.size(), 20, nullptr));
    wire.insert(wire.end(), {4, 0, 0});
    EXPECT_EQ(TLV_ERR_TRUNCATED, tlv_lldp_validate(wire.data(), wire.size(), 20, nullptr));
}

TEST(Integration_Tlv_Lldp, GenericSchemaReportAndValueCodecComposition) {
    auto wire = base_lldpdu;
    wire.insert(wire.end(), {6, 2, 0, 0});
    tlv_schema_diagnostic_t        issue{};
    tlv_schema_diagnostic_report_t report = {&issue, 1, 0};
    EXPECT_EQ(TLV_ERR_SCHEMA, tlv_schema_validate_all_diag(
                                  wire.data(), wire.size(), &tlv_format_lldp, &tlv_lldp_schema, 0,
                                  10, TLV_SCHEMA_UNKNOWN_BY_SCHEMA, &report, nullptr));
    EXPECT_EQ(1u, report.count);
    EXPECT_EQ(TLV_SCHEMA_ISSUE_DUPLICATE, issue.detail.kind);
    EXPECT_EQ(0u, issue.diagnostic.path.length);
    EXPECT_TRUE(tlv_tag_equal(TLV_TAG(3), issue.detail.tag));
    tlv_reader_t reader{};
    ASSERT_EQ(TLV_OK,
              tlv_reader_init(&reader, base_lldpdu.data(), base_lldpdu.size(), &tlv_format_lldp));
    std::vector<uint8_t> rebuilt;
    while (!tlv_reader_at_end(&reader)) {
        tlv_element_t element{};
        ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
        if (element.tag.data[0] == 3) {
            uint16_t ttl = 0;
            size_t   value_size = 0;
            ASSERT_EQ(TLV_OK, tlv_size_to_native(element.value.size, &value_size));
            ASSERT_EQ(TLV_OK, tlv_codec_decode(&tlv_lldp_codec_ttl, element.value.data, value_size,
                                               &ttl, sizeof(ttl), NULL));
            EXPECT_EQ(120, ttl);
        }
        uint8_t encoded[258];
        size_t  size = 0;
        ASSERT_EQ(TLV_OK, tlv_format_encode(&tlv_format_lldp, &element, encoded, sizeof(encoded),
                                            &size, nullptr));
        rebuilt.insert(rebuilt.end(), encoded, encoded + size);
    }
    EXPECT_EQ(base_lldpdu, rebuilt);
}

#if OPENTLV_DOCUMENT
TEST(Integration_Tlv_Lldp, DocumentQueryCodecEditAndStructuralRevalidation) {
    tlv_document_options_t options{};
    ASSERT_EQ(TLV_OK, tlv_document_options_init(&options, &tlv_format_lldp));
    tlv_document_t* raw = nullptr;
    ASSERT_EQ(TLV_OK,
              tlv_document_parse(base_lldpdu.data(), base_lldpdu.size(), &options, &raw, nullptr));
    std::unique_ptr<tlv_document_t, decltype(&tlv_document_free)> doc(raw, tlv_document_free);
    tlv_query_t                                                   query{};
    ASSERT_EQ(TLV_OK, tlv_query_parse("03", &query, nullptr));
    tlv_node_t* ttl_node = nullptr;
    ASSERT_EQ(TLV_OK, tlv_document_find_path(doc.get(), &query, &ttl_node));
    ASSERT_NE(nullptr, ttl_node);
    const uint16_t ttl = 300;
    uint8_t        value[2];
    size_t         written = 0;
    ASSERT_EQ(TLV_OK, tlv_codec_encode(&tlv_lldp_codec_ttl, &ttl, sizeof(ttl), value, sizeof(value),
                                       &written, NULL));
    ASSERT_EQ(TLV_OK, tlv_node_set_value(ttl_node, value, written));
    std::array<uint8_t, 12> wire{};
    ASSERT_EQ(TLV_OK, tlv_document_encode(doc.get(), wire.data(), wire.size(), &written));
    ASSERT_EQ(TLV_OK, tlv_lldp_validate(wire.data(), written, 3, nullptr));
    EXPECT_EQ(1, wire[10]);
    EXPECT_EQ(0x2C, wire[11]);
    // Structural validation stays opt-in even after a Document edit.
    ASSERT_EQ(TLV_OK, tlv_node_set_value(ttl_node, value, 1));
    ASSERT_EQ(TLV_OK, tlv_document_encode(doc.get(), wire.data(), wire.size(), &written));
    EXPECT_EQ(TLV_ERR_SCHEMA, tlv_lldp_validate(wire.data(), written, 3, nullptr));
}
#endif

TEST(Integration_Tlv_Lldp, SchemaLengthBoundariesRemainSeparateFromFraming) {
    struct Bounds {
        uint8_t type;
        size_t  minimum;
        size_t  maximum;
    };
    for (auto bounds :
         {Bounds{4, 0, 255}, {5, 0, 255}, {6, 0, 255}, {7, 4, 4}, {8, 9, 167}, {127, 4, 511}}) {
        for (size_t length : {bounds.minimum, bounds.maximum, bounds.maximum + 1}) {
            if (length > 511) continue; // Framing's 512 rejection is tested separately.
            auto wire = base_lldpdu;
            wire.push_back(static_cast<uint8_t>((bounds.type << 1) | (length >> 8)));
            wire.push_back(static_cast<uint8_t>(length));
            wire.insert(wire.end(), length, 0);
            EXPECT_EQ(length <= bounds.maximum ? TLV_OK : TLV_ERR_SCHEMA,
                      tlv_lldp_validate(wire.data(), wire.size(), 4, nullptr));
        }
    }
}

TEST(Integration_Tlv_Lldp, EveryRepresentableTypeAndLengthRoundtrips) {
    EXPECT_EQ(1, tlv_config_lldp());
    EXPECT_EQ(nullptr, tlv_format_lldp.is_constructed);
    std::array<uint8_t, 511> value{};
    value.fill(0xA5);
    std::array<uint8_t, 513> wire{}, preserved{};
    for (unsigned type = 0; type < 128; ++type) {
        const uint8_t tag = static_cast<uint8_t>(type);
        for (size_t length = 0; length <= 511; ++length) {
            const tlv_element_t element = {tlv_tag(&tag, 1), {value.data(), length}};
            size_t              written = 0;
            ASSERT_EQ(TLV_OK, tlv_format_encode(&tlv_format_lldp, &element, wire.data(),
                                                wire.size(), &written, nullptr));
            ASSERT_EQ(length + 2, written);
            ASSERT_EQ((type << 1) | (length >> 8), wire[0]);
            ASSERT_EQ(length & 255, wire[1]);
            tlv_decoded_t decoded{};
            ASSERT_EQ(TLV_OK,
                      tlv_format_decode(&tlv_format_lldp, wire.data(), written, &decoded, nullptr));
            ASSERT_TRUE(tlv_tag_equal(element.tag, decoded.element.tag));
            ASSERT_EQ(length, decoded.element.value.size);
            ASSERT_EQ(wire.data() + 2, decoded.element.value.data);
            ASSERT_EQ(0, std::memcmp(value.data(), decoded.element.value.data, length));
            ASSERT_EQ(TLV_TAG_BINDING_FORMAT, decoded.source.tag_binding);
            ASSERT_EQ(TLV_OK, tlv_source_preserve(&decoded.source, &decoded.element,
                                                  preserved.data(), preserved.size(), &written));
            ASSERT_EQ(0, std::memcmp(wire.data(), preserved.data(), written));
        }
    }
}

TEST(Integration_Tlv_Lldp, RejectsUnrepresentableElementsBeforeWriting) {
    uint8_t       output[4] = {0xCC, 0xCC, 0xCC, 0xCC};
    const uint8_t value = 0xAA;
    size_t        written = 99;
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE, tlv_write(output, sizeof(output), &tlv_format_lldp,
                                                  TLV_TAG(0, 1), &value, 1, &written));
    EXPECT_EQ(TLV_ERR_INVALID_TAG, tlv_write(output, sizeof(output), &tlv_format_lldp, TLV_TAG(128),
                                             &value, 1, &written));
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE, tlv_write(output, sizeof(output), &tlv_format_lldp,
                                                  tlv_tag(nullptr, 0), &value, 1, &written));
    tlv_element_t  element = {TLV_TAG(1), {nullptr, 512}};
    tlv_encoding_t encoding{};
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
              tlv_format_measure(&tlv_format_lldp, &element, &encoding, nullptr));
    element.value.size = UINT64_MAX;
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
              tlv_format_measure(&tlv_format_lldp, &element, &encoding, nullptr));
    element.value.size = 511;
    ASSERT_EQ(TLV_OK, tlv_format_measure(&tlv_format_lldp, &element, &encoding, nullptr));
    EXPECT_EQ(513u, encoding.total);
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              tlv_write(output, 2, &tlv_format_lldp, TLV_TAG(1), &value, 1, &written));
    for (auto byte : output) EXPECT_EQ(0xCC, byte);
}

TEST(Integration_Tlv_Lldp, TruncationReportsWireRegionsAndDoesNotAdvance) {
    const uint8_t wire[] = {3, 0, 0xAA}; // Type 1, length 256.
    for (size_t size : {size_t(1), size_t(2), size_t(3)}) {
        tlv_reader_t reader{};
        ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, wire, size, &tlv_format_lldp));
        tlv_element_t element{};
        element.tag = TLV_TAG(42);
        tlv_reader_diagnostic_t error{};
        EXPECT_EQ(TLV_ERR_TRUNCATED,
                  TLV_DIAGNOSTIC_RESULT(error, tlv_reader_next_diag(&reader, &element, &error)));
        EXPECT_EQ(0u, reader.pos);
        EXPECT_TRUE(tlv_tag_equal(TLV_TAG(42), element.tag));
        EXPECT_EQ(size == 1 ? TLV_READER_OP_HEADER : TLV_READER_OP_VALUE, error.detail.operation);
        EXPECT_EQ(size == 1 ? 0u : 2u, error.diagnostic.location.begin);
        if (size > 1) {
            EXPECT_TRUE(error.detail.has_declared_length);
            EXPECT_EQ(256u, error.detail.declared_length);
        }
    }
}

TEST(Integration_Tlv_Lldp, ReaderDefinitionsAndQueryUseTypeWithoutProtocolSemantics) {
    // End, then organisational value: framing deliberately does not stop at End.
    const uint8_t wire[] = {0, 0, 0xFE, 4, 0, 0x80, 0xC2, 1};
    tlv_reader_t  reader{};
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, wire, sizeof(wire), &tlv_format_lldp));
    tlv_element_t end{}, organisation{};
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &end));
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &organisation));
    EXPECT_TRUE(tlv_reader_at_end(&reader));
    EXPECT_TRUE(tlv_tag_equal(TLV_TAG(0), end.tag));
    EXPECT_TRUE(tlv_tag_equal(TLV_TAG(127), organisation.tag));
    EXPECT_EQ(wire + 4, organisation.value.data);
    ASSERT_NE(nullptr, tlv_definition_find(&tlv_lldp_types, &organisation.tag));
    EXPECT_STREQ("Organisationally Specific",
                 tlv_definition_find(&tlv_lldp_types, &organisation.tag)->name);
    const auto reserved = TLV_TAG(9);
    EXPECT_EQ(nullptr, tlv_definition_find(&tlv_lldp_types, &reserved));
    EXPECT_EQ(10u, tlv_lldp_types.count);
    tlv_query_t query{};
    ASSERT_EQ(TLV_OK, tlv_query_parse("7F", &query, nullptr));
    size_t matches = 0;
    auto   visit = [](const tlv_element_t* element, size_t, size_t offset, void* context) {
        EXPECT_TRUE(tlv_tag_equal(TLV_TAG(127), element->tag));
        EXPECT_EQ(2u, offset);
        ++*static_cast<size_t*>(context);
        return TLV_VISIT_CONTINUE;
    };
    EXPECT_EQ(TLV_OK, tlv_query_visit_buffer(wire, sizeof(wire), &tlv_format_lldp, &query, 0, 2,
                                             visit, &matches, nullptr));
    EXPECT_EQ(1u, matches);
#if OPENTLV_DOCUMENT
    tlv_document_options_t options{};
    ASSERT_EQ(TLV_OK, tlv_document_options_init(&options, &tlv_format_lldp));
    tlv_document_t* raw = nullptr;
    ASSERT_EQ(TLV_OK, tlv_document_parse(wire, sizeof(wire), &options, &raw, nullptr));
    std::unique_ptr<tlv_document_t, decltype(&tlv_document_free)> doc(raw, tlv_document_free);
    tlv_node_t*                                                   found = nullptr;
    ASSERT_EQ(TLV_OK, tlv_document_find_path(doc.get(), &query, &found));
    EXPECT_NE(nullptr, found);
    uint8_t output[sizeof(wire)]{};
    size_t  written = 0;
    ASSERT_EQ(TLV_OK, tlv_document_encode(doc.get(), output, sizeof(output), &written));
    EXPECT_EQ(sizeof(wire), written);
    EXPECT_EQ(0, std::memcmp(wire, output, sizeof(wire)));
#endif
}
