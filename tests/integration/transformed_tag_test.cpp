#include "tlv/config.h"
#include "tlv/format.h"
#include "tlv/copy.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#include "tlv/query/query.h"
#include "tlv/schema/schema.h"
#if OPENTLV_DOCUMENT
#include "tlv/document/document.h"
#endif
#include <gtest/gtest.h>
#include <array>
#include <cstring>
#include <memory>
#include <vector>

namespace {
// Generic packed-header fixture, not an LLDP implementation or semantic validator.
const std::array<uint8_t, 128> identifiers = [] {
    std::array<uint8_t, 128> result{};
    for (size_t i = 0; i < result.size(); ++i) result[i] = static_cast<uint8_t>(i);
    return result;
}();

tlv_result_t packed_decode(const void* context, const uint8_t* data, size_t size,
                           tlv_decoded_t* result, tlv_format_error_t*) {
    if (size < 2) return TLV_ERR_BUFFER_TOO_SHORT;
    const size_t length = (static_cast<size_t>(data[0] & 1) << 8) | data[1];
    if (length > size - 2) return TLV_ERR_BUFFER_TOO_SHORT;
    const auto* table = static_cast<const std::array<uint8_t, 128>*>(context);
    result->element = {tlv_tag(&(*table)[data[0] >> 1], 1), {data + 2, length}};
    result->source.header = {0, 2, 1};
    result->source.tag = {0, 1, 1};
    result->source.length = {0, 2, 1};
    result->source.value = {2, length, 1};
    result->source.trailer = {2 + length, 0, 1};
    result->source.size = 2 + length;
    result->source.tag_binding = TLV_TAG_BINDING_FORMAT;
    return TLV_OK;
}

tlv_result_t packed_measure(const void*, const tlv_element_t* element, tlv_encoding_t* result,
                            tlv_format_error_t*) {
    if (element->tag.size != 1 || element->tag.data[0] > 127) return TLV_ERR_INVALID_TAG_SIZE;
    if (element->value.size > 511) return TLV_ERR_INVALID_LENGTH;
    *result = {2, element->value.size, 0, 2 + element->value.size};
    return TLV_OK;
}

tlv_result_t packed_encode(const void* context, const tlv_element_t* element, uint8_t* data,
                           size_t capacity, size_t* written, tlv_format_error_t* error) {
    tlv_encoding_t sizes{};
    const auto     rc = packed_measure(context, element, &sizes, error);
    if (rc != TLV_OK) return rc;
    // The validated format limit is 511, representable in every supported size_t.
    const size_t length = static_cast<size_t>(element->value.size);
    if (capacity < length + 2) return TLV_ERR_BUFFER_TOO_SHORT;
    data[0] = static_cast<uint8_t>((element->tag.data[0] << 1) | (length >> 8));
    data[1] = static_cast<uint8_t>(length & 255);
    if (length) std::memcpy(data + 2, element->value.data, length);
    *written = length + 2;
    return TLV_OK;
}

const tlv_format_t packed_format = {&identifiers, packed_decode, packed_measure, packed_encode,
                                    nullptr};

TEST(Integration_Tlv_TransformedTag, PackedIdentityRoundtripAndPreservation) {
    std::vector<tlv_decoded_t>        retained;
    std::vector<std::vector<uint8_t>> wires;
    for (size_t length : {size_t(0), size_t(1), size_t(255), size_t(256), size_t(511)}) {
        SCOPED_TRACE(length);
        const std::vector<uint8_t> value(length, 0xAA);
        wires.emplace_back(length + 2);
        auto&  wire = wires.back();
        size_t written = 0;
        ASSERT_EQ(TLV_OK, tlv_write(wire.data(), wire.size(), &packed_format, TLV_TAG(1),
                                    value.data(), value.size(), &written));
        EXPECT_EQ(length + 2, written);
        EXPECT_EQ(length >= 256 ? 3 : 2, wire[0]);
        EXPECT_EQ(length & 255, wire[1]);
        tlv_decoded_t decoded{};
        ASSERT_EQ(TLV_OK,
                  tlv_format_decode(&packed_format, wire.data(), wire.size(), &decoded, nullptr));
        EXPECT_TRUE(tlv_tag_equal(TLV_TAG(1), decoded.element.tag));
        EXPECT_EQ(wire.data() + 2, decoded.element.value.data);
        EXPECT_EQ(TLV_TAG_BINDING_FORMAT, decoded.source.tag_binding);
        retained.push_back(decoded);

        std::vector<uint8_t> output(wire.size());
        ASSERT_EQ(TLV_OK, tlv_copy_element(&decoded.element, &packed_format, output.data(),
                                           output.size(), &written));
        EXPECT_EQ(wire, output);
        ASSERT_EQ(TLV_OK, tlv_source_preserve(&decoded.source, &decoded.element, output.data(),
                                              output.size(), &written));
        EXPECT_EQ(wire, output);
        auto changed = decoded.element;
        changed.tag = TLV_TAG(2);
        EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_source_preserve(&decoded.source, &changed, output.data(),
                                                           output.size(), &written));
        if (length) {
            auto changed_value = value;
            changed_value[0] ^= 1;
            changed = decoded.element;
            changed.value.data = changed_value.data();
            EXPECT_EQ(TLV_ERR_INVALID_ARG,
                      tlv_source_preserve(&decoded.source, &changed, output.data(), output.size(),
                                          &written));
        }
    }
    // Returned structs have been copied and other identifiers decoded since their creation.
    const uint8_t other[] = {0xFE, 0};
    tlv_decoded_t last{};
    ASSERT_EQ(TLV_OK, tlv_format_decode(&packed_format, other, sizeof(other), &last, nullptr));
    EXPECT_TRUE(tlv_tag_equal(TLV_TAG(127), last.element.tag));
    for (const auto& decoded : retained) {
        EXPECT_TRUE(tlv_tag_equal(TLV_TAG(1), decoded.element.tag));
        EXPECT_EQ(&identifiers[1], decoded.element.tag.data);
        size_t written = 0;
        EXPECT_EQ(TLV_OK,
                  tlv_source_preserve(&decoded.source, &decoded.element, nullptr, 0, &written));
        EXPECT_EQ(decoded.source.size, written);
    }
}

TEST(Integration_Tlv_TransformedTag, BoundsAndRejectedCallbacksDoNotPublishResults) {
    tlv_element_t  too_large = {TLV_TAG(1), {nullptr, 512}};
    tlv_encoding_t sizes{};
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
              tlv_format_measure(&packed_format, &too_large, &sizes, nullptr));
    const uint8_t wire[] = {2, 1, 0xAA};
    for (size_t size : {size_t(1), size_t(2)}) {
        tlv_decoded_t decoded{};
        decoded.source.size = 99;
        EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
                  tlv_format_decode(&packed_format, wire, size, &decoded, nullptr));
        EXPECT_EQ(99u, decoded.source.size);
    }
    for (int variant = 0; variant < 5; ++variant) {
        SCOPED_TRACE(variant);
        tlv_format_t bad = packed_format;
        bad.context = &variant;
        bad.decode = [](const void* context, const uint8_t* data, size_t size,
                        tlv_decoded_t* result, tlv_format_error_t* error) {
            const auto rc = packed_decode(&identifiers, data, size, result, error);
            if (rc != TLV_OK) return rc;
            switch (*static_cast<const int*>(context)) {
                case 0: result->source.tag_binding = TLV_TAG_BINDING_SOURCE; break;
                case 1: result->element.tag.data = nullptr; break;
                case 2: result->source.tag = {size, 1, 1}; break;
                case 3: result->element.value.data = identifiers.data(); break;
                case 4: result->element.tag = {nullptr, 0}; break;
            }
            return TLV_OK;
        };
        tlv_decoded_t decoded{};
        decoded.source.size = 99;
        EXPECT_EQ(TLV_ERR_INVALID_ARG,
                  tlv_format_decode(&bad, wire, sizeof(wire), &decoded, nullptr));
        EXPECT_EQ(99u, decoded.source.size);
    }
}

TEST(Integration_Tlv_TransformedTag, WireEnvelopeIsIndependentOfSemanticTag) {
    const uint8_t wire[] = {2, 0};
    for (bool present : {false, true}) {
        tlv_format_t format = packed_format;
        format.context = &present;
        format.decode = [](const void* context, const uint8_t* data, size_t size,
                           tlv_decoded_t* result, tlv_format_error_t* error) {
            const auto rc = packed_decode(&identifiers, data, size, result, error);
            if (rc == TLV_OK)
                result->source.tag = {0, 2, *static_cast<const bool*>(context) ? 1 : 0};
            return rc;
        };
        tlv_decoded_t decoded{};
        ASSERT_EQ(TLV_OK, tlv_format_decode(&format, wire, sizeof(wire), &decoded, nullptr));
        EXPECT_TRUE(tlv_tag_equal(TLV_TAG(1), decoded.element.tag));
        EXPECT_EQ(present, decoded.source.tag.present != 0);
    }
}

TEST(Integration_Tlv_TransformedTag, EmptyFormatIdentifierRetainsPresence) {
    const uint8_t wire[] = {2, 0};
    tlv_format_t  format = packed_format;
    format.decode = [](const void* context, const uint8_t* data, size_t size, tlv_decoded_t* result,
                       tlv_format_error_t* error) {
        const auto rc = packed_decode(context, data, size, result, error);
        if (rc == TLV_OK) result->element.tag.size = 0;
        return rc;
    };
    tlv_decoded_t decoded{};
    ASSERT_EQ(TLV_OK, tlv_format_decode(&format, wire, sizeof(wire), &decoded, nullptr));
    auto element = decoded.element;
    element.tag = tlv_tag(&identifiers[0], 0);
    size_t written = 0;
    EXPECT_EQ(TLV_OK, tlv_source_preserve(&decoded.source, &element, nullptr, 0, &written));
    EXPECT_EQ(sizeof(wire), written);
    element.tag = tlv_tag(nullptr, 0);
    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              tlv_source_preserve(&decoded.source, &element, nullptr, 0, &written));
}

TEST(Integration_Tlv_TransformedTag, ReaderQueryAndSchemaUseCanonicalIdentity) {
    std::vector<uint8_t> wire(2 + 255 + 2 + 256, 0xAA);
    wire[0] = 2;
    wire[1] = 255;
    wire[257] = 3;
    wire[258] = 0;
    tlv_reader_t reader{};
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, wire.data(), wire.size(), &packed_format));
    tlv_element_t first{}, second{};
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &first));
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &second));
    EXPECT_TRUE(tlv_tag_equal(first.tag, second.tag));
    EXPECT_TRUE(tlv_reader_at_end(&reader));

    tlv_query_t query{};
    ASSERT_EQ(TLV_OK, tlv_query_parse("01", &query, nullptr));
    size_t count = 0;
    auto   visitor = [](const tlv_element_t* element, size_t, size_t, void* context) {
        EXPECT_TRUE(tlv_tag_equal(TLV_TAG(1), element->tag));
        ++*static_cast<size_t*>(context);
        return TLV_VISIT_CONTINUE;
    };
    EXPECT_EQ(TLV_OK, tlv_query_walk(wire.data(), wire.size(), &packed_format, &query, 0, 2,
                                     visitor, &count, nullptr));
    EXPECT_EQ(2u, count);
    tlv_structure_rule_t     rule{};
    const tlv_schema_entry_t field = {TLV_TAG(1), 255, 256, 0, nullptr, 0};
    rule.entry = &field;
    rule.min_occurs = rule.max_occurs = 2;
    tlv_structure_schema_t schema{};
    schema.rules = &rule;
    schema.count = 1;
    EXPECT_EQ(TLV_OK, tlv_schema_validate(wire.data(), wire.size(), &packed_format, &schema, 0, 2,
                                          nullptr));
}

#if OPENTLV_DOCUMENT
TEST(Integration_Tlv_TransformedTag, DocumentCopiesTagAndRegeneratesPackedLength) {
    const uint8_t          wire[] = {2, 1, 0xAA};
    tlv_document_options_t options{};
    ASSERT_EQ(TLV_OK, tlv_document_options_init(&options, &packed_format));
    tlv_document_t* raw = nullptr;
    ASSERT_EQ(TLV_OK, tlv_document_parse(wire, sizeof(wire), &options, &raw, nullptr));
    std::unique_ptr<tlv_document_t, decltype(&tlv_document_free)> doc(raw, tlv_document_free);
    auto* node = tlv_document_find(doc.get(), nullptr, TLV_TAG(1));
    ASSERT_NE(nullptr, node);
    EXPECT_TRUE(tlv_tag_equal(TLV_TAG(1), tlv_node_tag(node)));
    EXPECT_NE(&identifiers[1], tlv_node_tag(node).data);
    const std::vector<uint8_t> value(256, 0xBB);
    ASSERT_EQ(TLV_OK, tlv_node_set_value(node, value.data(), value.size()));
    std::vector<uint8_t> output(258);
    size_t               written = 0;
    ASSERT_EQ(TLV_OK, tlv_document_encode(doc.get(), output.data(), output.size(), &written));
    EXPECT_EQ(258u, written);
    EXPECT_EQ(3, output[0]);
    EXPECT_EQ(0, output[1]);
    tlv_decoded_t decoded{};
    ASSERT_EQ(TLV_OK,
              tlv_format_decode(&packed_format, output.data(), output.size(), &decoded, nullptr));
    EXPECT_TRUE(tlv_tag_equal(TLV_TAG(1), decoded.element.tag));
    EXPECT_EQ(0, std::memcmp(decoded.element.value.data, value.data(), value.size()));
}
#endif
} // namespace
