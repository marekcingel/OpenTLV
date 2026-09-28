#include "tlv/builtins/lldp/lldp.h"
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
        EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_reader_next_diag(&reader, &element, &error));
        EXPECT_EQ(0u, reader.pos);
        EXPECT_TRUE(tlv_tag_equal(TLV_TAG(42), element.tag));
        EXPECT_EQ(size == 1 ? TLV_READER_OP_HEADER : TLV_READER_OP_VALUE, error.operation);
        EXPECT_EQ(size == 1 ? 0u : 2u, error.diagnostic.offset);
        if (size > 1) {
            EXPECT_TRUE(error.has_declared_length);
            EXPECT_EQ(256u, error.declared_length);
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
    EXPECT_EQ(TLV_OK, tlv_query_walk(wire, sizeof(wire), &tlv_format_lldp, &query, 0, 2, visit,
                                     &matches, nullptr));
    EXPECT_EQ(1u, matches);
#if OPENTLV_DOCUMENT
    tlv_document_options_t options{};
    ASSERT_EQ(TLV_OK, tlv_document_options_init(&options, &tlv_format_lldp));
    tlv_document_t* raw = nullptr;
    ASSERT_EQ(TLV_OK, tlv_document_parse(wire, sizeof(wire), &options, &raw, nullptr));
    std::unique_ptr<tlv_document_t, decltype(&tlv_document_free)> doc(raw, tlv_document_free);
    EXPECT_NE(nullptr, tlv_document_find_path(doc.get(), &query));
    uint8_t output[sizeof(wire)]{};
    size_t  written = 0;
    ASSERT_EQ(TLV_OK, tlv_document_encode(doc.get(), output, sizeof(output), &written));
    EXPECT_EQ(sizeof(wire), written);
    EXPECT_EQ(0, std::memcmp(wire, output, sizeof(wire)));
#endif
}
