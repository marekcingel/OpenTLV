// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/builtins/nfc/type2.h"
#include "tlv/config.h"
#include "tlv/query/query.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#if OPENTLV_DOCUMENT
#include "tlv/document/document.h"
#endif
#include <gtest/gtest.h>
#include <cstring>
#include <memory>
#include <vector>

TEST(Integration_Tlv_NfcType2, ReaderWriterExposeNullAndContinuePastTerminator) {
    const uint8_t wire[] = {0, 3, 1, 1, 255, 0, 254, 0, 42, 1, 7};
    const uint8_t codes[] = {0, 3, 255, 254, 0, 42};
    const size_t  lengths[] = {0, 1, 0, 0, 0, 1};
    uint8_t       output[sizeof(wire)] = {};
    tlv_reader_t  reader{};
    tlv_writer_t  writer{};
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, wire, sizeof(wire), &tlv_format_nfc_type2));
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, output, sizeof(output), &tlv_format_nfc_type2));
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
                  tlv_read_source_diag(wire + offset, sizeof(wire) - offset, &tlv_format_nfc_type2,
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

TEST(Integration_Tlv_NfcType2, QueryAndDocumentPreserveControlElementsAndOffsets) {
    // The element after Terminator is intentional: the caller controls stopping.
    const uint8_t                          wire[] = {0, 3, 1, 3, 254, 0, 0xE0, 0};
    const char*                            paths[] = {"00", "03", "FE", "E0"};
    const std::vector<std::vector<size_t>> offsets = {{0, 5}, {1}, {4}, {6}};
    const size_t                           lengths[] = {0, 1, 0, 0};
#if OPENTLV_DOCUMENT
    tlv_document_options_t options{};
    ASSERT_EQ(TLV_OK, tlv_document_options_init(&options, &tlv_format_nfc_type2));
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
        ASSERT_EQ(TLV_OK, tlv_query_visit_buffer(wire, sizeof(wire), &tlv_format_nfc_type2, &query,
                                                 0, 5, visit, &matches, nullptr));
        EXPECT_EQ(offsets[i], matches);
#if OPENTLV_DOCUMENT
        tlv_node_t* node = nullptr;
        ASSERT_EQ(TLV_OK, tlv_document_find_path(doc.get(), &query, &node));
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
}
