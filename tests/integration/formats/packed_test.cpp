// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/formats/packed.h"
#include "tlv/reader/reader.h"
#include "tlv/query/query.h"
#include "tlv/config.h"
#if OPENTLV_DOCUMENT
#include "tlv/document/document.h"
#endif
#include <gtest/gtest.h>
#include <cstring>
#include <memory>

TEST(Integration_Tlv_Packed, ReaderQueryAndOwnedDocumentUseCanonicalTags) {
    static const uint8_t      tags[] = {0, 1, 2, 3};
    const tlv_packed_layout_t layout = {1,
                                        {1, 6, 2, TLV_BYTE_ORDER_LITTLE_ENDIAN},
                                        {1, 0, 6, TLV_BYTE_ORDER_LITTLE_ENDIAN},
                                        TLV_LENGTH_SCOPE_TAG_AND_VALUE,
                                        tags,
                                        1,
                                        sizeof(tags)};
    const tlv_format_t format = {&layout, tlv_packed_decode, tlv_packed_measure, tlv_packed_encode,
                                 nullptr};
    const uint8_t      wire[] = {0x42, 0xAA, 0x83, 0xBB, 0xCC};
    tlv_reader_t       reader{};
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, wire, sizeof(wire), &format));
    tlv_element_t first{}, second{};
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &first));
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &second));
    EXPECT_TRUE(tlv_reader_at_end(&reader));
    EXPECT_EQ(tags + 1, first.tag.data);
    EXPECT_EQ(tags + 2, second.tag.data);
    EXPECT_EQ(wire + 3, second.value.data);
    tlv_query_t query{};
    ASSERT_EQ(TLV_OK, tlv_query_parse("02", &query, nullptr));
    size_t matches = 0;
    auto   visit = [](const tlv_element_t* element, size_t, size_t offset, void* context) {
        EXPECT_EQ(2, element->tag.data[0]);
        EXPECT_EQ(2u, offset);
        ++*static_cast<size_t*>(context);
        return TLV_VISIT_CONTINUE;
    };
    ASSERT_EQ(TLV_OK, tlv_query_visit_buffer(wire, sizeof(wire), &format, &query, 0, 2, visit,
                                             &matches, nullptr));
    EXPECT_EQ(1u, matches);
#if OPENTLV_DOCUMENT
    tlv_document_options_t options{};
    ASSERT_EQ(TLV_OK, tlv_document_options_init(&options, &format));
    tlv_document_t* raw = nullptr;
    ASSERT_EQ(TLV_OK, tlv_document_parse(wire, sizeof(wire), &options, &raw, nullptr));
    std::unique_ptr<tlv_document_t, decltype(&tlv_document_free)> doc(raw, tlv_document_free);
    tlv_node_t*                                                   node = nullptr;
    ASSERT_EQ(TLV_OK, tlv_document_find_path(doc.get(), &query, &node));
    ASSERT_NE(nullptr, node);
    uint8_t output[sizeof(wire)]{};
    size_t  written = 0;
    ASSERT_EQ(TLV_OK, tlv_document_encode(doc.get(), output, sizeof(output), &written));
    EXPECT_EQ(sizeof(wire), written);
    EXPECT_EQ(0, std::memcmp(wire, output, written));
    const uint8_t replacement[] = {0xDD};
    ASSERT_EQ(TLV_OK, tlv_node_set_value(node, replacement, sizeof(replacement)));
    ASSERT_EQ(TLV_OK, tlv_document_encode(doc.get(), output, sizeof(output), &written));
    const uint8_t expected[] = {0x42, 0xAA, 0x82, 0xDD};
    EXPECT_EQ(sizeof(expected), written);
    EXPECT_EQ(0, std::memcmp(expected, output, sizeof(expected)));
#endif
}
