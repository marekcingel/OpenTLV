#include "controlled_format.h"
#include "tlv/reader/tree.h"
#include "tlv/writer/tree.h"
#include "tlv/config.h"
#if OPENTLV_FORMAT_BER
#include "tlv/builtins/asn1/ber.h"
#endif
#if OPENTLV_FORMAT_CER
#include "tlv/builtins/asn1/cer.h"
#endif
#include <gtest/gtest.h>
#include <cstring>
#include <vector>

namespace {
int constructed(const void*, const tlv_tag_t* tag) {
    return tag->size == 1 && tag->data[0] >= 0x80;
}
const tlv_format_t format = {&controlled::format_layout, tlv_fields_decode, tlv_fields_measure,
                             tlv_fields_encode, constructed};
} // namespace

TEST(Integration_Tlv_TreeWriter, ReaderTransformWriterWithoutDocument) {
    const uint8_t    input[] = {0xE1, 9, 1, 1, 0xAA, 0xE2, 4, 2, 2, 0xBB, 0xCC, 0xE3, 0, 3, 0};
    uint8_t          output[64]{}, scratch[64]{};
    tlv_tree_frame_t read_frames[4]{};
    tlv_tree_writer_frame_t write_frames[4]{};
    tlv_tree_reader_t       reader{};
    tlv_tree_writer_t       writer{};
    ASSERT_EQ(TLV_OK, tlv_tree_reader_init(&reader, input, sizeof(input), &format, read_frames, 4,
                                           4, SIZE_MAX));
    ASSERT_EQ(TLV_OK, tlv_tree_writer_init(&writer, output, sizeof(output), &format, write_frames,
                                           4, scratch, sizeof(scratch), 4, SIZE_MAX));
    tlv_tree_item_t item{};
    size_t          open = 0;
    tlv_result_t    rc;
    const uint8_t   replacement[] = {0x11, 0x22, 0x33};
    while ((rc = tlv_tree_reader_next(&reader, &item)) == TLV_OK) {
        while (open > item.depth) {
            ASSERT_EQ(TLV_OK, tlv_tree_writer_end(&writer));
            --open;
        }
        if (item.element.tag.data[0] == 0xE2) {
            // Copy a complete subtree without visiting/writing descendants twice.
            ASSERT_EQ(TLV_OK, tlv_tree_writer_write_element(&writer, &item.element));
            ASSERT_EQ(TLV_OK, tlv_tree_reader_skip_subtree(&reader));
        } else if (item.constructed) {
            ASSERT_EQ(TLV_OK, tlv_tree_writer_begin(&writer, item.element.tag));
            ++open;
        } else {
            if (item.element.tag.data[0] == 1)
                item.element.value = {replacement, sizeof(replacement)};
            ASSERT_EQ(TLV_OK, tlv_tree_writer_write_element(&writer, &item.element));
        }
    }
    ASSERT_EQ(TLV_ERR_END_OF_BUFFER, rc);
    while (open) {
        ASSERT_EQ(TLV_OK, tlv_tree_writer_end(&writer));
        --open;
    }
    ASSERT_EQ(TLV_OK, tlv_tree_writer_finish(&writer));
    const uint8_t expected[] = {0xE1, 11, 1,    3,    0x11, 0x22, 0x33, 0xE2, 4,
                                2,    2,  0xBB, 0xCC, 0xE3, 0,    3,    0};
    ASSERT_EQ(sizeof(expected), tlv_tree_writer_size(&writer));
    EXPECT_EQ(0, std::memcmp(output, expected, sizeof(expected)));
}

#if OPENTLV_FORMAT_BER
TEST(Integration_Tlv_TreeWriter, DefiniteLengthBoundariesAndIndefiniteTrailers) {
    const auto                       parent = TLV_TAG(0xE1);
    const auto                       tag = TLV_TAG(0x04);
    std::vector<const tlv_format_t*> formats = {&tlv_format_ber};
#if OPENTLV_FORMAT_CER
    formats.push_back(&tlv_format_cer);
#endif
    for (const auto* wire_format : formats) {
        // Child encodings have exactly 127, 128, 255 and 256 bytes.
        for (size_t length : {125u, 126u, 252u, 253u}) {
            SCOPED_TRACE(length);
            std::vector<uint8_t> value(length, 0xAB);
            const tlv_element_t  leaf = {tag, {value.data(), length}};
            uint8_t output[512]{}, scratch[512]{}, reference_value[512]{}, reference[512]{};
            size_t  value_size = 0, reference_size = 0;
            ASSERT_EQ(TLV_OK, tlv_write_element(reference_value, sizeof(reference_value),
                                                wire_format, &leaf, &value_size));
            const tlv_element_t complete = {parent, {reference_value, value_size}};
            ASSERT_EQ(TLV_OK, tlv_write_element(reference, sizeof(reference), wire_format,
                                                &complete, &reference_size));
            tlv_tree_writer_frame_t frame{};
            tlv_tree_writer_t       writer{};
            ASSERT_EQ(TLV_OK, tlv_tree_writer_init(&writer, output, reference_size, wire_format,
                                                   &frame, 1, scratch, value_size, 1, SIZE_MAX));
            ASSERT_EQ(TLV_OK, tlv_tree_writer_begin(&writer, parent));
            ASSERT_EQ(TLV_OK, tlv_tree_writer_write_element(&writer, &leaf));
            ASSERT_EQ(TLV_OK, tlv_tree_writer_end(&writer));
            ASSERT_EQ(reference_size, tlv_tree_writer_size(&writer));
            EXPECT_EQ(0, std::memcmp(output, reference, reference_size));
            tlv_decoded_t decoded{};
            ASSERT_EQ(TLV_OK,
                      tlv_format_decode(wire_format, output, reference_size, &decoded, nullptr));
            EXPECT_EQ(value_size, decoded.element.value.size);
            EXPECT_EQ(0, std::memcmp(decoded.element.value.data, reference_value, value_size));
        }
    }
}

TEST(Integration_Tlv_TreeWriter, BerIndefiniteKeepsFormatPolicyAndNestedTerminators) {
    uint8_t                 data[8]{}, scratch[4]{};
    tlv_tree_writer_frame_t frames[2]{};
    tlv_tree_writer_t       writer{};
    ASSERT_EQ(TLV_OK, tlv_tree_writer_init(&writer, data, sizeof(data), &tlv_format_ber_indefinite,
                                           frames, 2, scratch, sizeof(scratch), 2, SIZE_MAX));
    ASSERT_EQ(TLV_OK, tlv_tree_writer_begin(&writer, TLV_TAG(0xE1)));
    const tlv_element_t primitive = {TLV_TAG(0x04), {nullptr, 0}};
    // This preset only writes constructed indefinite elements, unlike CER.
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_tree_writer_write_element(&writer, &primitive));
    ASSERT_EQ(TLV_OK, tlv_tree_writer_begin(&writer, TLV_TAG(0xE2)));
    ASSERT_EQ(TLV_OK, tlv_tree_writer_end(&writer));
    ASSERT_EQ(TLV_OK, tlv_tree_writer_end(&writer));
    const uint8_t expected[] = {0xE1, 0x80, 0xE2, 0x80, 0, 0, 0, 0};
    ASSERT_EQ(sizeof(expected), tlv_tree_writer_size(&writer));
    EXPECT_EQ(0, std::memcmp(data, expected, sizeof(expected)));
    tlv_decoded_t decoded{};
    EXPECT_EQ(TLV_OK, tlv_format_decode(&tlv_format_ber, data, sizeof(data), &decoded, nullptr));
}
#endif
