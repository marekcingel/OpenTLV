// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/builtins/nfc/type2.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#include <gtest/gtest.h>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace {
struct ExpectedElement {
    uint8_t              tag;
    std::vector<uint8_t> value;
    size_t               offset;
    size_t               header;
};

struct Vector {
    const char*                  name;
    std::vector<ExpectedElement> elements;
};

std::vector<uint8_t> ramp(size_t size) {
    std::vector<uint8_t> value(size);
    for (size_t i = 0; i < size; ++i) value[i] = static_cast<uint8_t>(i);
    return value;
}

// Expectations are semantic fixtures, independent of the binary input files.
const Vector vectors[] = {
    {"sample",
     {{0, {}, 0, 1}, {3, {0xD1, 1, 5, 0x54, 2, 0x65, 0x6E, 0x48, 0x69}, 1, 2}, {0xFE, {}, 12, 1}}},
    {"empty-ndef", {{3, {}, 0, 2}, {0xFE, {}, 2, 1}}},
    {"controls",
     {{1, {0xA0, 0x10, 0x44}, 0, 2},
      {2, {0xB0, 4, 4}, 5, 2},
      {3, {}, 10, 2},
      {0xFD, {0, 0xFE, 0xFF}, 12, 2},
      {0xFE, {}, 17, 1}}},
    {"short-254", {{0xFD, ramp(254), 0, 2}, {0xFE, {}, 256, 1}}},
    {"extended-255", {{0xFD, ramp(255), 0, 4}, {0xFE, {}, 259, 1}}},
    {"extended-256", {{0xFD, ramp(256), 0, 4}, {0xFE, {}, 260, 1}}},
    // Framing-only vector: generic Reader continues past Terminator and exposes reserved tags.
    {"framing-policy",
     {{0, {}, 0, 1}, {0xFE, {}, 1, 1}, {0, {}, 2, 1}, {0x2A, {}, 3, 2}, {0xFF, {0xA5}, 5, 2}}},
};

class NfcType2Vectors : public testing::TestWithParam<Vector> {
protected:
    std::vector<uint8_t> wire;

    void SetUp() override {
        const std::string path =
            std::string(OPENTLV_NFC_TYPE2_CORPUS) + "/" + GetParam().name + ".bin";
        std::ifstream input(path, std::ios::binary);
        ASSERT_TRUE(input.is_open()) << path;
        wire.assign(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
        ASSERT_FALSE(input.bad()) << path;
        ASSERT_FALSE(wire.empty()) << path;
    }
};

TEST_P(NfcType2Vectors, DecodeExpectedElementsAndSourceRanges) {
    tlv_reader_t reader{};
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, wire.data(), wire.size(), &tlv_format_nfc_type2));
    for (const auto& expected : GetParam().elements) {
        SCOPED_TRACE(expected.offset);
        EXPECT_EQ(expected.offset, tlv_reader_offset(&reader));
        tlv_element_t element{};
        tlv_source_t  source{};
        ASSERT_EQ(TLV_OK, tlv_reader_next_source_diag(&reader, &element, &source, nullptr));
        ASSERT_EQ(1u, element.tag.size);
        EXPECT_EQ(expected.tag, element.tag.data[0]);
        ASSERT_EQ(expected.value.size(), element.value.size);
        EXPECT_EQ(expected.value, std::vector<uint8_t>(element.value.data,
                                                       element.value.data + element.value.size));
        EXPECT_EQ(wire.data() + expected.offset, source.data);
        EXPECT_EQ(source.data, element.tag.data);
        EXPECT_EQ(source.data + expected.header, element.value.data);
        EXPECT_EQ(expected.header + expected.value.size(), source.size);
        EXPECT_EQ(0u, source.tag.offset);
        EXPECT_EQ(1u, source.tag.size);
        EXPECT_EQ(expected.header, source.header.size);
        EXPECT_EQ(expected.header != 1, !!source.length.present);
        if (source.length.present) {
            EXPECT_EQ(1u, source.length.offset);
            EXPECT_EQ(expected.header - 1, source.length.size);
        }
        EXPECT_EQ(expected.header, source.value.offset);
        EXPECT_EQ(expected.value.size(), source.value.size);
    }
    EXPECT_EQ(wire.size(), tlv_reader_offset(&reader));
    tlv_element_t element{};
    EXPECT_EQ(TLV_ERR_END_OF_BUFFER, tlv_reader_next(&reader, &element));
}

TEST_P(NfcType2Vectors, EncodeIndependentElementsMatchesDump) {
    std::vector<uint8_t> output(wire.size());
    tlv_writer_t         writer{};
    ASSERT_EQ(TLV_OK,
              tlv_writer_init(&writer, output.data(), output.size(), &tlv_format_nfc_type2));
    for (const auto& expected : GetParam().elements) {
        const tlv_element_t element{tlv_tag(&expected.tag, 1),
                                    {expected.value.data(), expected.value.size()}};
        ASSERT_EQ(TLV_OK, tlv_writer_copy_element(&writer, &element));
    }
    EXPECT_EQ(wire.size(), tlv_writer_size(&writer));
    EXPECT_EQ(wire, output);
}

TEST_P(NfcType2Vectors, ReaderElementWriterRoundTripMatchesDump) {
    std::vector<uint8_t> output(wire.size());
    tlv_reader_t         reader{};
    tlv_writer_t         writer{};
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, wire.data(), wire.size(), &tlv_format_nfc_type2));
    ASSERT_EQ(TLV_OK,
              tlv_writer_init(&writer, output.data(), output.size(), &tlv_format_nfc_type2));
    size_t count = 0;
    while (!tlv_reader_at_end(&reader)) {
        tlv_element_t element{};
        ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
        // Regenerate framing from Element; no raw copying or source preservation.
        ASSERT_EQ(TLV_OK, tlv_writer_copy_element(&writer, &element));
        ++count;
    }
    EXPECT_EQ(GetParam().elements.size(), count);
    EXPECT_EQ(wire.size(), tlv_writer_size(&writer));
    EXPECT_EQ(wire, output);
}

INSTANTIATE_TEST_SUITE_P(Integration_Tlv, NfcType2Vectors, testing::ValuesIn(vectors));

TEST(Integration_Tlv_NfcType2, RejectsInvalidCorpusDumps) {
    const struct {
        const char*  name;
        tlv_result_t result;
    } cases[] = {{"nonminimal-extended", TLV_ERR_INVALID_LENGTH},
                 {"reserved-length", TLV_ERR_INVALID_LENGTH},
                 {"missing-length", TLV_ERR_BUFFER_TOO_SHORT},
                 {"truncated-extended", TLV_ERR_BUFFER_TOO_SHORT},
                 {"truncated-value", TLV_ERR_BUFFER_TOO_SHORT}};
    for (const auto& test : cases) {
        SCOPED_TRACE(test.name);
        const std::string path =
            std::string(OPENTLV_NFC_TYPE2_CORPUS) + "/invalid/" + test.name + ".bin";
        std::ifstream input(path, std::ios::binary);
        ASSERT_TRUE(input.is_open()) << path;
        const std::vector<uint8_t> wire{std::istreambuf_iterator<char>(input),
                                        std::istreambuf_iterator<char>()};
        ASSERT_FALSE(input.bad());
        tlv_reader_t reader{};
        ASSERT_EQ(TLV_OK,
                  tlv_reader_init(&reader, wire.data(), wire.size(), &tlv_format_nfc_type2));
        tlv_element_t element{};
        EXPECT_EQ(test.result, tlv_reader_next(&reader, &element));
        EXPECT_EQ(0u, tlv_reader_offset(&reader));
    }
}
} // namespace
