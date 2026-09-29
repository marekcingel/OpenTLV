#include "tlv/codec/text.h"
#include <gtest/gtest.h>
#include <cstring>

TEST(Unit_Tlv_Text, FixedWidthZeroPaddingAndBorrowedView) {
    const tlv_text_codec_config_t config = {TLV_TEXT_ASCII_ALNUM, 6, 6, 1};
    const tlv_codec_t             codec = tlv_text_codec(&config);
    const uint8_t                 expected[] = {'A', 'b', '0', 0, 0, 0};
    tlv_value_t                   text = {expected, 3};
    uint8_t                       wire[6] = {};
    size_t                        written = 99;
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_encode(&codec, &text, sizeof(text), wire, 6, &written));
    EXPECT_EQ(6u, written);
    EXPECT_EQ(0, std::memcmp(wire, expected, 6));
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_decode(&codec, wire, 6, &text, sizeof(text)));
    EXPECT_EQ(wire, text.data);
    EXPECT_EQ(3u, text.size);
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_encode(&codec, &text, sizeof(text), nullptr, 0, &written));
    EXPECT_EQ(6u, written);
}

TEST(Unit_Tlv_Text, ExplicitAlphabetsRejectControlNonAsciiAndEmbeddedPadding) {
    tlv_text_codec_config_t config = {TLV_TEXT_ASCII_PRINTABLE, 1, 3, 0};
    for (unsigned byte = 0; byte <= 255; ++byte) {
        const uint8_t data = static_cast<uint8_t>(byte);
        tlv_value_t   output = {nullptr, 999};
        const bool    printable = byte >= 0x20 && byte <= 0x7E;
        EXPECT_EQ(printable ? TLV_CODEC_OK : TLV_CODEC_ERR_INVALID_VALUE,
                  tlv_text_decode(&config, &data, 1, &output, sizeof(output)));
        if (!printable) EXPECT_EQ(999u, output.size);
    }
    config = {TLV_TEXT_ASCII_ALNUM, 1, 3, 1};
    const uint8_t data[][3] = {{'A', 0, 'B'}, {'A', ' ', 'B'}, {'A', '-', 'B'}};
    tlv_value_t   output = {nullptr, 999};
    for (const auto& bytes : data)
        EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
                  tlv_text_decode(&config, bytes, sizeof(bytes), &output, sizeof(output)));
    EXPECT_EQ(nullptr, output.data);
    EXPECT_EQ(999u, output.size);
}

TEST(Unit_Tlv_Text, BoundsEmptyTextAndFailuresPreserveOutput) {
    tlv_text_codec_config_t config = {TLV_TEXT_ASCII_PRINTABLE, 2, 2, 0};
    const uint8_t           input[] = {'A', '!'};
    tlv_value_t             text = {input, 1};
    size_t                  written = 9;
    uint8_t                 output[] = {0xA5, 0xA5};
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_text_encode(&config, &text, sizeof(text), output, 2, &written));
    EXPECT_EQ(0u, written);
    text.size = 2;
    EXPECT_EQ(TLV_CODEC_ERR_BUFFER_TOO_SHORT,
              tlv_text_encode(&config, &text, sizeof(text), output, 1, &written));
    EXPECT_EQ(0u, written);
    EXPECT_EQ(0xA5, output[0]);
    EXPECT_EQ(0xA5, output[1]);
    tlv_value_t decoded = {nullptr, 99};
    EXPECT_EQ(TLV_CODEC_ERR_BUFFER_TOO_SHORT,
              tlv_text_decode(&config, input, 2, &decoded, sizeof(decoded) - 1));
    EXPECT_EQ(99u, decoded.size);
    config.zero_padding = 1;
    text = {nullptr, 0};
    ASSERT_EQ(TLV_CODEC_OK, tlv_text_encode(&config, &text, sizeof(text), output, 2, &written));
    ASSERT_EQ(TLV_CODEC_OK, tlv_text_decode(&config, output, 2, &decoded, sizeof(decoded)));
    EXPECT_EQ(0u, decoded.size);
    config.zero_padding = 2;
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_text_encode(&config, &text, sizeof(text), nullptr, 0, &written));
    config = {TLV_TEXT_ASCII_PRINTABLE, 0, 0, 0};
    EXPECT_EQ(TLV_CODEC_OK, tlv_text_decode(&config, nullptr, 0, &decoded, sizeof(decoded)));
    EXPECT_EQ(nullptr, decoded.data);
    EXPECT_EQ(0u, decoded.size);
    config.min_length = 1;
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_text_decode(&config, nullptr, 0, &decoded, sizeof(decoded)));
    EXPECT_EQ(TLV_CODEC_ERR_NULL_ARG,
              tlv_text_encode(nullptr, &text, sizeof(text), nullptr, 0, &written));
}

TEST(Unit_Tlv_Text, RejectsUnaddressableLogicalLengthBeforeReadingInput) {
    if (sizeof(size_t) >= sizeof(tlv_size_t)) return;
    const tlv_text_codec_config_t config = {TLV_TEXT_ASCII_PRINTABLE, 0, SIZE_MAX, 0};
    const uint8_t                 byte = 'A';
    const tlv_value_t             text = {&byte, static_cast<tlv_size_t>(SIZE_MAX) + 1};
    size_t                        written = 99;
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_text_encode(&config, &text, sizeof(text), nullptr, 0, &written));
    EXPECT_EQ(0u, written);
}
