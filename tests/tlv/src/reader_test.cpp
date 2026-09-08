#include "tlv/formats/default.h"
#include "tlv/formats/fixed_1byte.h"
#include "tlv/reader/reader.h"
#include <gtest/gtest.h>
#include <limits>

TEST(Reader, ReadsOnlyFirstElementAndBorrowsValue) {
    uint8_t data[] = {1, 2, 0xAB, 0xCD, 2, 0xFF};
    tlv_view_t view{};
    size_t consumed = 0;
    ASSERT_EQ(TLV_OK, tlv_read(data, sizeof(data), &tlv_format_fixed_1byte, &view, &consumed));
    EXPECT_EQ(1u, view.tag.size);
    EXPECT_EQ(1u, view.tag.data[0]);
    EXPECT_EQ(data + 2, view.value.data);
    EXPECT_EQ(2u, view.value.length);
    EXPECT_EQ(4u, consumed);
    data[2] = 0xEF;
    EXPECT_EQ(0xEF, view.value.data[0]);
}

TEST(Reader, EmptyValueAndBerLength) {
    const uint8_t data[] = {0x42, 0x82, 0, 0};
    tlv_view_t view{};
    size_t consumed = 0;
    ASSERT_EQ(TLV_OK, tlv_read(data, sizeof(data), &tlv_format_default, &view, &consumed));
    EXPECT_EQ(data + sizeof(data), view.value.data);
    EXPECT_EQ(0u, view.value.length);
    EXPECT_EQ(sizeof(data), consumed);
}

namespace {
struct Config {
    size_t tag_bytes = 2;
    size_t length_bytes = 2;
    size_t value_bytes = 2;
    uint8_t tag_size = 1;
    tlv_result_t tag_error = TLV_OK;
    tlv_result_t length_error = TLV_OK;
};

tlv_format_t make_format(const Config* config) {
    tlv_format_t format{};
    format.context = config;
    format.read_tag = [](const void* ctx, const uint8_t*, size_t size,
                         tlv_tag_t* tag, size_t* used) {
        const auto& c = *static_cast<const Config*>(ctx);
        if (c.tag_error != TLV_OK) return c.tag_error;
        if (size < 2) return TLV_ERR_BUFFER_TOO_SHORT;
        *tag = tlv_tag_t{{0x42}, c.tag_size};
        *used = c.tag_bytes;
        return TLV_OK;
    };
    format.read_length = [](const void* ctx, const uint8_t*, size_t size,
                            size_t* length, size_t* used) {
        const auto& c = *static_cast<const Config*>(ctx);
        if (c.length_error != TLV_OK) return c.length_error;
        if (size < c.length_bytes) return TLV_ERR_BUFFER_TOO_SHORT;
        *length = c.value_bytes;
        *used = c.length_bytes;
        return TLV_OK;
    };
    return format;
}

void expect_failure(const uint8_t* data, size_t size, const tlv_format_t* format,
                    tlv_result_t error) {
    tlv_view_t view = {tlv_tag_t{{0xEE}, 1}, {data, 42}};
    size_t consumed = 99;
    EXPECT_EQ(error, tlv_read(data, size, format, &view, &consumed));
    EXPECT_EQ(99u, consumed);
    EXPECT_EQ(1u, view.tag.size);
    EXPECT_EQ(0xEE, view.tag.data[0]);
    EXPECT_EQ(data, view.value.data);
    EXPECT_EQ(42u, view.value.length);
}
}

TEST(Reader, CustomFormatAndEveryTruncatedPrefix) {
    const uint8_t data[6] = {};
    Config config;
    const auto format = make_format(&config);
    for (size_t size = 0; size < sizeof(data); ++size) {
        SCOPED_TRACE(size);
        expect_failure(data, size, &format,
                       size ? TLV_ERR_BUFFER_TOO_SHORT : TLV_ERR_END_OF_BUFFER);
    }
    tlv_view_t view{};
    size_t consumed = 0;
    ASSERT_EQ(TLV_OK, tlv_read(data, sizeof(data), &format, &view, &consumed));
    EXPECT_EQ(0x42, view.tag.data[0]);
    EXPECT_EQ(data + 4, view.value.data);
    EXPECT_EQ(2u, view.value.length);
    EXPECT_EQ(6u, consumed);
    config.length_bytes = 0;
    ASSERT_EQ(TLV_OK, tlv_read(data, sizeof(data), &format, &view, &consumed));
    EXPECT_EQ(data + 2, view.value.data);
    EXPECT_EQ(4u, consumed);
}

TEST(Reader, RejectsInvalidArguments) {
    const uint8_t data[] = {1, 0};
    auto format = tlv_format_fixed_1byte;
    tlv_view_t view{};
    size_t consumed = 0;
    expect_failure(nullptr, 0, &format, TLV_ERR_END_OF_BUFFER);
    expect_failure(nullptr, 1, &format, TLV_ERR_NULL_ARG);
    expect_failure(data, sizeof(data), nullptr, TLV_ERR_NULL_ARG);
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_read(data, sizeof(data), &format, nullptr, &consumed));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_read(data, sizeof(data), &format, &view, nullptr));
    format.read_tag = nullptr;
    expect_failure(data, sizeof(data), &format, TLV_ERR_NULL_ARG);
    format = tlv_format_fixed_1byte;
    format.read_length = nullptr;
    expect_failure(data, sizeof(data), &format, TLV_ERR_NULL_ARG);
}

TEST(Reader, RejectsInvalidCallbackResultsAndPropagatesErrors) {
    const uint8_t data[6] = {};
    Config config;
    auto format = make_format(&config);
    config.tag_bytes = 0;
    expect_failure(data, sizeof(data), &format, TLV_ERR_INVALID_TAG);
    config.tag_bytes = std::numeric_limits<size_t>::max();
    expect_failure(data, sizeof(data), &format, TLV_ERR_INVALID_TAG);
    config = Config{};
    config.tag_size = 0;
    expect_failure(data, sizeof(data), &format, TLV_ERR_INVALID_TAG);
#if TLV_TAG_MAX_SIZE < 255
    config.tag_size = TLV_TAG_MAX_SIZE + 1;
    expect_failure(data, sizeof(data), &format, TLV_ERR_INVALID_TAG);
#endif
    config = Config{};
    config.value_bytes = std::numeric_limits<size_t>::max();
    expect_failure(data, sizeof(data), &format, TLV_ERR_BUFFER_TOO_SHORT);
    format.read_length = [](const void*, const uint8_t*, size_t, size_t*, size_t* used) {
        *used = std::numeric_limits<size_t>::max();
        return TLV_OK;
    };
    expect_failure(data, sizeof(data), &format, TLV_ERR_INVALID_LENGTH);
    format = make_format(&config);
    config.tag_error = TLV_ERR_INVALID_TAG;
    expect_failure(data, sizeof(data), &format, TLV_ERR_INVALID_TAG);
    config = Config{};
    config.length_error = TLV_ERR_INVALID_LENGTH;
    expect_failure(data, sizeof(data), &format, TLV_ERR_INVALID_LENGTH);
}

TEST(Reader, DetectsTruncatedBerLengthAndValue) {
    const uint8_t data[] = {1, 0x82, 0, 2, 0xAB, 0xCD};
    for (size_t size = 1; size < sizeof(data); ++size)
        expect_failure(data, size, &tlv_format_default, TLV_ERR_BUFFER_TOO_SHORT);
    const uint8_t invalid[] = {1, 0x80};
    expect_failure(invalid, sizeof(invalid), &tlv_format_default, TLV_ERR_INVALID_LENGTH);
}
