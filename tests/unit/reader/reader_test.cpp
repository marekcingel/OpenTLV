#include "controlled_format.h"
#include "tlv/reader/reader.h"
#include <gtest/gtest.h>
#include <cstring>
#include <limits>

TEST(Unit_Tlv_Reader, ReadsOnlyFirstElementAndBorrowsValue) {
    uint8_t    data[] = {1, 2, 0xAB, 0xCD, 2, 0xFF};
    tlv_view_t view{};
    size_t     consumed = 0;
    ASSERT_EQ(TLV_OK, tlv_read(data, sizeof(data), &controlled::reader, &view, &consumed));
    EXPECT_EQ(1u, view.tag.size);
    EXPECT_EQ(1u, view.tag.data[0]);
    EXPECT_EQ(data + 2, view.value.data);
    EXPECT_EQ(2u, view.value.length);
    EXPECT_EQ(4u, consumed);
    data[2] = 0xEF;
    EXPECT_EQ(0xEF, view.value.data[0]);
}

namespace {
struct Config {
    size_t       tag_bytes = 2;
    size_t       length_bytes = 2;
    size_t       value_bytes = 2;
    size_t       tag_size = 1;
    bool         tag_without_data = false;
    tlv_result_t tag_error = TLV_OK;
    tlv_result_t length_error = TLV_OK;
};

tlv_reader_format_t make_format(const Config* config) {
    tlv_reader_format_t format{};
    format.context = config;
    format.read_tag = [](const void* ctx, const uint8_t* data, size_t size, tlv_tag_t* tag,
                         size_t* used) {
        const auto& c = *static_cast<const Config*>(ctx);
        if (c.tag_error != TLV_OK) return c.tag_error;
        if (size < 2) return TLV_ERR_BUFFER_TOO_SHORT;
        *tag = tlv_tag(c.tag_without_data || !c.tag_size ? nullptr : data, c.tag_size);
        *used = c.tag_bytes;
        return TLV_OK;
    };
    format.read_length = [](const void* ctx, const uint8_t*, size_t size, size_t* length,
                            size_t* used) {
        const auto& c = *static_cast<const Config*>(ctx);
        if (c.length_error != TLV_OK) return c.length_error;
        if (size < c.length_bytes) return TLV_ERR_BUFFER_TOO_SHORT;
        *length = c.value_bytes;
        *used = c.length_bytes;
        return TLV_OK;
    };
    return format;
}

void expect_failure(const uint8_t* data, size_t size, const tlv_reader_format_t* format,
                    tlv_result_t error) {
    tlv_view_t view = {TLV_TAG(0xEE), {data, 42}};
    size_t     consumed = 99;
    EXPECT_EQ(error, tlv_read(data, size, format, &view, &consumed));
    EXPECT_EQ(99u, consumed);
    EXPECT_EQ(1u, view.tag.size);
    EXPECT_EQ(0xEE, view.tag.data[0]);
    EXPECT_EQ(data, view.value.data);
    EXPECT_EQ(42u, view.value.length);
}
} // namespace

TEST(Unit_Tlv_Reader, CustomFormatAndEveryTruncatedPrefix) {
    const uint8_t data[6] = {};
    Config        config;
    const auto    format = make_format(&config);
    for (size_t size = 0; size < sizeof(data); ++size) {
        SCOPED_TRACE(size);
        expect_failure(data, size, &format,
                       size ? TLV_ERR_BUFFER_TOO_SHORT : TLV_ERR_END_OF_BUFFER);
    }
    tlv_view_t view{};
    size_t     consumed = 0;
    ASSERT_EQ(TLV_OK, tlv_read(data, sizeof(data), &format, &view, &consumed));
    EXPECT_EQ(data, view.tag.data);
    EXPECT_EQ(data + 4, view.value.data);
    EXPECT_EQ(2u, view.value.length);
    EXPECT_EQ(6u, consumed);
    config.length_bytes = 0;
    ASSERT_EQ(TLV_OK, tlv_read(data, sizeof(data), &format, &view, &consumed));
    EXPECT_EQ(data + 2, view.value.data);
    EXPECT_EQ(4u, consumed);
}

TEST(Unit_Tlv_Reader, RejectsInvalidArguments) {
    const uint8_t data[] = {1, 0};
    auto          format = controlled::reader;
    tlv_view_t    view{};
    size_t        consumed = 0;
    expect_failure(nullptr, 0, &format, TLV_ERR_END_OF_BUFFER);
    expect_failure(nullptr, 1, &format, TLV_ERR_NULL_ARG);
    expect_failure(data, sizeof(data), nullptr, TLV_ERR_NULL_ARG);
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_read(data, sizeof(data), &format, nullptr, &consumed));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_read(data, sizeof(data), &format, &view, nullptr));
    format.read_tag = nullptr;
    expect_failure(data, sizeof(data), &format, TLV_ERR_NULL_ARG);
    format = controlled::reader;
    format.read_length = nullptr;
    expect_failure(data, sizeof(data), &format, TLV_ERR_NULL_ARG);
}

TEST(Unit_Tlv_Reader, RejectsInvalidCallbackResultsAndPropagatesErrors) {
    const uint8_t data[6] = {};
    Config        config;
    auto          format = make_format(&config);
    config.tag_bytes = 0;
    expect_failure(data, sizeof(data), &format, TLV_ERR_INVALID_TAG);
    config.tag_bytes = std::numeric_limits<size_t>::max();
    expect_failure(data, sizeof(data), &format, TLV_ERR_INVALID_TAG);
    config = Config{};
    // Whether an empty tag is acceptable is up to the format, not the reader.
    config.tag_size = 0;
    {
        tlv_view_t view{};
        size_t     consumed = 0;
        ASSERT_EQ(TLV_OK, tlv_read(data, sizeof(data), &format, &view, &consumed));
        EXPECT_EQ(0u, view.tag.size);
    }
    // A tag that claims bytes but has no pointer is malformed.
    config = Config{};
    config.tag_without_data = true;
    expect_failure(data, sizeof(data), &format, TLV_ERR_INVALID_TAG);
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

TEST(Unit_Tlv_ReaderDiagnostic, ReadDiagLeavesDiagnosticUnchangedOnSuccess) {
    const uint8_t           data[] = {0xAB, 2, 0xCD, 0xEF};
    tlv_view_t              view{};
    size_t                  consumed = 0;
    tlv_reader_diagnostic_t diagnostic;
    std::memset(&diagnostic, 0xAA, sizeof(diagnostic));
    unsigned char before[sizeof(diagnostic)];
    std::memcpy(before, &diagnostic, sizeof(before));

    ASSERT_EQ(TLV_OK, tlv_read_diag(data, sizeof(data), &controlled::reader, &view, &consumed,
                                    &diagnostic));

    EXPECT_EQ(0, std::memcmp(before, &diagnostic, sizeof(before)));
}

TEST(Unit_Tlv_ReaderDiagnostic, ReadDiagAcceptsANullOutParameter) {
    const uint8_t data[] = {0xAB, 2, 0xCD};
    tlv_view_t    view{};
    size_t        consumed = 0;

    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              tlv_read_diag(data, sizeof(data), &controlled::reader, &view, &consumed, nullptr));
}

TEST(Unit_Tlv_ReaderDiagnostic, ReadDiagReportsValueExceedingAvailableBytes) {
    // Tag 0xAB declares a 6-byte value but only 4 bytes remain, matching the
    // motivating example: code, offset, tag, declared_length and available.
    const uint8_t           data[] = {0xAB, 6, 0, 0, 0, 0};
    tlv_view_t              view{};
    size_t                  consumed = 0;
    tlv_reader_diagnostic_t diagnostic;

    ASSERT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_read_diag(data, sizeof(data), &controlled::reader,
                                                      &view, &consumed, &diagnostic));

    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, diagnostic.diagnostic.code);
    EXPECT_EQ(TLV_DIAGNOSTIC_SEVERITY_ERROR, diagnostic.diagnostic.severity);
    ASSERT_NE(0, diagnostic.diagnostic.has_offset);
    EXPECT_EQ(2u, diagnostic.diagnostic.offset);
    EXPECT_EQ(TLV_READER_OP_VALUE, diagnostic.operation);
    ASSERT_NE(0, diagnostic.has_tag);
    ASSERT_EQ(1u, diagnostic.tag.size);
    EXPECT_EQ(0xAB, diagnostic.tag.data[0]);
    ASSERT_NE(0, diagnostic.has_tag_offset);
    EXPECT_EQ(0u, diagnostic.tag_offset);
    ASSERT_NE(0, diagnostic.has_length_offset);
    EXPECT_EQ(1u, diagnostic.length_offset);
    ASSERT_NE(0, diagnostic.has_value_offset);
    EXPECT_EQ(2u, diagnostic.value_offset);
    ASSERT_NE(0, diagnostic.has_declared_length);
    EXPECT_EQ(6u, diagnostic.declared_length);
    ASSERT_NE(0, diagnostic.has_available);
    EXPECT_EQ(4u, diagnostic.available);
    ASSERT_NE(0, diagnostic.has_enclosing_end);
    EXPECT_EQ(sizeof(data), diagnostic.enclosing_end);
}

TEST(Unit_Tlv_ReaderDiagnostic, ReadDiagReportsATruncatedTag) {
    tlv_view_t              view{};
    size_t                  consumed = 0;
    tlv_reader_diagnostic_t diagnostic;

    ASSERT_EQ(TLV_ERR_END_OF_BUFFER,
              tlv_read_diag(nullptr, 0, &controlled::reader, &view, &consumed, &diagnostic));

    EXPECT_EQ(TLV_ERR_END_OF_BUFFER, diagnostic.diagnostic.code);
    EXPECT_EQ(TLV_READER_OP_TAG, diagnostic.operation);
    EXPECT_EQ(0, diagnostic.has_tag);
    ASSERT_NE(0, diagnostic.has_available);
    EXPECT_EQ(0u, diagnostic.available);
}

TEST(Unit_Tlv_ReaderDiagnostic, ReadDiagReportsATruncatedLengthWithTheDecodedTag) {
    const uint8_t           data[] = {0xAB};
    tlv_view_t              view{};
    size_t                  consumed = 0;
    tlv_reader_diagnostic_t diagnostic;

    ASSERT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_read_diag(data, sizeof(data), &controlled::reader,
                                                      &view, &consumed, &diagnostic));

    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, diagnostic.diagnostic.code);
    EXPECT_EQ(TLV_READER_OP_LENGTH, diagnostic.operation);
    ASSERT_NE(0, diagnostic.diagnostic.has_offset);
    EXPECT_EQ(1u, diagnostic.diagnostic.offset);
    ASSERT_NE(0, diagnostic.has_tag);
    EXPECT_EQ(0xAB, diagnostic.tag.data[0]);
    ASSERT_NE(0, diagnostic.has_length_offset);
    EXPECT_EQ(1u, diagnostic.length_offset);
}

TEST(Unit_Tlv_ReaderDiagnostic, ReaderNextDiagReportsOffsetsAbsoluteWithinTheBuffer) {
    const uint8_t data[] = {0xAB, 1, 0xCD, 0xEF, 6, 0, 0, 0, 0};
    tlv_reader_t  reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data), &controlled::reader));

    tlv_view_t view{};
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &view));
    EXPECT_EQ(3u, reader.pos);

    tlv_reader_diagnostic_t diagnostic;
    ASSERT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_reader_next_diag(&reader, &view, &diagnostic));

    ASSERT_NE(0, diagnostic.diagnostic.has_offset);
    EXPECT_EQ(5u, diagnostic.diagnostic.offset);
    ASSERT_NE(0, diagnostic.has_tag_offset);
    EXPECT_EQ(3u, diagnostic.tag_offset);
    ASSERT_NE(0, diagnostic.has_length_offset);
    EXPECT_EQ(4u, diagnostic.length_offset);
    ASSERT_NE(0, diagnostic.has_value_offset);
    EXPECT_EQ(5u, diagnostic.value_offset);
    ASSERT_NE(0, diagnostic.has_enclosing_end);
    EXPECT_EQ(sizeof(data), diagnostic.enclosing_end);
    EXPECT_EQ(3u, reader.pos);
}

TEST(Unit_Tlv_ReaderDiagnostic, ReaderNextDiagReportsEndOfBufferAtTheCurrentPosition) {
    const uint8_t data[] = {0xAB, 1, 0xCD};
    tlv_reader_t  reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data), &controlled::reader));

    tlv_view_t view{};
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &view));
    EXPECT_TRUE(tlv_reader_at_end(&reader));

    tlv_reader_diagnostic_t diagnostic;
    ASSERT_EQ(TLV_ERR_END_OF_BUFFER, tlv_reader_next_diag(&reader, &view, &diagnostic));
    ASSERT_NE(0, diagnostic.has_tag_offset);
    EXPECT_EQ(sizeof(data), diagnostic.tag_offset);
}

TEST(Unit_Tlv_ReaderDiagnostic, InitResetsEveryFieldAndIgnoresANullDiagnostic) {
    tlv_reader_diagnostic_t diagnostic;
    std::memset(&diagnostic, 0xAA, sizeof(diagnostic));

    tlv_reader_diagnostic_init(&diagnostic);

    EXPECT_EQ(TLV_OK, diagnostic.diagnostic.code);
    EXPECT_EQ(0, diagnostic.diagnostic.has_offset);
    EXPECT_EQ(0, diagnostic.has_tag);
    EXPECT_EQ(0, diagnostic.has_tag_offset);
    EXPECT_EQ(0, diagnostic.has_length_offset);
    EXPECT_EQ(0, diagnostic.has_value_offset);
    EXPECT_EQ(0, diagnostic.has_declared_length);
    EXPECT_EQ(0, diagnostic.has_available);
    EXPECT_EQ(0, diagnostic.has_enclosing_end);

    tlv_reader_diagnostic_init(nullptr);
}
