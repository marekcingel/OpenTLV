// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "controlled_format.h"
#include "tlv/reader/reader.h"
#include <gtest/gtest.h>
#include <cstring>
#include <limits>

TEST(Unit_Tlv_Reader, ReadsOnlyFirstElementAndBorrowsValue) {
    uint8_t       data[] = {1, 2, 0xAB, 0xCD, 2, 0xFF};
    tlv_element_t element{};
    size_t        consumed = 0;
    ASSERT_EQ(TLV_OK, tlv_read(data, sizeof(data), &controlled::format, &element, &consumed));
    EXPECT_EQ(1u, element.tag.size);
    EXPECT_EQ(1u, element.tag.data[0]);
    EXPECT_EQ(data + 2, element.value.data);
    EXPECT_EQ(2u, element.value.size);
    EXPECT_EQ(4u, consumed);
    data[2] = 0xEF;
    EXPECT_EQ(0xEF, element.value.data[0]);
}

namespace {
struct Config {
    tlv_field_composition_t layout = controlled::format_layout;
    size_t                  tag_bytes = 2;
    size_t                  length_bytes = 2;
    size_t                  value_bytes = 2;
    size_t                  tag_size = 2;
    bool                    tag_without_data = false;
    tlv_result_t            tag_error = TLV_OK;
    tlv_result_t            length_error = TLV_OK;
};

tlv_format_t make_format(Config* config) {
    tlv_format_t format{};
    format.context = &config->layout;
    config->layout.context = config;
    format.decode = tlv_fields_decode;
    config->layout.read_tag = [](const void* ctx, const uint8_t* data, size_t size, tlv_tag_t* tag,
                                 size_t* used) {
        const auto& c = *static_cast<const Config*>(ctx);
        if (c.tag_error != TLV_OK) return c.tag_error;
        if (size < 2) return TLV_ERR_BUFFER_TOO_SHORT;
        *tag = tlv_tag(c.tag_without_data || !c.tag_size ? nullptr : data, c.tag_size);
        *used = c.tag_bytes;
        return TLV_OK;
    };
    config->layout.read_length = [](const void* ctx, const uint8_t*, size_t size,
                                    tlv_size_t* length, size_t* used) {
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
    tlv_element_t element = {TLV_TAG(0xEE), {data, 42}};
    size_t        consumed = 99;
    EXPECT_EQ(error, tlv_read(data, size, format, &element, &consumed));
    EXPECT_EQ(99u, consumed);
    EXPECT_EQ(1u, element.tag.size);
    EXPECT_EQ(0xEE, element.tag.data[0]);
    EXPECT_EQ(data, element.value.data);
    EXPECT_EQ(42u, element.value.size);
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
    tlv_element_t element{};
    size_t        consumed = 0;
    ASSERT_EQ(TLV_OK, tlv_read(data, sizeof(data), &format, &element, &consumed));
    EXPECT_EQ(data, element.tag.data);
    EXPECT_EQ(data + 4, element.value.data);
    EXPECT_EQ(2u, element.value.size);
    EXPECT_EQ(6u, consumed);
    config.length_bytes = 0;
    ASSERT_EQ(TLV_OK, tlv_read(data, sizeof(data), &format, &element, &consumed));
    EXPECT_EQ(data + 2, element.value.data);
    EXPECT_EQ(4u, consumed);
}

TEST(Unit_Tlv_Reader, RejectsInvalidArguments) {
    const uint8_t data[] = {1, 0};
    auto          format = controlled::format;
    tlv_element_t element{};
    size_t        consumed = 0;
    expect_failure(nullptr, 0, &format, TLV_ERR_END_OF_BUFFER);
    expect_failure(nullptr, 1, &format, TLV_ERR_NULL_ARG);
    expect_failure(data, sizeof(data), nullptr, TLV_ERR_NULL_ARG);
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_read(data, sizeof(data), &format, nullptr, &consumed));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_read(data, sizeof(data), &format, &element, nullptr));
    format.decode = nullptr;
    expect_failure(data, sizeof(data), &format, TLV_ERR_NULL_ARG);
    format = controlled::format;
    format.decode = nullptr;
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
    format = make_format(&config);
    // An empty semantic Tag cannot describe a nonempty source Tag range.
    config.tag_size = 0;
    expect_failure(data, sizeof(data), &format, TLV_ERR_INVALID_ARG);
    // A tag that claims bytes but has no pointer is malformed.
    config = Config{};
    format = make_format(&config);
    config.tag_without_data = true;
    expect_failure(data, sizeof(data), &format, TLV_ERR_INVALID_TAG);
    config = Config{};
    format = make_format(&config);
    config.value_bytes = std::numeric_limits<size_t>::max();
    expect_failure(data, sizeof(data), &format, TLV_ERR_BUFFER_TOO_SHORT);
    config.layout.read_length = [](const void*, const uint8_t*, size_t, tlv_size_t*, size_t* used) {
        *used = std::numeric_limits<size_t>::max();
        return TLV_OK;
    };
    expect_failure(data, sizeof(data), &format, TLV_ERR_INVALID_LENGTH);
    format = make_format(&config);
    config.tag_error = TLV_ERR_INVALID_TAG;
    expect_failure(data, sizeof(data), &format, TLV_ERR_INVALID_TAG);
    config = Config{};
    format = make_format(&config);
    config.length_error = TLV_ERR_INVALID_LENGTH;
    expect_failure(data, sizeof(data), &format, TLV_ERR_INVALID_LENGTH);
}

TEST(Unit_Tlv_ReaderDiagnostic, ReadDiagLeavesDiagnosticUnchangedOnSuccess) {
    const uint8_t           data[] = {0xAB, 2, 0xCD, 0xEF};
    tlv_element_t           element{};
    size_t                  consumed = 0;
    tlv_reader_diagnostic_t diagnostic;
    std::memset(&diagnostic, 0xAA, sizeof(diagnostic));
    unsigned char before[sizeof(diagnostic)];
    std::memcpy(before, &diagnostic, sizeof(before));

    ASSERT_EQ(TLV_OK, tlv_read_diag(data, sizeof(data), &controlled::format, &element, &consumed,
                                    &diagnostic));

    EXPECT_EQ(0, std::memcmp(before, &diagnostic, sizeof(before)));
}

TEST(Unit_Tlv_ReaderDiagnostic, ReadDiagAcceptsANullOutParameter) {
    const uint8_t data[] = {0xAB, 2, 0xCD};
    tlv_element_t element{};
    size_t        consumed = 0;

    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              tlv_read_diag(data, sizeof(data), &controlled::format, &element, &consumed, nullptr));
}

TEST(Unit_Tlv_ReaderDiagnostic, ReadDiagReportsValueExceedingAvailableBytes) {
    // Tag 0xAB declares a 6-byte value but only 4 bytes remain, matching the
    // motivating example: code, offset, tag, declared_length and available.
    const uint8_t           data[] = {0xAB, 6, 0, 0, 0, 0};
    tlv_element_t           element{};
    size_t                  consumed = 0;
    tlv_reader_diagnostic_t diagnostic;

    ASSERT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_read_diag(data, sizeof(data), &controlled::format,
                                                      &element, &consumed, &diagnostic));

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

TEST(Unit_Tlv_ReaderDiagnostic, ReadDiagReportsEmptyInputAtHeader) {
    tlv_element_t           element{};
    size_t                  consumed = 0;
    tlv_reader_diagnostic_t diagnostic;

    ASSERT_EQ(TLV_ERR_END_OF_BUFFER,
              tlv_read_diag(nullptr, 0, &controlled::format, &element, &consumed, &diagnostic));

    EXPECT_EQ(TLV_ERR_END_OF_BUFFER, diagnostic.diagnostic.code);
    EXPECT_EQ(TLV_READER_OP_HEADER, diagnostic.operation);
    EXPECT_EQ(0, diagnostic.has_tag);
    ASSERT_NE(0, diagnostic.has_available);
    EXPECT_EQ(0u, diagnostic.available);
}

TEST(Unit_Tlv_ReaderDiagnostic, ReadDiagReportsATruncatedLengthWithTheDecodedTag) {
    const uint8_t           data[] = {0xAB};
    tlv_element_t           element{};
    size_t                  consumed = 0;
    tlv_reader_diagnostic_t diagnostic;

    ASSERT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_read_diag(data, sizeof(data), &controlled::format,
                                                      &element, &consumed, &diagnostic));

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
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data), &controlled::format));

    tlv_element_t element{};
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
    EXPECT_EQ(3u, reader.pos);

    tlv_reader_diagnostic_t diagnostic;
    ASSERT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_reader_next_diag(&reader, &element, &diagnostic));

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
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data), &controlled::format));

    tlv_element_t element{};
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
    EXPECT_TRUE(tlv_reader_at_end(&reader));

    tlv_reader_diagnostic_t diagnostic;
    ASSERT_EQ(TLV_ERR_END_OF_BUFFER, tlv_reader_next_diag(&reader, &element, &diagnostic));
    EXPECT_EQ(TLV_READER_OP_HEADER, diagnostic.operation);
    EXPECT_EQ(0, diagnostic.has_tag_offset);
    EXPECT_EQ(sizeof(data), diagnostic.diagnostic.offset);
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

TEST(Unit_Tlv_ReaderCursor, PreservesStateAndOutputsForEveryIncompletePrefix) {
    const uint8_t data[] = {1, 0, 2, 2, 0xAB, 0xCD};
    for (size_t size = 2; size < sizeof(data); ++size) {
        SCOPED_TRACE(size);
        tlv_reader_t reader;
        ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, size, &controlled::format));
        tlv_element_t element{};
        tlv_source_t  source{};
        ASSERT_EQ(TLV_OK, tlv_reader_next_source_diag(&reader, &element, &source, nullptr));
        const auto before = reader;
        const auto previous = element;
        const auto original_source = source;
        for (int repeat = 0; repeat != 2; ++repeat) {
            tlv_reader_diagnostic_t diagnostic{};
            const auto expected = size == 2 ? TLV_ERR_END_OF_BUFFER : TLV_ERR_BUFFER_TOO_SHORT;
            EXPECT_EQ(expected, tlv_reader_next(&reader, &element));
            EXPECT_EQ(expected, tlv_reader_next_diag(&reader, &element, &diagnostic));
            EXPECT_EQ(expected,
                      tlv_reader_next_source_diag(&reader, &element, &source, &diagnostic));
            EXPECT_EQ(before.pos, reader.pos);
            EXPECT_EQ(before.data, reader.data);
            EXPECT_EQ(before.size, reader.size);
            EXPECT_EQ(before.format, reader.format);
            EXPECT_EQ(previous.tag.data, element.tag.data);
            EXPECT_EQ(previous.tag.size, element.tag.size);
            EXPECT_EQ(previous.value.data, element.value.data);
            EXPECT_EQ(previous.value.size, element.value.size);
            EXPECT_EQ(original_source.data, source.data);
            EXPECT_EQ(original_source.size, source.size);
            EXPECT_EQ(expected, diagnostic.diagnostic.code);
            EXPECT_EQ(size, diagnostic.enclosing_end);
            EXPECT_EQ(size == 2, tlv_reader_at_end(&reader) != 0);
        }
    }
}

TEST(Unit_Tlv_ReaderCursor, RetainedResultsSurviveAdvanceAndReinitialization) {
    const uint8_t data[] = {1, 1, 0xAB, 2, 0};
    tlv_reader_t  reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data), &controlled::format));
    tlv_element_t first{}, second{};
    tlv_source_t  source{};
    ASSERT_EQ(TLV_OK, tlv_reader_next_source_diag(&reader, &first, &source, nullptr));
    EXPECT_EQ(data, source.data);
    EXPECT_EQ(3u, source.size);
    EXPECT_EQ(2u, source.value.offset);
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &second));
    EXPECT_EQ(data + 3, second.tag.data);
    EXPECT_EQ(sizeof(data), reader.pos);
    EXPECT_EQ(TLV_ERR_END_OF_BUFFER, tlv_reader_next(&reader, &second));
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, nullptr, 0, &controlled::format));
    EXPECT_EQ(0u, reader.pos);
    EXPECT_TRUE(tlv_reader_at_end(&reader));
    EXPECT_EQ(TLV_ERR_END_OF_BUFFER, tlv_reader_next(&reader, &second));
    EXPECT_EQ(data + 2, first.value.data);
    EXPECT_EQ(0xAB, first.value.data[0]);
    uint8_t copy[3]{};
    size_t  written = 0;
    ASSERT_EQ(TLV_OK, tlv_source_preserve(&source, &first, copy, sizeof(copy), &written));
    EXPECT_EQ(3u, written);
    EXPECT_EQ(0, std::memcmp(data, copy, written));
}

TEST(Unit_Tlv_ReaderCursor, DoesNotRecoverOrReinterpretFormatErrors) {
    const uint8_t data[6] = {};
    Config        config;
    config.tag_error = TLV_ERR_INVALID_TAG;
    const auto   format = make_format(&config);
    tlv_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data), &format));
    tlv_element_t element = {TLV_TAG(0xEE), {data, 42}};
    for (int repeat = 0; repeat != 2; ++repeat) {
        tlv_reader_diagnostic_t diagnostic{};
        EXPECT_EQ(TLV_ERR_INVALID_TAG, tlv_reader_next_diag(&reader, &element, &diagnostic));
        EXPECT_EQ(TLV_ERR_INVALID_TAG, diagnostic.diagnostic.code);
        EXPECT_EQ(TLV_READER_OP_TAG, diagnostic.operation);
        EXPECT_EQ(0u, diagnostic.diagnostic.offset);
        EXPECT_EQ(0u, reader.pos);
        EXPECT_FALSE(tlv_reader_at_end(&reader));
        EXPECT_EQ(0xEE, element.tag.data[0]);
        EXPECT_EQ(42u, element.value.size);
    }
}

TEST(Unit_Tlv_ReaderCursor, SourceAndElementRequireOnlyOneFormatDecode) {
    struct Counter {
        size_t calls = 0;
    } counter;
    tlv_format_t format{};
    format.context = &counter;
    format.decode = [](const void* ctx, const uint8_t* data, size_t size, tlv_decoded_t* decoded,
                       tlv_format_error_t* error) {
        ++const_cast<Counter*>(static_cast<const Counter*>(ctx))->calls;
        return controlled::format.decode(controlled::format.context, data, size, decoded, error);
    };
    const uint8_t data[] = {1, 0, 2, 0};
    tlv_reader_t  reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data), &format));
    tlv_element_t           element{};
    tlv_source_t            source{};
    tlv_reader_diagnostic_t diagnostic{};
    diagnostic.has_available = 1;
    diagnostic.available = 123;
    ASSERT_EQ(TLV_OK, tlv_reader_next_source_diag(&reader, &element, &source, &diagnostic));
    ASSERT_EQ(TLV_OK, tlv_reader_next_source_diag(&reader, &element, &source, &diagnostic));
    EXPECT_EQ(2u, counter.calls);
    EXPECT_EQ(data + 2, source.data);
    EXPECT_EQ(&format, source.format);
    EXPECT_EQ(element.tag.data, source.element.tag.data);
    EXPECT_EQ(123u, diagnostic.available);
    EXPECT_EQ(TLV_ERR_END_OF_BUFFER,
              tlv_reader_next_source_diag(&reader, &element, &source, nullptr));
    EXPECT_EQ(2u, counter.calls);
}

TEST(Unit_Tlv_ReaderCursor, RejectsInvalidStateAndArgumentsWithoutAdvancing) {
    const uint8_t data[] = {1, 0};
    tlv_reader_t  reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data), &controlled::format));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_reader_init(&reader, nullptr, 1, &controlled::format));
    EXPECT_EQ(data, reader.data);
    EXPECT_EQ(sizeof(data), reader.size);
    tlv_element_t           element{};
    tlv_reader_diagnostic_t diagnostic{};
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              tlv_reader_next_source_diag(&reader, &element, nullptr, &diagnostic));
    EXPECT_EQ(TLV_ERR_NULL_ARG, diagnostic.diagnostic.code);
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_reader_next(&reader, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_reader_next(nullptr, &element));
    EXPECT_EQ(0u, reader.pos);
    reader.pos = sizeof(data) + 1;
    EXPECT_FALSE(tlv_reader_at_end(&reader));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_reader_next(&reader, &element));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_reader_next_diag(&reader, &element, &diagnostic));
    EXPECT_EQ(sizeof(data) + 1, reader.pos);
    EXPECT_EQ(reader.pos, diagnostic.diagnostic.offset);
    EXPECT_FALSE(tlv_reader_at_end(nullptr));
}
