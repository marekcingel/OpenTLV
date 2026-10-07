// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/formats/compose.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#include <gtest/gtest.h>
#include <cstring>
#include <limits>
#include <vector>

namespace {
// Two raw tag bytes, and a configurable fixed-width little-endian length.
const size_t width = 2;
tlv_result_t read_tag(const void*, const uint8_t* data, size_t size, tlv_tag_t* tag, size_t* used) {
    if (size < 2) return TLV_ERR_BUFFER_TOO_SHORT;
    *tag = tlv_tag(data, 2);
    *used = 2;
    return TLV_OK;
}
tlv_result_t write_tag(const void*, const tlv_tag_t* tag, uint8_t* data, size_t size,
                       size_t* used) {
    if (tag->size != 2) return TLV_ERR_INVALID_TAG_SIZE;
    *used = 2;
    if (!data) return TLV_OK;
    if (size < 2) return TLV_ERR_BUFFER_TOO_SHORT;
    std::memcpy(data, tag->data, 2);
    return TLV_OK;
}
tlv_result_t length_size(const void* ctx, tlv_size_t length, size_t* used) {
    if (length > 65535) return TLV_ERR_INVALID_LENGTH;
    *used = *static_cast<const size_t*>(ctx);
    return TLV_OK;
}
tlv_result_t read_length(const void* ctx, const uint8_t* data, size_t size, tlv_size_t* length,
                         size_t* used) {
    *used = *static_cast<const size_t*>(ctx);
    if (size < *used) return TLV_ERR_BUFFER_TOO_SHORT;
    *length = data[0] | (static_cast<size_t>(data[1]) << 8);
    return TLV_OK;
}
tlv_result_t write_length(const void* ctx, tlv_size_t length, uint8_t* data, size_t size,
                          size_t* used) {
    const auto rc = length_size(ctx, length, used);
    if (rc != TLV_OK) return rc;
    if (!data) return TLV_OK;
    if (size < *used) return TLV_ERR_BUFFER_TOO_SHORT;
    data[0] = static_cast<uint8_t>(length);
    data[1] = static_cast<uint8_t>(length >> 8);
    return TLV_OK;
}
const tlv_field_composition_t fixed_layout = {
    &width,  read_tag, read_length,           nullptr,
    nullptr, nullptr,  TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
const tlv_format_t            fixed = {&fixed_layout, tlv_fields_decode, nullptr, nullptr, nullptr};
const tlv_field_composition_t fixed_writer_layout = {&width,
                                                     nullptr,
                                                     nullptr,
                                                     nullptr,
                                                     write_tag,
                                                     write_length,
                                                     TLV_ELEMENT_ORDER_TLV,
                                                     TLV_LENGTH_SCOPE_VALUE};
const tlv_format_t            fixed_writer = {&fixed_writer_layout, nullptr, tlv_fields_measure,
                                              tlv_fields_encode, nullptr};
} // namespace

TEST(Unit_Tlv_Format, TruncationPreservesReaderStateAndOutput) {
    const uint8_t data[] = {0x9F, 0x02, 0x02, 0x00, 0xAB, 0xCD};
    for (size_t size = 1; size < sizeof(data); ++size) {
        tlv_reader_t reader;
        ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, size, &fixed));
        tlv_element_t element = {TLV_TAG(0xEE), {nullptr, 42}};
        EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_reader_next(&reader, &element));
        EXPECT_EQ(0u, reader.pos);
        EXPECT_EQ(0xEE, element.tag.data[0]);
        EXPECT_EQ(42u, element.value.size);
    }
}

TEST(Unit_Tlv_Format, WriterPreflightDoesNotModifyBuffer) {
    uint8_t data[5];
    std::memset(data, 0xEE, sizeof(data));
    tlv_writer_t writer;
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, data, sizeof(data), &fixed_writer));
    const tlv_tag_t tag = TLV_TAG(1, 2);
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_writer_write(&writer, tag, data, 2));
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_writer_write(&writer, tag, data, 65536));
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE, tlv_writer_write(&writer, (TLV_TAG(1)), nullptr, 0));
    EXPECT_EQ(0u, writer.pos);
    for (auto byte : data) EXPECT_EQ(0xEE, byte);
}

TEST(Unit_Tlv_Format, RequiredCallbacksAreValidatedPerDirection) {
    tlv_reader_t reader;
    tlv_writer_t writer;
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_reader_init(&reader, nullptr, 0, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_writer_init(&writer, nullptr, 0, nullptr));
    tlv_format_t format = fixed;
    format.decode = nullptr;
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_reader_init(&reader, nullptr, 0, &format));
    EXPECT_EQ(TLV_OK, tlv_writer_init(&writer, nullptr, 0, &fixed_writer));
    format = fixed;
    format.decode = nullptr;
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_reader_init(&reader, nullptr, 0, &format));
    for (int i = 0; i < 3; ++i) {
        tlv_format_t output_format = fixed_writer;
        if (i == 0) output_format.encode = nullptr;
        if (i == 1) output_format.encode = nullptr;
        if (i == 2) output_format.measure = nullptr;
        EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_writer_init(&writer, nullptr, 0, &output_format));
        EXPECT_EQ(TLV_OK, tlv_reader_init(&reader, nullptr, 0, &fixed));
    }
}

TEST(Unit_Tlv_Format, InvalidCallbackSizesAndErrorsDoNotAdvance) {
    uint8_t                 data[8] = {};
    tlv_field_composition_t layout = fixed_layout;
    tlv_format_t            format = fixed;
    format.context = &layout;
    layout.read_tag = [](const void*, const uint8_t*, size_t, tlv_tag_t*, size_t* used) {
        *used = std::numeric_limits<size_t>::max();
        return TLV_OK;
    };
    tlv_reader_t  reader;
    tlv_element_t element{};
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data), &format));
    EXPECT_EQ(TLV_ERR_INVALID_TAG, tlv_reader_next(&reader, &element));
    EXPECT_EQ(0u, reader.pos);
    layout = fixed_layout;
    layout.read_length = [](const void*, const uint8_t*, size_t, tlv_size_t* length, size_t* used) {
        *used = 2;
        *length = std::numeric_limits<size_t>::max();
        return TLV_OK;
    };
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_reader_next(&reader, &element));
    EXPECT_EQ(0u, reader.pos);
    layout.read_length = [](const void*, const uint8_t*, size_t, tlv_size_t*, size_t* used) {
        *used = std::numeric_limits<size_t>::max();
        return TLV_OK;
    };
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_reader_next(&reader, &element));
    tlv_field_composition_t output_layout = fixed_writer_layout;
    tlv_format_t            output_format = fixed_writer;
    output_format.context = &output_layout;
    output_layout.write_length = [](const void*, tlv_size_t, uint8_t*, size_t, size_t*) {
        return TLV_ERR_INVALID_LENGTH;
    };
    tlv_writer_t writer;
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, data, sizeof(data), &output_format));
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_writer_write(&writer, (TLV_TAG(1, 2)), nullptr, 0));
    EXPECT_EQ(0u, writer.pos);
    output_layout.write_length = [](const void*, tlv_size_t, uint8_t* data, size_t, size_t* used) {
        *used = data ? 3 : 2;
        return TLV_OK;
    };
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_writer_write(&writer, (TLV_TAG(1, 2)), nullptr, 0));
    EXPECT_EQ(0u, writer.pos);
}

namespace {
void expect_empty_range(const tlv_range_t& range) {
    EXPECT_EQ(0u, range.offset);
    EXPECT_EQ(0u, range.size);
    EXPECT_EQ(0, range.present);
}

void expect_empty_element(const tlv_element_t& element) {
    EXPECT_EQ(nullptr, element.tag.data);
    EXPECT_EQ(0u, element.tag.size);
    EXPECT_EQ(nullptr, element.value.data);
    EXPECT_EQ(0u, element.value.size);
}

void expect_same_range(const tlv_range_t& expected, const tlv_range_t& actual) {
    EXPECT_EQ(expected.offset, actual.offset);
    EXPECT_EQ(expected.size, actual.size);
    EXPECT_EQ(expected.present, actual.present);
}

void expect_same_format_error(const tlv_format_error_t& expected,
                              const tlv_format_error_t& actual) {
    EXPECT_EQ(expected.region, actual.region);
    EXPECT_EQ(expected.offset, actual.offset);
    EXPECT_EQ(expected.has_offset, actual.has_offset);
    EXPECT_EQ(expected.required, actual.required);
    EXPECT_EQ(expected.has_required, actual.has_required);
    expect_same_range(expected.tag, actual.tag);
    expect_same_range(expected.length, actual.length);
    expect_same_range(expected.value, actual.value);
}

const tlv_format_error_t stale_error = {TLV_REGION_TRAILER, 17,        1,        19, 1,
                                        {1, 2, 1},          {3, 4, 1}, {5, 6, 1}};

void expect_same_element(const tlv_element_t& expected, const tlv_element_t& actual) {
    EXPECT_EQ(expected.tag.data, actual.tag.data);
    EXPECT_EQ(expected.tag.size, actual.tag.size);
    EXPECT_EQ(expected.value.data, actual.value.data);
    EXPECT_EQ(expected.value.size, actual.value.size);
}

void expect_same_source(const tlv_source_t& expected, const tlv_source_t& actual) {
    EXPECT_EQ(expected.data, actual.data);
    EXPECT_EQ(expected.size, actual.size);
    EXPECT_EQ(expected.format, actual.format);
    EXPECT_EQ(expected.tag_binding, actual.tag_binding);
    expect_same_range(expected.header, actual.header);
    expect_same_range(expected.tag, actual.tag);
    expect_same_range(expected.length, actual.length);
    expect_same_range(expected.value, actual.value);
    expect_same_range(expected.trailer, actual.trailer);
    expect_same_element(expected.element, actual.element);
}

void expect_same_reader(const tlv_reader_t& expected, const tlv_reader_t& actual) {
    EXPECT_EQ(expected.format, actual.format);
    EXPECT_EQ(expected.data, actual.data);
    EXPECT_EQ(expected.size, actual.size);
    EXPECT_EQ(expected.pos, actual.pos);
    EXPECT_EQ(expected.base_offset, actual.base_offset);
    EXPECT_EQ(expected.final_input, actual.final_input);
}

tlv_result_t initialized_decode(const void* context, const uint8_t* data, size_t size,
                                tlv_decoded_t* result, tlv_format_error_t* error) {
    EXPECT_NE(nullptr, result);
    EXPECT_NE(nullptr, error);
    if (!result || !error) return TLV_ERR_NULL_ARG;
    expect_empty_element(result->element);
    expect_empty_element(result->source.element);
    EXPECT_EQ(nullptr, result->source.data);
    EXPECT_EQ(nullptr, result->source.format);
    EXPECT_EQ(0u, result->source.size);
    EXPECT_EQ(TLV_TAG_BINDING_SOURCE, result->source.tag_binding);
    for (const auto* range : {&result->source.header, &result->source.tag, &result->source.length,
                              &result->source.value, &result->source.trailer, &error->tag,
                              &error->length, &error->value})
        expect_empty_range(*range);
    EXPECT_EQ(TLV_REGION_HEADER, error->region);
    EXPECT_EQ(0u, error->offset);
    EXPECT_EQ(0, error->has_offset);
    EXPECT_EQ(0u, error->required);
    EXPECT_EQ(0, error->has_required);

    // A single-byte value with no explicit Tag or Length relies on the core's
    // zero initialization of all optional fields.
    result->element.value = {data, 1};
    result->source.size = 1;
    result->source.header = {0, 0, 1};
    result->source.value = {0, 1, 1};
    result->source.trailer = {1, 0, 1};
    if (!data[0] || !context) return TLV_OK;

    // Leave a plausible partial result and hostile failure metadata behind.
    error->region = TLV_REGION_LENGTH;
    error->offset = std::numeric_limits<size_t>::max();
    error->has_offset = 1;
    error->tag = {size, 1, 1};
    error->length = {0, std::numeric_limits<size_t>::max(), 1};
    error->value = {0, size + 1, 1};
    const int mode = *static_cast<const int*>(context);
    if (mode == 1) {
        result->source.value.offset = size + 1;
        return TLV_OK;
    }
    return mode == 2 ? TLV_ERR_INVALID_LENGTH : TLV_ERR_BUFFER_TOO_SHORT;
}

struct DecodeProbe {
    size_t*      calls;
    tlv_result_t result;
    bool         partial_detail;
    bool         inconsistent_source;
};

tlv_result_t probed_decode(const void* context, const uint8_t* data, size_t size,
                           tlv_decoded_t* result, tlv_format_error_t* error) {
    const auto& probe = *static_cast<const DecodeProbe*>(context);
    ++*probe.calls;
    const auto rc = initialized_decode(nullptr, data, size, result, error);
    if (rc != TLV_OK) return rc;
    if (probe.partial_detail) {
        error->region = TLV_REGION_VALUE;
        error->has_required = 1;
        error->required = size + 2;
    }
    if (probe.inconsistent_source) result->source.value.offset = size + 1;
    return probe.result;
}
} // namespace

TEST(Unit_Tlv_Format, DecodeCallbacksReceiveInitializedOutputsWithOptionalFieldsAbsent) {
    const uint8_t      data[] = {0, 0};
    const tlv_format_t format = {nullptr, initialized_decode, nullptr, nullptr, nullptr};
    for (bool diagnostic : {false, true}) {
        tlv_decoded_t decoded{};
        decoded.element.tag = TLV_TAG(0xEE);
        decoded.source.tag = {0, 1, 1};
        tlv_format_error_t error = stale_error;
        ASSERT_EQ(TLV_OK, tlv_format_decode(&format, data, sizeof(data), &decoded,
                                            diagnostic ? &error : nullptr));
        expect_same_format_error(stale_error, error);
        EXPECT_EQ(nullptr, decoded.element.tag.data);
        EXPECT_EQ(0u, decoded.element.tag.size);
        expect_empty_range(decoded.source.tag);
        expect_empty_range(decoded.source.length);
        EXPECT_EQ(data, decoded.source.data);
        EXPECT_EQ(&format, decoded.source.format);
        EXPECT_EQ(data, decoded.source.element.value.data);
        EXPECT_EQ(1u, decoded.source.element.value.size);
        EXPECT_EQ(1u, decoded.source.size);

        tlv_reader_t reader;
        ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data, sizeof(data), &format));
        tlv_element_t           element{};
        tlv_source_t            source{};
        tlv_reader_diagnostic_t detail{};
        ASSERT_EQ(TLV_OK, tlv_reader_next_diag(&reader, &element, diagnostic ? &detail : nullptr));
        ASSERT_EQ(TLV_OK, tlv_reader_next_source_diag(&reader, &element, &source,
                                                      diagnostic ? &detail : nullptr));
        EXPECT_EQ(sizeof(data), reader.pos);
        EXPECT_EQ(data + 1, element.value.data);
        EXPECT_EQ(data + 1, source.data);
        EXPECT_EQ(&format, source.format);
        expect_empty_range(source.tag);
        expect_empty_range(source.length);
    }
}

TEST(Unit_Tlv_Format, DecodePreflightInitializesAllFailureDetailWithoutCallingDecoder) {
    const uint8_t      data[] = {0};
    size_t             calls = 0;
    const DecodeProbe  probe = {&calls, TLV_OK, false, false};
    const tlv_format_t format = {&probe, probed_decode, nullptr, nullptr, nullptr};
    const tlv_format_t no_decode = {};
    tlv_decoded_t      decoded{};
    ASSERT_EQ(TLV_OK, tlv_format_decode(&format, data, sizeof(data), &decoded, nullptr));
    const auto decoded_before = decoded;
    calls = 0;
    const struct {
        const tlv_format_t* format;
        const uint8_t*      data;
        size_t              size;
        tlv_decoded_t*      decoded;
        tlv_result_t        result;
    } cases[] = {
        {nullptr, data, sizeof(data), &decoded, TLV_ERR_NULL_ARG},
        {&no_decode, data, sizeof(data), &decoded, TLV_ERR_NULL_ARG},
        {&format, data, sizeof(data), nullptr, TLV_ERR_NULL_ARG},
        {&format, nullptr, sizeof(data), &decoded, TLV_ERR_NULL_ARG},
        {&format, data, 0, &decoded, TLV_ERR_END_OF_BUFFER},
        {&format, nullptr, 0, &decoded, TLV_ERR_END_OF_BUFFER},
    };
    for (const auto& test : cases) {
        SCOPED_TRACE(::testing::Message()
                     << "format=" << test.format << " data=" << static_cast<const void*>(test.data)
                     << " size=" << test.size << " decoded=" << test.decoded);
        for (bool diagnostic : {false, true}) {
            tlv_format_error_t error = stale_error;
            EXPECT_EQ(test.result, tlv_format_decode(test.format, test.data, test.size,
                                                     test.decoded, diagnostic ? &error : nullptr));
            EXPECT_EQ(0u, calls);
            expect_same_element(decoded_before.element, decoded.element);
            expect_same_source(decoded_before.source, decoded.source);
            if (diagnostic) {
                tlv_format_error_t expected{};
                expected.has_offset = test.result == TLV_ERR_END_OF_BUFFER;
                expect_same_format_error(expected, error);
            }
        }
    }
}

TEST(Unit_Tlv_Format, DecodeCallbacksPublishCompletePartialOrAbsentFailureDetailOnce) {
    const uint8_t     data[] = {0};
    size_t            calls = 0;
    const DecodeProbe cases[] = {
        {&calls, TLV_ERR_NULL_ARG, false, false},
        {&calls, TLV_ERR_NULL_ARG, true, false},
        {&calls, TLV_ERR_BUFFER_TOO_SHORT, false, false},
        {&calls, TLV_ERR_INVALID_LENGTH, true, false},
        {&calls, TLV_OK, false, true},
        {&calls, TLV_OK, true, true},
    };
    const tlv_format_t successful = {nullptr, initialized_decode, nullptr, nullptr, nullptr};
    tlv_decoded_t      decoded{};
    ASSERT_EQ(TLV_OK, tlv_format_decode(&successful, data, sizeof(data), &decoded, nullptr));
    const auto decoded_before = decoded;
    for (const auto& probe : cases) {
        SCOPED_TRACE(::testing::Message()
                     << "result=" << probe.result << " partial_detail=" << probe.partial_detail
                     << " inconsistent_source=" << probe.inconsistent_source);
        const tlv_format_t format = {&probe, probed_decode, nullptr, nullptr, nullptr};
        const auto         failure = probe.inconsistent_source ? TLV_ERR_INVALID_ARG : probe.result;
        for (bool diagnostic : {false, true}) {
            calls = 0;
            tlv_format_error_t error = stale_error;
            EXPECT_EQ(failure, tlv_format_decode(&format, data, sizeof(data), &decoded,
                                                 diagnostic ? &error : nullptr));
            EXPECT_EQ(1u, calls);
            expect_same_element(decoded_before.element, decoded.element);
            expect_same_source(decoded_before.source, decoded.source);
            if (diagnostic) {
                tlv_format_error_t expected{};
                if (probe.partial_detail) {
                    expected.region = TLV_REGION_VALUE;
                    expected.has_required = 1;
                    expected.required = sizeof(data) + 2;
                }
                expect_same_format_error(expected, error);
            }
        }
    }
}

TEST(Unit_Tlv_Format, FailedDecodeCallbacksPreservePublishedOutputsAcrossReaderPaths) {
    const uint8_t data[] = {0, 1};
    for (int mode : {1, 2, 3}) {
        SCOPED_TRACE(mode);
        const tlv_format_t format = {&mode, initialized_decode, nullptr, nullptr, nullptr};
        const tlv_result_t failure = mode == 1   ? TLV_ERR_INVALID_ARG
                                     : mode == 2 ? TLV_ERR_INVALID_LENGTH
                                                 : TLV_ERR_BUFFER_TOO_SHORT;
        tlv_decoded_t      decoded{};
        ASSERT_EQ(TLV_OK, tlv_format_decode(&format, data, sizeof(data), &decoded, nullptr));
        const auto decoded_before = decoded;
        for (bool diagnostic : {false, true}) {
            tlv_format_error_t error{};
            EXPECT_EQ(failure, tlv_format_decode(&format, data + 1, 1, &decoded,
                                                 diagnostic ? &error : nullptr));
            expect_same_element(decoded_before.element, decoded.element);
            expect_same_source(decoded_before.source, decoded.source);
            if (diagnostic) {
                EXPECT_FALSE(error.tag.present);
                EXPECT_FALSE(error.length.present);
                EXPECT_FALSE(error.value.present);
            }
            for (bool incremental : {false, true}) {
                for (bool with_source : {false, true}) {
                    SCOPED_TRACE(::testing::Message()
                                 << "diagnostic=" << diagnostic << " incremental=" << incremental
                                 << " source=" << with_source);
                    tlv_reader_t reader;
                    ASSERT_EQ(TLV_OK, incremental
                                          ? tlv_reader_init_incremental(&reader, data, sizeof(data),
                                                                        &format)
                                          : tlv_reader_init(&reader, data, sizeof(data), &format));
                    tlv_element_t element{};
                    tlv_source_t  source{};
                    ASSERT_EQ(TLV_OK,
                              tlv_reader_next_source_diag(&reader, &element, &source, nullptr));
                    const auto         reader_before = reader;
                    const auto         element_before = element;
                    const auto         source_before = source;
                    const tlv_result_t expected =
                        incremental && mode == 3 ? TLV_NEED_MORE_DATA : failure;
                    tlv_reader_diagnostic_t detail{};
                    for (int retry = 0; retry < 2; ++retry) {
                        EXPECT_EQ(expected,
                                  with_source
                                      ? tlv_reader_next_source_diag(&reader, &element, &source,
                                                                    diagnostic ? &detail : nullptr)
                                      : tlv_reader_next_diag(&reader, &element,
                                                             diagnostic ? &detail : nullptr));
                        expect_same_reader(reader_before, reader);
                        expect_same_element(element_before, element);
                        expect_same_source(source_before, source);
                        if (diagnostic) {
                            EXPECT_EQ(expected, detail.diagnostic.code);
                            EXPECT_EQ(TLV_READER_OP_LENGTH, detail.operation);
                            EXPECT_FALSE(detail.diagnostic.has_offset);
                            EXPECT_FALSE(detail.has_tag);
                            EXPECT_FALSE(detail.has_raw_length);
                            EXPECT_FALSE(detail.has_value_offset);
                        }
                    }
                }
            }
        }
    }
}

TEST(Unit_Tlv_Format, MissingDecodeArgumentsDoNotPublishUninitializedDiagnosticFields) {
    const uint8_t      data[] = {0};
    const tlv_format_t no_decode = {};
    for (const auto* format : {&fixed, &no_decode, static_cast<const tlv_format_t*>(nullptr)}) {
        tlv_element_t           element{};
        size_t                  consumed = 99;
        tlv_reader_diagnostic_t diagnostic;
        std::memset(&diagnostic, 0xAA, sizeof(diagnostic));
        EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_read_diag(format == &fixed ? nullptr : data, sizeof(data),
                                                  format, &element, &consumed, &diagnostic));
        EXPECT_EQ(99u, consumed);
        EXPECT_EQ(TLV_ERR_NULL_ARG, diagnostic.diagnostic.code);
        EXPECT_EQ(TLV_READER_OP_HEADER, diagnostic.operation);
        EXPECT_FALSE(diagnostic.diagnostic.has_offset);
        EXPECT_EQ(0u, diagnostic.diagnostic.offset);
        EXPECT_FALSE(diagnostic.has_tag);
        EXPECT_FALSE(diagnostic.has_raw_length);
        EXPECT_FALSE(diagnostic.has_declared_length);
        EXPECT_FALSE(diagnostic.has_required);
        EXPECT_FALSE(diagnostic.has_available);
    }
}

namespace {
// A format whose tag width is chosen at runtime, as a format loaded from a
// description would: nothing about the width is known when OpenTLV is built.
struct RuntimeTagFormat {
    size_t tag_width;
};

const size_t& width_of(const void* ctx) {
    return static_cast<const RuntimeTagFormat*>(ctx)->tag_width;
}
tlv_result_t runtime_read_tag(const void* ctx, const uint8_t* data, size_t size, tlv_tag_t* tag,
                              size_t* used) {
    if (size < width_of(ctx)) return TLV_ERR_BUFFER_TOO_SHORT;
    *tag = tlv_tag(data, width_of(ctx));
    *used = width_of(ctx);
    return TLV_OK;
}
tlv_result_t runtime_write_tag(const void* ctx, const tlv_tag_t* tag, uint8_t* data, size_t size,
                               size_t* used) {
    if (tag->size != width_of(ctx)) return TLV_ERR_INVALID_TAG_SIZE;
    *used = tag->size;
    if (!data) return TLV_OK;
    if (size < tag->size) return TLV_ERR_BUFFER_TOO_SHORT;
    std::memcpy(data, tag->data, tag->size);
    return TLV_OK;
}
tlv_result_t one_byte_length_size(const void*, tlv_size_t length, size_t* used) {
    if (length > 255) return TLV_ERR_INVALID_LENGTH;
    *used = 1;
    return TLV_OK;
}
tlv_result_t one_byte_read_length(const void*, const uint8_t* data, size_t size, tlv_size_t* length,
                                  size_t* used) {
    if (size < 1) return TLV_ERR_BUFFER_TOO_SHORT;
    *length = data[0];
    *used = 1;
    return TLV_OK;
}
tlv_result_t one_byte_write_length(const void* ctx, tlv_size_t length, uint8_t* data, size_t size,
                                   size_t* used) {
    const auto rc = one_byte_length_size(ctx, length, used);
    if (rc != TLV_OK) return rc;
    if (!data) return TLV_OK;
    if (size < 1) return TLV_ERR_BUFFER_TOO_SHORT;
    data[0] = static_cast<uint8_t>(length);
    return TLV_OK;
}
} // namespace

TEST(Unit_Tlv_Format, RuntimeDefinedTagWidthsRoundTripWithoutRebuilding) {
    // Widths above the former default capacity of 8, including the 12 bytes of the motivating case.
    for (size_t tag_width :
         {size_t(1), size_t(2), size_t(8), size_t(9), size_t(12), size_t(64), size_t(300)}) {
        SCOPED_TRACE(tag_width);
        const RuntimeTagFormat        context = {tag_width};
        const tlv_field_composition_t reader_format_layout = {
            &context, runtime_read_tag, one_byte_read_length,  nullptr,
            nullptr,  nullptr,          TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
        const tlv_format_t reader_format = {&reader_format_layout, tlv_fields_decode, nullptr,
                                            nullptr, nullptr};
        const tlv_field_composition_t writer_format_layout = {&context,
                                                              nullptr,
                                                              nullptr,
                                                              nullptr,
                                                              runtime_write_tag,
                                                              one_byte_write_length,
                                                              TLV_ELEMENT_ORDER_TLV,
                                                              TLV_LENGTH_SCOPE_VALUE};
        const tlv_format_t   writer_format = {&writer_format_layout, nullptr, tlv_fields_measure,
                                              tlv_fields_encode, nullptr};
        std::vector<uint8_t> tag_bytes(tag_width);
        for (size_t i = 0; i < tag_width; ++i) tag_bytes[i] = static_cast<uint8_t>(0x10 + i);
        const uint8_t value[] = {0xAA, 0xBB};

        std::vector<uint8_t> wire(tag_width + 1 + sizeof(value));
        size_t               written = 0;
        ASSERT_EQ(TLV_OK, tlv_write(wire.data(), wire.size(), &writer_format,
                                    tlv_tag(tag_bytes.data(), tag_bytes.size()), value,
                                    sizeof(value), &written));
        EXPECT_EQ(wire.size(), written);

        tlv_element_t element{};
        size_t        consumed = 0;
        ASSERT_EQ(TLV_OK, tlv_read(wire.data(), wire.size(), &reader_format, &element, &consumed));
        EXPECT_EQ(wire.size(), consumed);
        // The tag is a window onto the input, not a copy.
        EXPECT_EQ(wire.data(), element.tag.data);
        EXPECT_EQ(tag_width, element.tag.size);
        EXPECT_TRUE(tlv_tag_equal(element.tag, tlv_tag(tag_bytes.data(), tag_bytes.size())));
        EXPECT_EQ(sizeof(value), static_cast<size_t>(element.value.size));

        // The format, not the tag type, rejects a tag of another width.
        std::vector<uint8_t> other(tag_width + 1, 0x42);
        EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE,
                  tlv_write(wire.data(), wire.size(), &writer_format,
                            tlv_tag(other.data(), other.size()), value, sizeof(value), &written));
    }
}
