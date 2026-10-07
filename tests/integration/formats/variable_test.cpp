// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/formats/variable.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#include "tlv/size.h"
#include <gtest/gtest.h>
#include <array>
#include <cstring>
#include <vector>

namespace {
const tlv_variable_format_t config = {{0x70, 0x20, 0x01, 0xF0, 8, NULL},
                                      {0x80, 0x7F, TLV_BYTE_ORDER_LITTLE_ENDIAN, NULL},
                                      TLV_ELEMENT_ORDER_TLV,
                                      TLV_LENGTH_SCOPE_VALUE,
                                      NULL};

// A synthetic container: zero-width long count, definite child elements, FA FB
// trailer recognized only at child boundaries. This policy belongs to this
// fixture; the generic identifier/count primitives know nothing about it.
tlv_result_t resolve(const void* context, const tlv_tag_t*, const uint8_t* data, size_t size,
                     size_t* length_size, tlv_size_t* value_size, size_t* trailer_size,
                     tlv_format_error_t* error) {
    const auto* c = static_cast<const tlv_variable_format_t*>(context);
    *length_size = size ? 1 : 0;
    if (!size) return TLV_ERR_BUFFER_TOO_SHORT;
    *trailer_size = 0;
    if (data[0] != 0x80)
        return tlv_variable_length_read(&c->length, data, size, value_size, length_size);
    tlv_format_t child_format = {};
    tlv_result_t rc = tlv_variable_format_init(&child_format, c);
    if (rc != TLV_OK) return rc;
    size_t pos = 1;
    while (pos < size) {
        if (data[pos] == 0xFA) {
            if (size - pos < 2) break;
            if (data[pos + 1] != 0xFB) return TLV_ERR_INVALID_LENGTH;
            *value_size = pos - 1;
            *trailer_size = 2;
            return TLV_OK;
        }
        tlv_decoded_t child = {};
        rc = tlv_format_decode(&child_format, data + pos, size - pos, &child, error);
        if (rc != TLV_OK) {
            if (error->has_offset) error->offset += pos;
            return rc;
        }
        pos += child.source.size;
    }
    error->region = TLV_REGION_TRAILER;
    error->offset = pos;
    error->has_offset = 1;
    return TLV_ERR_BUFFER_TOO_SHORT;
}

tlv_result_t terminated_measure(const void* context, const tlv_element_t* element,
                                tlv_encoding_t* encoding, tlv_format_error_t*) {
    const auto*  fields = static_cast<const tlv_field_composition_t*>(context);
    size_t       tag_size = 0;
    tlv_result_t rc = fields->write_tag(fields->context, &element->tag, nullptr, 0, &tag_size);
    if (rc != TLV_OK) return rc;
    encoding->header = tag_size + tlv_size_t{1};
    encoding->value = element->value.size;
    encoding->trailer = 2;
    rc = tlv_size_add(encoding->header, encoding->value, &encoding->total);
    return rc == TLV_OK ? tlv_size_add(encoding->total, 2, &encoding->total) : rc;
}

tlv_result_t terminated_encode(const void* context, const tlv_element_t* element, uint8_t* data,
                               size_t capacity, size_t* written, tlv_format_error_t* error) {
    tlv_encoding_t encoding = {};
    tlv_result_t   rc = terminated_measure(context, element, &encoding, error);
    if (rc != TLV_OK) return rc;
    size_t total = 0;
    rc = tlv_size_to_native(encoding.total, &total);
    if (rc != TLV_OK) return rc;
    if (capacity < total) return TLV_ERR_BUFFER_TOO_SHORT;
    std::memcpy(data, element->tag.data, element->tag.size);
    data[element->tag.size] = 0x80;
    if (element->value.size)
        std::memcpy(data + element->tag.size + 1, element->value.data,
                    static_cast<size_t>(element->value.size));
    data[total - 2] = 0xFA;
    data[total - 1] = 0xFB;
    *written = total;
    return TLV_OK;
}
} // namespace

TEST(Integration_Tlv_Variable, ReaderWriterAndLayoutAcrossOrderAndScope) {
    const uint8_t              tag_bytes[] = {0xA5, 0xB1, 0xC0};
    const std::vector<uint8_t> value(256, 0xCC);
    for (auto order : {TLV_ELEMENT_ORDER_TLV, TLV_ELEMENT_ORDER_LTV}) {
        for (auto scope : {TLV_LENGTH_SCOPE_VALUE, TLV_LENGTH_SCOPE_TAG_AND_VALUE}) {
            auto c = config;
            c.element_order = order;
            c.length_scope = scope;
            tlv_format_t format = {};
            ASSERT_EQ(TLV_OK, tlv_variable_format_init(&format, &c));
            EXPECT_EQ(&c, format.context);
            EXPECT_EQ(nullptr, format.is_constructed);
            const auto          copied = format;
            const tlv_element_t element = {tlv_tag(tag_bytes, 3), {value.data(), value.size()}};
            tlv_encoding_t      sizes = {};
            ASSERT_EQ(TLV_OK, tlv_format_measure(&copied, &element, &sizes, nullptr));
            EXPECT_EQ(6u, sizes.header);
            EXPECT_EQ(262u, sizes.total);
            std::vector<uint8_t> bytes(262);
            tlv_writer_t         writer = {};
            ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, bytes.data(), bytes.size(), &copied));
            ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, element.tag, value.data(), value.size()));
            EXPECT_EQ(bytes.size(), writer.pos);
            const size_t tag_offset = order == TLV_ELEMENT_ORDER_TLV ? 0 : 3;
            const size_t length_offset = 3 - tag_offset;
            EXPECT_EQ(0, std::memcmp(bytes.data() + tag_offset, tag_bytes, 3));
            EXPECT_EQ(0x82, bytes[length_offset]);
            EXPECT_EQ(scope == TLV_LENGTH_SCOPE_VALUE ? 0 : 3, bytes[length_offset + 1]);
            EXPECT_EQ(1, bytes[length_offset + 2]);
            tlv_decoded_t decoded = {};
            ASSERT_EQ(TLV_OK,
                      tlv_format_decode(&copied, bytes.data(), bytes.size(), &decoded, nullptr));
            EXPECT_EQ(bytes.data() + tag_offset, decoded.element.tag.data);
            EXPECT_EQ(tag_offset, decoded.source.tag.offset);
            EXPECT_EQ(length_offset, decoded.source.length.offset);
            EXPECT_EQ(3u, decoded.source.length.size);
            EXPECT_EQ(6u, decoded.source.value.offset);
            EXPECT_EQ(0u, decoded.source.trailer.size);
            EXPECT_EQ(bytes.size(), decoded.source.size);
            tlv_reader_t reader = {};
            ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, bytes.data(), bytes.size(), &copied));
            tlv_element_t read = {};
            ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &read));
            EXPECT_EQ(value.size(), read.value.size);
            EXPECT_EQ(TLV_ERR_END_OF_BUFFER, tlv_reader_next(&reader, &read));
        }
    }
}

TEST(Integration_Tlv_Variable, SemanticEncodingVersusExactSourcePreservation) {
    tlv_format_t format = {};
    ASSERT_EQ(TLV_OK, tlv_variable_format_init(&format, &config));
    const uint8_t bytes[] = {0xA5, 0x01, 0, 0x82, 1, 0, 0xCC};
    tlv_decoded_t decoded = {};
    ASSERT_EQ(TLV_OK, tlv_format_decode(&format, bytes, sizeof(bytes), &decoded, nullptr));
    EXPECT_EQ(3u, decoded.element.tag.size); // Nonminimal identifier remains byte identity.
    uint8_t out[sizeof(bytes)] = {};
    size_t  used = 0;
    ASSERT_EQ(TLV_OK,
              tlv_source_preserve(&decoded.source, &decoded.element, out, sizeof(out), &used));
    EXPECT_EQ(sizeof(bytes), used);
    EXPECT_EQ(0, std::memcmp(out, bytes, used));
    ASSERT_EQ(TLV_OK,
              tlv_format_encode(&format, &decoded.element, out, sizeof(out), &used, nullptr));
    const uint8_t canonical[] = {0xA5, 0x01, 0, 1, 0xCC};
    EXPECT_EQ(sizeof(canonical), used);
    EXPECT_EQ(0, std::memcmp(out, canonical, used));
}

TEST(Integration_Tlv_Variable, ErrorsKeepReaderWriterStateAndProvideFieldLocations) {
    tlv_format_t format = {};
    ASSERT_EQ(TLV_OK, tlv_variable_format_init(&format, &config));
    const uint8_t      bytes[] = {0xA5, 0xC0, 0x83, 0xFF};
    tlv_decoded_t      decoded = {};
    tlv_format_error_t error = {};
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              tlv_format_decode(&format, bytes, sizeof(bytes), &decoded, &error));
    EXPECT_EQ(TLV_REGION_LENGTH, error.region);
    EXPECT_EQ(2u, error.offset);
    EXPECT_EQ(2u, error.length.size);
    tlv_reader_t  reader = {};
    tlv_element_t element = {};
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, bytes, sizeof(bytes), &format));
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_reader_next(&reader, &element));
    EXPECT_EQ(0u, reader.pos);
    uint8_t      destination[] = {0xCC};
    tlv_writer_t writer = {};
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, destination, 1, &format));
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_writer_write(&writer, tlv_tag(bytes, 2), nullptr, 0));
    EXPECT_EQ(0u, writer.pos);
    EXPECT_EQ(0xCC, destination[0]);
    auto scoped = config;
    scoped.length_scope = TLV_LENGTH_SCOPE_TAG_AND_VALUE;
    ASSERT_EQ(TLV_OK, tlv_variable_format_init(&format, &scoped));
    const uint8_t underflow[] = {0xA5, 0xC0, 1};
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
              tlv_format_decode(&format, underflow, sizeof(underflow), &decoded, &error));
    EXPECT_EQ(TLV_REGION_LENGTH, error.region);
    const tlv_element_t huge = {tlv_tag(bytes, 2), {nullptr, UINT64_MAX}};
    tlv_encoding_t      sizes = {};
    EXPECT_EQ(TLV_ERR_OVERFLOW, tlv_format_measure(&format, &huge, &sizes, nullptr));
}

TEST(Integration_Tlv_Variable, ComposesTerminatedBoundsAndTrailerWithoutBuiltinPolicy) {
    tlv_field_composition_t fields = {};
    ASSERT_EQ(TLV_OK, tlv_variable_fields_init(&fields, &config));
    fields.resolve = resolve;
    const tlv_format_t format = {&fields, tlv_fields_decode, terminated_measure, terminated_encode,
                                 nullptr};
    // The apparent terminator inside the definite child's payload is skipped.
    const uint8_t bytes[] = {0xA5, 0xC0, 0x80, 0x10, 2, 0xFA, 0xFB, 0xFA, 0xFB, 0xEE};
    tlv_decoded_t decoded = {};
    ASSERT_EQ(TLV_OK, tlv_format_decode(&format, bytes, sizeof(bytes), &decoded, nullptr));
    EXPECT_EQ(4u, decoded.element.value.size);
    EXPECT_EQ(1u, decoded.source.length.size);
    EXPECT_EQ(7u, decoded.source.trailer.offset);
    EXPECT_EQ(2u, decoded.source.trailer.size);
    EXPECT_EQ(9u, decoded.source.size);
    tlv_encoding_t encoding = {};
    ASSERT_EQ(TLV_OK, tlv_format_measure(&format, &decoded.element, &encoding, nullptr));
    EXPECT_EQ(9u, encoding.total);
    EXPECT_EQ(2u, encoding.trailer);
    uint8_t out[9] = {};
    size_t  used = 0;
    ASSERT_EQ(TLV_OK,
              tlv_format_encode(&format, &decoded.element, out, sizeof(out), &used, nullptr));
    EXPECT_EQ(9u, used);
    EXPECT_EQ(0, std::memcmp(bytes, out, used));
    tlv_format_error_t error = {};
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_format_decode(&format, bytes, 7, &decoded, &error));
    EXPECT_EQ(TLV_REGION_TRAILER, error.region);
    EXPECT_EQ(7u, error.offset);
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_format_decode(&format, bytes, 8, &decoded, &error));
}

TEST(Integration_Tlv_Variable, DeclarativeThreeByteTagsMinimalLengthsAndConstructedBit) {
    static const uint8_t                 forbidden[] = {0};
    static const tlv_identifier_policy_t tag_policy = {forbidden, 1, 1, 0};
    static const tlv_length_policy_t     length_policy = {1, 1, 1, 2, 65535};
    static const tlv_constructed_bit_t   constructed = {0, 0x20, 0x20};
    const tlv_variable_format_t          config = {
        {0x1F, 0x1F, 0x80, 0x7F, 3, &tag_policy},
        {0x80, 0x7F, TLV_BYTE_ORDER_LITTLE_ENDIAN, &length_policy},
        TLV_ELEMENT_ORDER_TLV,
        TLV_LENGTH_SCOPE_VALUE,
        &constructed};
    tlv_format_t format{};
    ASSERT_EQ(TLV_OK, tlv_variable_format_init(&format, &config));
    const uint8_t            tag[] = {0xBF, 0x81, 0x01};
    std::array<uint8_t, 256> value{};
    const tlv_element_t      element = {tlv_tag(tag, sizeof(tag)), {value.data(), value.size()}};
    std::array<uint8_t, 262> wire{};
    size_t                   written = 0;
    ASSERT_EQ(TLV_OK,
              tlv_format_encode(&format, &element, wire.data(), wire.size(), &written, nullptr));
    const uint8_t expected_header[] = {0xBF, 0x81, 1, 0x82, 0, 1};
    EXPECT_EQ(0, std::memcmp(expected_header, wire.data(), sizeof(expected_header)));
    tlv_decoded_t decoded{};
    ASSERT_EQ(TLV_OK, tlv_format_decode(&format, wire.data(), written, &decoded, nullptr));
    EXPECT_EQ(1, format.is_constructed(format.context, &decoded.element.tag));
    EXPECT_EQ(256u, decoded.element.value.size);
    EXPECT_EQ(wire.data(), decoded.element.tag.data);
    const uint8_t      padded[] = {1, 0x81, 1, 42};
    tlv_format_error_t error{};
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
              tlv_format_decode(&format, padded, sizeof(padded), &decoded, &error));
    EXPECT_EQ(TLV_REGION_LENGTH, error.region);
    EXPECT_EQ(1u, error.offset);
    const uint8_t width_error[] = {1, 0x83};
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
              tlv_format_decode(&format, width_error, sizeof(width_error), &decoded, &error));
    EXPECT_EQ(1u, error.length.size);
}
