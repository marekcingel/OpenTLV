// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/format.h"
#include "tlv/size.h"
#include "tlv/element.h"

#include <gtest/gtest.h>

#include <vector>
#include <algorithm>

TEST(Unit_Tlv_Element, ZeroInitializationProducesEmptyElement) {
    tlv_source_t source{};
    (void)source;
    tlv_element_t empty{};
    EXPECT_EQ(nullptr, empty.tag.data);
    EXPECT_EQ(0u, empty.tag.size);

    EXPECT_EQ(nullptr, empty.value.data);
    EXPECT_EQ(0u, empty.value.size);
}

TEST(Unit_Tlv_Element, TagBorrowsRawBytesOfAnySize) {
    tlv_source_t source{};
    (void)source;
    std::vector<uint8_t> bytes(300);
    for (size_t i = 0; i < bytes.size(); ++i) bytes[i] = static_cast<uint8_t>(0x9F + i);

    for (size_t size : {size_t(1), size_t(2), size_t(8), size_t(9), size_t(16), size_t(300)}) {
        SCOPED_TRACE(size);
        tlv_tag_t tag = tlv_tag(bytes.data(), size);
        tlv_tag_t copy = tag;
        // A copy refers to the same bytes: nothing is stored inline.
        EXPECT_EQ(bytes.data(), copy.data);
        EXPECT_EQ(size, copy.size);
        bytes[0] = static_cast<uint8_t>(bytes[0] + 1);
        EXPECT_EQ(bytes[0], copy.data[0]);
        bytes[0] = static_cast<uint8_t>(bytes[0] - 1);
    }
}

TEST(Unit_Tlv_Element, CopyingElementBorrowsEveryField) {
    tlv_source_t source{};
    (void)source;
    uint8_t tag_bytes[] = {0x81};

    uint8_t       storage[] = {0x12, 0x34, 0x56};
    tlv_element_t element = {tlv_tag(tag_bytes, sizeof(tag_bytes)), {storage + 1, 2}};
    tlv_element_t copy = element;
    EXPECT_EQ(1u, copy.tag.size);
    EXPECT_EQ(tag_bytes, copy.tag.data);

    EXPECT_EQ(storage + 1, copy.value.data);
    EXPECT_EQ(2u, copy.value.size);
    storage[1] = 0xAB;
    EXPECT_EQ(0xAB, copy.value.data[0]);
    EXPECT_EQ(0x56, copy.value.data[1]);
    // The tag is borrowed as well, so a change of the bytes shows in every copy.
    tag_bytes[0] = 0x00;
    EXPECT_EQ(0x00, copy.tag.data[0]);
}

TEST(Unit_Tlv_Element, ResultDistinguishesSuccessFromError) {
    tlv_source_t source{};
    (void)source;
    tlv_result_t result = TLV_OK;
    EXPECT_EQ(0, result);
    EXPECT_NE(TLV_OK, TLV_ERR_NULL_ARG);
}

#include "tlv/config.h"
#include "tlv/reader/reader.h"
#include "../controlled_format.h"
#include <type_traits>

static_assert(std::is_same<decltype(tlv_value_t{}.size), tlv_size_t>::value,
              "Decoded value sizes use the wire-size type");
static_assert(sizeof(tlv_size_t) == 8, "Logical sizes are always 64 bits");
static_assert(std::is_same<decltype(tlv_length_t{}.size), size_t>::value,
              "Raw length fields have native memory extents");

TEST(Unit_Tlv_Element, OversizedLogicalValuePreservesOutputsAndFullDiagnostic) {
    tlv_source_t source{};
    (void)source;
    const uint8_t data[] = {1, 0};
    auto          layout = controlled::format_layout;
    auto          format = controlled::format;
    format.context = &layout;
    layout.read_length = [](const void*, const uint8_t*, size_t, tlv_size_t* size,
                            size_t* consumed) {
        *size = TLV_SIZE_MAX;
        *consumed = 1;
        return TLV_OK;
    };
    tlv_element_t           element{TLV_TAG(9), {data, 1}};
    size_t                  consumed = 99;
    tlv_reader_diagnostic_t diagnostic{};
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              tlv_read_diag(data, sizeof(data), &format, &element, &consumed, &diagnostic));
    EXPECT_EQ(99u, consumed);
    EXPECT_EQ(9u, element.tag.data[0]);
    EXPECT_EQ(nullptr, source.data);
    EXPECT_EQ(1u, element.value.size);
    EXPECT_EQ(TLV_SIZE_MAX, diagnostic.declared_length);
}

#if OPENTLV_FORMAT_BER
#include "tlv/builtins/asn1/ber.h"
TEST(Unit_Tlv_Element, RetainsMultibyteTagAndNonminimalLengthExactly) {
    tlv_source_t source{};
    (void)source;
    const uint8_t data[] = {0x9F, 0x20, 0x82, 0x00, 0x01, 0xAA};
    tlv_element_t element{};
    size_t        consumed = 0;
    ASSERT_EQ(TLV_OK, tlv_read_source_diag(data, sizeof(data), &tlv_format_ber, &element, &consumed,
                                           &source, nullptr));
    EXPECT_EQ(data, element.tag.data);
    EXPECT_EQ(2u, element.tag.size);
    EXPECT_EQ(data + 2, (source.data + source.length.offset));
    EXPECT_EQ(3u, source.length.size);
    EXPECT_EQ(data + 5, element.value.data);
    EXPECT_EQ(1u, element.value.size);
    EXPECT_EQ(sizeof(data), consumed);
}

TEST(Unit_Tlv_Element, EmptyAndTerminatedValuesKeepTheirRawLength) {
    tlv_source_t source{};
    (void)source;
    const uint8_t empty[] = {0x04, 0x00};
    const uint8_t terminated[] = {0x30, 0x80, 0x04, 0x00, 0x00, 0x00};
    tlv_element_t element{};
    size_t        consumed = 0;
    ASSERT_EQ(TLV_OK, tlv_read_source_diag(empty, sizeof(empty), &tlv_format_ber, &element,
                                           &consumed, &source, nullptr));
    EXPECT_EQ(empty + 1, (source.data + source.length.offset));
    EXPECT_EQ(1u, source.length.size);
    EXPECT_EQ(0u, element.value.size);
    ASSERT_EQ(TLV_OK, tlv_read_source_diag(terminated, sizeof(terminated), &tlv_format_ber,
                                           &element, &consumed, &source, nullptr));
    EXPECT_EQ(terminated + 1, (source.data + source.length.offset));
    EXPECT_EQ(0x80, (source.data + source.length.offset)[0]);
    EXPECT_EQ(1u, source.length.size);
    EXPECT_EQ(2u, element.value.size);
    EXPECT_EQ(sizeof(terminated), consumed);
}

TEST(Unit_Tlv_Element, TruncationDoesNotPublishPartialRawFields) {
    tlv_source_t source{};
    (void)source;
    const uint8_t data[] = {0x9F, 0x20, 0x82, 0x00, 0x01, 0xAA};
    for (size_t size = 0; size < sizeof(data); ++size) {
        tlv_element_t element{TLV_TAG(9), {data, 1}};
        size_t        consumed = 99;
        EXPECT_NE(TLV_OK, tlv_read_source_diag(data, size, &tlv_format_ber, &element, &consumed,
                                               &source, nullptr));
        EXPECT_EQ(99u, consumed);
        EXPECT_EQ(9u, element.tag.data[0]);
        EXPECT_EQ(nullptr, source.data);
        EXPECT_EQ(0u, source.length.size);
        EXPECT_EQ(data, element.value.data);
        EXPECT_EQ(1u, element.value.size);
    }
}
#endif

#if OPENTLV_BLUETOOTH
#include "tlv/builtins/bluetooth/bluetooth_ltv.h"
TEST(Unit_Tlv_Element, LengthBeforeTagKeepsRawCountSeparateFromValueSize) {
    tlv_source_t source{};
    (void)source;
    const uint8_t data[] = {3, 0xFF, 0xAA, 0xBB};
    tlv_element_t element{};
    size_t        consumed = 0;
    ASSERT_EQ(TLV_OK, tlv_read_source_diag(data, sizeof(data), &tlv_format_bluetooth_ltv, &element,
                                           &consumed, &source, nullptr));
    EXPECT_EQ(data, (source.data + source.length.offset));
    EXPECT_EQ(1u, source.length.size);
    EXPECT_EQ(3u, (source.data + source.length.offset)[0]);
    EXPECT_EQ(data + 1, element.tag.data);
    EXPECT_EQ(data + 2, element.value.data);
    EXPECT_EQ(2u, element.value.size);
}
#endif

#if OPENTLV_FORMAT_BER
TEST(Unit_Tlv_Element, BerOversizedValueKeepsDecodedAndRawLengthInDiagnostic) {
    tlv_source_t source{};
    (void)source;
    std::vector<uint8_t> data(7 + 127, 0);
    const uint8_t        header[] = {0x04, 0x85, 1, 0, 0, 0, 0};
    std::copy(header, header + sizeof(header), data.begin());
    tlv_element_t           element{};
    size_t                  consumed = 99;
    tlv_reader_diagnostic_t diagnostic{};
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_read_diag(data.data(), data.size(), &tlv_format_ber,
                                                      &element, &consumed, &diagnostic));
    EXPECT_EQ(99u, consumed);
    EXPECT_EQ(nullptr, element.tag.data);
    ASSERT_TRUE(diagnostic.has_declared_length);
    EXPECT_EQ(UINT64_C(4294967296), diagnostic.declared_length);
    EXPECT_EQ(127u, diagnostic.available);
    ASSERT_TRUE(diagnostic.has_raw_length);
    EXPECT_EQ(data.data() + 1, diagnostic.raw_length.data);
    EXPECT_EQ(6u, diagnostic.raw_length.size);
}

TEST(Unit_Tlv_Element, LogicalOverflowAndTruncatedLengthKeepAvailableRawBytes) {
    tlv_source_t source{};
    (void)source;
    const uint8_t           overflow[] = {0x04, 0x89, 1, 0, 0, 0, 0, 0, 0, 0, 0};
    tlv_element_t           element{};
    size_t                  consumed = 99;
    tlv_reader_diagnostic_t diagnostic{};
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_read_diag(overflow, sizeof(overflow), &tlv_format_ber,
                                                    &element, &consumed, &diagnostic));
    EXPECT_FALSE(diagnostic.has_declared_length);
    ASSERT_TRUE(diagnostic.has_raw_length);
    EXPECT_EQ(overflow + 1, diagnostic.raw_length.data);
    EXPECT_EQ(10u, diagnostic.raw_length.size);
    EXPECT_EQ(99u, consumed);
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              tlv_read_diag(overflow, 4, &tlv_format_ber, &element, &consumed, &diagnostic));
    ASSERT_TRUE(diagnostic.has_raw_length);
    EXPECT_EQ(3u, diagnostic.raw_length.size);
    EXPECT_EQ(99u, consumed);
}
#endif

#include "tlv/formats/fixed.h"
TEST(Unit_Tlv_Element, FixedSizeDomainIsIndependentOfFieldOrderAndByteOrder) {
    tlv_source_t source{};
    (void)source;
    for (auto byte_order : {TLV_BYTE_ORDER_BIG_ENDIAN, TLV_BYTE_ORDER_LITTLE_ENDIAN}) {
        for (auto order : {TLV_ELEMENT_ORDER_TLV, TLV_ELEMENT_ORDER_LTV}) {
            const tlv_fixed_format_t config = {{2}, {8, byte_order}, order, TLV_LENGTH_SCOPE_VALUE};
            tlv_format_t             format{};
            ASSERT_EQ(TLV_OK, tlv_fixed_format_init(&format, &config));
            uint8_t      data[11] = {};
            const size_t length_offset = order == TLV_ELEMENT_ORDER_TLV ? 2 : 0;
            const size_t tag_offset = order == TLV_ELEMENT_ORDER_TLV ? 0 : 8;
            data[tag_offset] = 0x9F;
            data[tag_offset + 1] = 0x02;
            ASSERT_EQ(TLV_OK, tlv_write_uint(data + length_offset, 8, byte_order, 1));
            data[10] = 0xAA;
            tlv_element_t element{};
            size_t        consumed = 0;
            ASSERT_EQ(TLV_OK, tlv_read_source_diag(data, sizeof(data), &format, &element, &consumed,
                                                   &source, nullptr));
            EXPECT_EQ(data + tag_offset, element.tag.data);
            EXPECT_EQ(data + length_offset, (source.data + source.length.offset));
            EXPECT_EQ(8u, source.length.size);
            EXPECT_EQ(data + 10, element.value.data);
            EXPECT_EQ(1u, element.value.size);
            ASSERT_EQ(TLV_OK, tlv_write_uint(data + length_offset, 8, byte_order, TLV_SIZE_MAX));
            tlv_reader_diagnostic_t diagnostic{};
            EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
                      tlv_read_diag(data, sizeof(data), &format, &element, &consumed, &diagnostic));
            EXPECT_EQ(TLV_SIZE_MAX, diagnostic.declared_length);
            EXPECT_EQ(1u, diagnostic.available);
            EXPECT_TRUE(diagnostic.has_raw_length);
            EXPECT_EQ(data + length_offset, diagnostic.raw_length.data);
            EXPECT_EQ(8u, diagnostic.raw_length.size);
            EXPECT_EQ(1u, element.value.size);
        }
    }
}

#if OPENTLV_FORMAT_DER
#include "tlv/builtins/asn1/der.h"
#include "tlv/builtins/asn1/der_validation.h"
TEST(Unit_Tlv_Element, DerRejectsNonminimalLengthButPreservesItsRawFieldInDiagnostic) {
    tlv_source_t source{};
    (void)source;
    const uint8_t           bytes[] = {4, 0x82, 0, 0x7F};
    tlv_element_t           element{};
    size_t                  consumed = 99;
    tlv_reader_diagnostic_t diagnostic{};
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_read_diag(bytes, sizeof(bytes), &tlv_format_der, &element,
                                                    &consumed, &diagnostic));
    EXPECT_EQ(99u, consumed);
    EXPECT_TRUE(diagnostic.has_raw_length);
    EXPECT_EQ(bytes + 1, diagnostic.raw_length.data);
    EXPECT_EQ(3u, diagnostic.raw_length.size);
}
TEST(Unit_Tlv_Element, DerValidationPublishesTheSameRawFields) {
    tlv_source_t source{};
    (void)source;
    const uint8_t bytes[] = {4, 1, 0xAA};
    tlv_element_t element{};
    size_t        consumed = 0;
    ASSERT_EQ(TLV_OK, tlv_read_source_diag(bytes, sizeof(bytes), &tlv_format_der, &element,
                                           &consumed, &source, nullptr));
    EXPECT_EQ(bytes + 1, (source.data + source.length.offset));
    EXPECT_EQ(1u, source.length.size);
    EXPECT_EQ(1u, element.value.size);
}
#endif

#if OPENTLV_FORMAT_CER
#include "tlv/builtins/asn1/cer_validation.h"
TEST(Unit_Tlv_Element, CerValidationPreservesPrimitiveAndIndefiniteLengthFields) {
    tlv_source_t source{};
    (void)source;
    const uint8_t bytes[] = {0x30, 0x80, 4, 1, 0xAA, 0, 0};
    tlv_element_t element{};
    size_t        consumed = 0;
    ASSERT_EQ(TLV_OK, tlv_read_source_diag(bytes, sizeof(bytes), &tlv_format_cer, &element,
                                           &consumed, &source, nullptr));
    EXPECT_EQ(bytes + 1, (source.data + source.length.offset));
    EXPECT_EQ(1u, source.length.size);
    EXPECT_EQ(3u, element.value.size);
    ASSERT_EQ(TLV_OK, tlv_read_source_diag(bytes + 2, 3, &tlv_format_cer, &element, &consumed,
                                           &source, nullptr));
    EXPECT_EQ(bytes + 3, (source.data + source.length.offset));
    EXPECT_EQ(1u, source.length.size);
    EXPECT_EQ(1u, element.value.size);
}
#endif

#include "tlv/writer/writer.h"
#include <cstring>
namespace {
// Header A5, tag, one-byte value count, arbitrary padding; trailer XOR(value).
tlv_result_t framed_decode(const void*, const uint8_t* data, size_t size, tlv_decoded_t* result,
                           tlv_format_error_t* error) {
    error->region = TLV_REGION_HEADER;
    error->has_offset = 1;
    if (size < 4) return TLV_ERR_BUFFER_TOO_SHORT;
    if (data[0] != 0xA5) return TLV_ERR_INVALID_VALUE;
    error->tag = {1, 1, 1};
    error->length = {2, 1, 1};
    const size_t n = data[2];
    error->region = TLV_REGION_VALUE;
    error->offset = 4;
    error->has_required = 1;
    error->required = n;
    if (n > size - 4) return TLV_ERR_BUFFER_TOO_SHORT;
    error->region = TLV_REGION_TRAILER;
    error->offset = 4 + n;
    error->required = 1;
    if (size - 4 - n < 1) return TLV_ERR_BUFFER_TOO_SHORT;
    uint8_t checksum = 0;
    for (size_t i = 0; i < n; ++i) checksum ^= data[4 + i];
    if (data[4 + n] != checksum) return TLV_ERR_INVALID_VALUE;
    result->element = {tlv_tag(data + 1, 1), {data + 4, n}};
    result->source.header = {0, 4, 1};
    result->source.tag = {1, 1, 1};
    result->source.length = {2, 1, 1};
    result->source.value = {4, n, 1};
    result->source.trailer = {4 + n, 1, 1};
    result->source.size = 5 + n;
    return TLV_OK;
}
tlv_result_t framed_measure(const void*, const tlv_element_t* element, tlv_encoding_t* encoding,
                            tlv_format_error_t*) {
    if (element->tag.size != 1) return TLV_ERR_INVALID_TAG_SIZE;
    if (element->value.size > 255) return TLV_ERR_INVALID_LENGTH;
    *encoding = {4, element->value.size, 1, 5 + element->value.size};
    return TLV_OK;
}
tlv_result_t framed_encode(const void*, const tlv_element_t* element, uint8_t* data,
                           size_t capacity, size_t* written, tlv_format_error_t*) {
    const auto n = static_cast<size_t>(element->value.size);
    if (capacity < 5 + n) return TLV_ERR_BUFFER_TOO_SHORT;
    data[0] = 0xA5;
    data[1] = element->tag.data[0];
    data[2] = static_cast<uint8_t>(n);
    data[3] = 0;
    uint8_t checksum = 0;
    for (size_t i = 0; i < n; ++i) {
        data[4 + i] = element->value.data[i];
        checksum ^= data[4 + i];
    }
    data[4 + n] = checksum;
    *written = 5 + n;
    return TLV_OK;
}
const tlv_format_t framed_format = {nullptr, framed_decode, framed_measure, framed_encode, nullptr};
} // namespace
TEST(Unit_Tlv_FormatContract, TrailerPreservationMutationAndSemanticEncoding) {
    const uint8_t wire[] = {0xA5, 7, 1, 0x9C, 0xAA, 0xAA};
    tlv_decoded_t decoded{};
    ASSERT_EQ(TLV_OK, tlv_format_decode(&framed_format, wire, sizeof(wire), &decoded, nullptr));
    EXPECT_EQ(4u, decoded.source.header.size);
    EXPECT_EQ(1u, decoded.source.trailer.size);
    uint8_t output[16] = {};
    size_t  written = 99;
    ASSERT_EQ(TLV_OK, tlv_source_preserve(&decoded.source, &decoded.element, output, sizeof(output),
                                          &written));
    EXPECT_EQ(sizeof(wire), written);
    EXPECT_EQ(0, std::memcmp(wire, output, written));
    const uint8_t changed[] = {0xBB, 0xCC};
    auto          element = decoded.element;
    element.value = {changed, sizeof(changed)};
    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              tlv_source_preserve(&decoded.source, &element, output, sizeof(output), &written));
    ASSERT_EQ(TLV_OK, tlv_format_encode(&framed_format, &element, output, sizeof(output), &written,
                                        nullptr));
    const uint8_t expected[] = {0xA5, 7, 2, 0, 0xBB, 0xCC, 0x77};
    EXPECT_EQ(sizeof(expected), written);
    EXPECT_EQ(0, std::memcmp(expected, output, written));
    tlv_decoded_t again{};
    ASSERT_EQ(TLV_OK, tlv_format_decode(&framed_format, output, written, &again, nullptr));
    EXPECT_EQ(element.value.size, again.element.value.size);
    EXPECT_EQ(0, std::memcmp(changed, again.element.value.data, sizeof(changed)));
    // Same-width mutation must also invalidate preservation.
    const uint8_t other = 0xBB;
    element.value = {&other, 1};
    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              tlv_source_preserve(&decoded.source, &element, output, sizeof(output), &written));
}
TEST(Unit_Tlv_FormatContract, EveryTruncatedRegionAndInvalidTrailerAreDiagnosedOnce) {
    uint8_t wire[] = {0xA5, 7, 1, 0x9C, 0xAA, 0xAA};
    for (size_t size = 1; size < sizeof(wire); ++size) {
        tlv_decoded_t result{};
        result.source.size = 99;
        tlv_format_error_t error{};
        ASSERT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
                  tlv_format_decode(&framed_format, wire, size, &result, &error));
        EXPECT_EQ(99u, result.source.size);
        EXPECT_EQ(size < 4    ? TLV_REGION_HEADER
                  : size == 4 ? TLV_REGION_VALUE
                              : TLV_REGION_TRAILER,
                  error.region);
        tlv_reader_diagnostic_t diagnostic{};
        tlv_element_t           element{};
        size_t                  consumed = 99;
        ASSERT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
                  tlv_read_diag(wire, size, &framed_format, &element, &consumed, &diagnostic));
        EXPECT_EQ(99u, consumed);
        EXPECT_EQ(error.region == TLV_REGION_VALUE, diagnostic.has_declared_length != 0);
    }
    wire[5] = 0;
    tlv_decoded_t      result{};
    tlv_format_error_t error{};
    EXPECT_EQ(TLV_ERR_INVALID_VALUE,
              tlv_format_decode(&framed_format, wire, sizeof(wire), &result, &error));
    EXPECT_EQ(TLV_REGION_TRAILER, error.region);
    EXPECT_EQ(5u, error.offset);
}
#if OPENTLV_FORMAT_BER
TEST(Unit_Tlv_FormatContract, BerNonminimalAndNestedIndefinitePreserveExactly) {
    for (const auto& wire : {std::vector<uint8_t>{4, 0x81, 1, 0xAA},
                             std::vector<uint8_t>{0x30, 0x80, 0x30, 0x80, 0, 0, 0, 0}}) {
        tlv_decoded_t result{};
        ASSERT_EQ(TLV_OK,
                  tlv_format_decode(&tlv_format_ber, wire.data(), wire.size(), &result, nullptr));
        std::vector<uint8_t> output(wire.size());
        size_t               written = 0;
        ASSERT_EQ(TLV_OK, tlv_source_preserve(&result.source, &result.element, output.data(),
                                              output.size(), &written));
        EXPECT_EQ(wire, output);
        ASSERT_EQ(TLV_OK, tlv_format_encode(&tlv_format_ber, &result.element, output.data(),
                                            output.size(), &written, nullptr));
        tlv_decoded_t again{};
        ASSERT_EQ(TLV_OK,
                  tlv_format_decode(&tlv_format_ber, output.data(), written, &again, nullptr));
        EXPECT_EQ(result.element.value.size, again.element.value.size);
        EXPECT_EQ(0, std::memcmp(result.element.value.data, again.element.value.data,
                                 static_cast<size_t>(again.element.value.size)));
    }
}
#endif
#if OPENTLV_FORMAT_CER
TEST(Unit_Tlv_FormatContract, GenericCerConstructedWriterProducesReadableFraming) {
    const uint8_t       value[] = {2, 1, 1};
    const tlv_element_t element = {TLV_TAG(0x30), {value, sizeof(value)}};
    tlv_encoding_t      sizes{};
    ASSERT_EQ(TLV_OK, tlv_format_measure(&tlv_format_cer, &element, &sizes, nullptr));
    EXPECT_EQ(2u, sizes.header);
    EXPECT_EQ(2u, sizes.trailer);
    uint8_t wire[7] = {};
    size_t  written = 0;
    ASSERT_EQ(TLV_OK,
              tlv_format_encode(&tlv_format_cer, &element, wire, sizeof(wire), &written, nullptr));
    tlv_decoded_t decoded{};
    ASSERT_EQ(TLV_OK, tlv_format_decode(&tlv_format_cer, wire, written, &decoded, nullptr));
    EXPECT_EQ(sizeof(value), decoded.element.value.size);
    EXPECT_EQ(0, std::memcmp(value, decoded.element.value.data, sizeof(value)));
}
#endif

TEST(Unit_Tlv_FormatContract, NoExplicitFieldsAndEmptyHeaderAreValid) {
    tlv_format_t format{};
    format.decode = [](const void*, const uint8_t* data, size_t size, tlv_decoded_t* result,
                       tlv_format_error_t*) {
        if (!size) return TLV_ERR_BUFFER_TOO_SHORT;
        result->element = {{nullptr, 0}, {data, 1}};
        result->source.header = {0, 0, 1};
        result->source.value = {0, 1, 1};
        result->source.trailer = {1, 0, 1};
        result->source.size = 1;
        return TLV_OK;
    };
    format.measure = [](const void*, const tlv_element_t* element, tlv_encoding_t* sizes,
                        tlv_format_error_t*) {
        if (element->tag.data || element->tag.size || element->value.size != 1)
            return TLV_ERR_INVALID_ARG;
        *sizes = {0, 1, 0, 1};
        return TLV_OK;
    };
    format.encode = [](const void*, const tlv_element_t* element, uint8_t* data, size_t capacity,
                       size_t* written, tlv_format_error_t*) {
        if (!capacity) return TLV_ERR_BUFFER_TOO_SHORT;
        data[0] = element->value.data[0];
        *written = 1;
        return TLV_OK;
    };
    const uint8_t wire = 42;
    tlv_decoded_t decoded{};
    ASSERT_EQ(TLV_OK, tlv_format_decode(&format, &wire, 1, &decoded, nullptr));
    EXPECT_FALSE(decoded.source.tag.present);
    EXPECT_FALSE(decoded.source.length.present);
    EXPECT_EQ(nullptr, decoded.element.tag.data);
    uint8_t output = 0;
    size_t  written = 0;
    ASSERT_EQ(TLV_OK, tlv_format_encode(&format, &decoded.element, &output, 1, &written, nullptr));
    EXPECT_EQ(wire, output);
}
TEST(Unit_Tlv_FormatContract, LogicalSizeAndWireLimitsAreSeparate) {
    const tlv_fixed_format_t config = {
        {1}, {8, TLV_BYTE_ORDER_BIG_ENDIAN}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
    tlv_format_t format{};
    ASSERT_EQ(TLV_OK, tlv_fixed_format_init(&format, &config));
    tlv_element_t  element = {TLV_TAG(1), {nullptr, UINT64_C(4294967296)}};
    tlv_encoding_t sizes{};
    ASSERT_EQ(TLV_OK, tlv_format_measure(&format, &element, &sizes, nullptr));
    EXPECT_EQ(UINT64_C(4294967305), sizes.total);
    element.value.size = TLV_SIZE_MAX;
    EXPECT_EQ(TLV_ERR_OVERFLOW, tlv_format_measure(&format, &element, &sizes, nullptr));
    size_t native = 99;
#if SIZE_MAX < UINT64_MAX
    EXPECT_EQ(TLV_ERR_NATIVE_SIZE, tlv_size_to_native(UINT64_C(4294967296), &native));
    EXPECT_EQ(99u, native);
#else
    EXPECT_EQ(TLV_OK, tlv_size_to_native(UINT64_C(4294967296), &native));
#endif
}

TEST(Unit_Tlv_FormatContract, PreservationUsesByteIdentityAndReportsRequiredCapacity) {
    const uint8_t wire[] = {0xA5, 7, 1, 0x9C, 0xAA, 0xAA};
    tlv_decoded_t decoded{};
    ASSERT_EQ(TLV_OK, tlv_format_decode(&framed_format, wire, sizeof(wire), &decoded, nullptr));
    const uint8_t tag = 7;
    const uint8_t value = 0xAA;
    tlv_element_t copied = {tlv_tag(&tag, 1), {&value, 1}};
    size_t        written = 99;
    ASSERT_EQ(TLV_OK, tlv_source_preserve(&decoded.source, &copied, nullptr, 0, &written));
    EXPECT_EQ(sizeof(wire), written);

    std::vector<uint8_t> output(sizeof(wire), 0xCC);
    const auto           untouched = output;
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_source_preserve(&decoded.source, &copied, output.data(),
                                                            output.size() - 1, &written));
    EXPECT_EQ(sizeof(wire), written);
    EXPECT_EQ(untouched, output);
    ASSERT_EQ(TLV_OK, tlv_source_preserve(&decoded.source, &copied, output.data(), output.size(),
                                          &written));
    EXPECT_EQ(0, std::memcmp(wire, output.data(), sizeof(wire)));

    const uint8_t other_tag = 8;
    copied.tag = tlv_tag(&other_tag, 1);
    output = untouched;
    written = 99;
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_source_preserve(&decoded.source, &copied, output.data(),
                                                       output.size(), &written));
    EXPECT_EQ(99u, written);
    EXPECT_EQ(untouched, output);
}

TEST(Unit_Tlv_FormatContract, PreservationSupportsOverlappingDestination) {
    for (size_t source_offset : {size_t(0), size_t(1)}) {
        SCOPED_TRACE(source_offset);
        const uint8_t expected[] = {0xA5, 7, 1, 0x9C, 0xAA, 0xAA};
        uint8_t       storage[sizeof(expected) + 1] = {};
        std::memcpy(storage + source_offset, expected, sizeof(expected));
        tlv_decoded_t decoded{};
        ASSERT_EQ(TLV_OK, tlv_format_decode(&framed_format, storage + source_offset,
                                            sizeof(expected), &decoded, nullptr));
        uint8_t* destination = storage + (1 - source_offset);
        size_t   written = 99;
        ASSERT_EQ(TLV_OK, tlv_source_preserve(&decoded.source, &decoded.element, destination,
                                              sizeof(expected), &written));
        EXPECT_EQ(sizeof(expected), written);
        EXPECT_EQ(0, std::memcmp(expected, destination, written));
    }
}

TEST(Unit_Tlv_FormatContract, StatefulReaderAndWriterAdvancePastTrailer) {
    uint8_t      wire[13] = {};
    tlv_writer_t writer{};
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, wire, sizeof(wire), &framed_format));
    const uint8_t first[] = {0xAA};
    const uint8_t second[] = {0xBB, 0xCC};
    ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, TLV_TAG(7), first, sizeof(first)));
    EXPECT_EQ(6u, tlv_writer_size(&writer));
    ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, TLV_TAG(8), second, sizeof(second)));
    EXPECT_EQ(sizeof(wire), tlv_writer_size(&writer));
    const uint8_t expected[] = {0xA5, 7, 1, 0, 0xAA, 0xAA, 0xA5, 8, 2, 0, 0xBB, 0xCC, 0x77};
    EXPECT_EQ(0, std::memcmp(expected, wire, sizeof(wire)));
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              tlv_writer_write(&writer, TLV_TAG(9), first, sizeof(first)));
    EXPECT_EQ(sizeof(wire), tlv_writer_size(&writer));
    EXPECT_EQ(0, std::memcmp(expected, wire, sizeof(wire)));

    tlv_reader_t reader{};
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, wire, sizeof(wire), &framed_format));
    tlv_element_t element{};
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
    ASSERT_EQ(1u, element.tag.size);
    EXPECT_EQ(7, element.tag.data[0]);
    EXPECT_EQ(sizeof(first), element.value.size);
    EXPECT_EQ(wire + 4, element.value.data);
    EXPECT_FALSE(tlv_reader_at_end(&reader));
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
    ASSERT_EQ(1u, element.tag.size);
    EXPECT_EQ(8, element.tag.data[0]);
    EXPECT_EQ(sizeof(second), element.value.size);
    EXPECT_EQ(wire + 10, element.value.data);
    EXPECT_TRUE(tlv_reader_at_end(&reader));
    EXPECT_EQ(TLV_ERR_END_OF_BUFFER, tlv_reader_next(&reader, &element));
}

TEST(Unit_Tlv_FormatContract, ReaderDiagnosticsDoNotDecodeAgain) {
    struct Context {
        mutable size_t calls = 0;
    } context;
    tlv_format_t format = framed_format;
    format.context = &context;
    format.decode = [](const void* opaque, const uint8_t* data, size_t size, tlv_decoded_t* decoded,
                       tlv_format_error_t* error) {
        ++static_cast<const Context*>(opaque)->calls;
        return framed_decode(nullptr, data, size, decoded, error);
    };
    const uint8_t           wire[] = {0xA5, 7, 1, 0x9C, 0xAA, 0};
    tlv_element_t           element{};
    size_t                  consumed = 99;
    tlv_reader_diagnostic_t diagnostic{};
    EXPECT_EQ(TLV_ERR_INVALID_VALUE,
              tlv_read_diag(wire, sizeof(wire), &format, &element, &consumed, &diagnostic));
    EXPECT_EQ(1u, context.calls);
    EXPECT_EQ(99u, consumed);
    EXPECT_EQ(5u, diagnostic.diagnostic.offset);
    EXPECT_TRUE(diagnostic.has_tag);
    ASSERT_EQ(1u, diagnostic.tag.size);
    EXPECT_EQ(7, diagnostic.tag.data[0]);
    EXPECT_TRUE(diagnostic.has_raw_length);
    EXPECT_FALSE(diagnostic.has_declared_length);
}

TEST(Unit_Tlv_FormatContract, DecodeRejectsInconsistentTagWithoutPublishingOutput) {
    const uint8_t wire[] = {0xA5, 7, 1, 0, 0xAA, 0xAA};
    const uint8_t external_tag = 7;
    struct Context {
        int            variant;
        const uint8_t* external;
    } context{0, &external_tag};
    tlv_format_t format = framed_format;
    format.context = &context;
    format.decode = [](const void* opaque, const uint8_t* data, size_t size, tlv_decoded_t* result,
                       tlv_format_error_t* error) {
        const auto* c = static_cast<const Context*>(opaque);
        const auto  rc = framed_decode(nullptr, data, size, result, error);
        if (rc != TLV_OK) return rc;
        switch (c->variant) {
            case 0: result->element.tag.data = c->external; break;
            case 1: result->element.tag.data = data + 2; break;
            case 2: result->element.tag.size = 2; break;
            case 3: result->source.tag.present = 0; break;
            case 4: result->element.tag = {nullptr, 0}; break;
            case 5:
                result->source.tag.present = 0;
                result->element.tag = {data + 1, 0};
                break;
            case 6: result->source.tag = {SIZE_MAX, 1, 1}; break;
        }
        return TLV_OK;
    };
    for (int variant = 0; variant < 7; ++variant) {
        SCOPED_TRACE(variant);
        context.variant = variant;
        tlv_decoded_t result{};
        result.source.size = 99;
        result.element.tag = tlv_tag(&external_tag, 1);
        EXPECT_EQ(TLV_ERR_INVALID_ARG,
                  tlv_format_decode(&format, wire, sizeof(wire), &result, nullptr));
        EXPECT_EQ(99u, result.source.size);
        EXPECT_EQ(&external_tag, result.element.tag.data);
        EXPECT_EQ(1u, result.element.tag.size);
    }
}

TEST(Unit_Tlv_FormatContract, EmptyTagPresenceIsPreservedWithoutPointerIdentity) {
    const uint8_t wire = 42;
    const uint8_t other_storage = 0;
    for (bool present : {false, true}) {
        SCOPED_TRACE(present);
        tlv_format_t format{};
        format.context = &present;
        format.decode = [](const void* opaque, const uint8_t* data, size_t, tlv_decoded_t* result,
                           tlv_format_error_t*) {
            const bool has_tag = *static_cast<const bool*>(opaque);
            result->element = {tlv_tag(has_tag ? data : nullptr, 0), {data, 1}};
            result->source.header = {0, 0, 1};
            result->source.tag = {0, 0, has_tag ? 1 : 0};
            result->source.value = {0, 1, 1};
            result->source.trailer = {1, 0, 1};
            result->source.size = 1;
            return TLV_OK;
        };
        tlv_decoded_t decoded{};
        ASSERT_EQ(TLV_OK, tlv_format_decode(&format, &wire, 1, &decoded, nullptr));
        auto element = decoded.element;
        element.tag = tlv_tag(present ? &other_storage : nullptr, 0);
        uint8_t output = 0;
        size_t  written = 99;
        ASSERT_EQ(TLV_OK, tlv_source_preserve(&decoded.source, &element, &output, 1, &written));
        EXPECT_EQ(wire, output);
        EXPECT_EQ(1u, written);
        element.tag = tlv_tag(present ? nullptr : &other_storage, 0);
        output = 0;
        written = 99;
        EXPECT_EQ(TLV_ERR_INVALID_ARG,
                  tlv_source_preserve(&decoded.source, &element, &output, 1, &written));
        EXPECT_EQ(0, output);
        EXPECT_EQ(99u, written);
    }
}
