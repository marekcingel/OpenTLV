#include "tlv/element.h"

#include <gtest/gtest.h>

#include <vector>
#include <algorithm>

TEST(Unit_Tlv_Element, ZeroInitializationProducesEmptyElement) {
    tlv_element_t empty{};
    EXPECT_EQ(nullptr, empty.tag.data);
    EXPECT_EQ(0u, empty.tag.size);
    EXPECT_EQ(nullptr, empty.length.data);
    EXPECT_EQ(0u, empty.length.size);
    EXPECT_EQ(nullptr, empty.value.data);
    EXPECT_EQ(0u, empty.value.size);
}

TEST(Unit_Tlv_Element, TagBorrowsRawBytesOfAnySize) {
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
    uint8_t       tag_bytes[] = {0x81};
    uint8_t       length_bytes[] = {0x81, 0x02};
    uint8_t       storage[] = {0x12, 0x34, 0x56};
    tlv_element_t element = {tlv_tag(tag_bytes, sizeof(tag_bytes)),
                             {length_bytes, sizeof(length_bytes)},
                             {storage + 1, 2}};
    tlv_element_t copy = element;
    EXPECT_EQ(1u, copy.tag.size);
    EXPECT_EQ(tag_bytes, copy.tag.data);
    EXPECT_EQ(length_bytes, copy.length.data);
    EXPECT_EQ(sizeof(length_bytes), copy.length.size);
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
    const uint8_t data[] = {1, 0};
    auto          format = controlled::format;
    format.read_length = [](const void*, const uint8_t*, size_t, tlv_size_t* size,
                            size_t* consumed) {
        *size = TLV_SIZE_MAX;
        *consumed = 1;
        return TLV_OK;
    };
    tlv_element_t           element{TLV_TAG(9), {data, 1}, {data, 1}};
    size_t                  consumed = 99;
    tlv_reader_diagnostic_t diagnostic{};
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              tlv_read_diag(data, sizeof(data), &format, &element, &consumed, &diagnostic));
    EXPECT_EQ(99u, consumed);
    EXPECT_EQ(9u, element.tag.data[0]);
    EXPECT_EQ(data, element.length.data);
    EXPECT_EQ(1u, element.value.size);
    EXPECT_EQ(TLV_SIZE_MAX, diagnostic.declared_length);
}

#if OPENTLV_FORMAT_BER
#include "tlv/builtins/asn1/ber.h"
TEST(Unit_Tlv_Element, RetainsMultibyteTagAndNonminimalLengthExactly) {
    const uint8_t data[] = {0x9F, 0x20, 0x82, 0x00, 0x01, 0xAA};
    tlv_element_t element{};
    size_t        consumed = 0;
    ASSERT_EQ(TLV_OK, tlv_read(data, sizeof(data), &tlv_format_ber, &element, &consumed));
    EXPECT_EQ(data, element.tag.data);
    EXPECT_EQ(2u, element.tag.size);
    EXPECT_EQ(data + 2, element.length.data);
    EXPECT_EQ(3u, element.length.size);
    EXPECT_EQ(data + 5, element.value.data);
    EXPECT_EQ(1u, element.value.size);
    EXPECT_EQ(sizeof(data), consumed);
}

TEST(Unit_Tlv_Element, EmptyAndTerminatedValuesKeepTheirRawLength) {
    const uint8_t empty[] = {0x04, 0x00};
    const uint8_t terminated[] = {0x30, 0x80, 0x04, 0x00, 0x00, 0x00};
    tlv_element_t element{};
    size_t        consumed = 0;
    ASSERT_EQ(TLV_OK, tlv_read(empty, sizeof(empty), &tlv_format_ber, &element, &consumed));
    EXPECT_EQ(empty + 1, element.length.data);
    EXPECT_EQ(1u, element.length.size);
    EXPECT_EQ(0u, element.value.size);
    ASSERT_EQ(TLV_OK,
              tlv_read(terminated, sizeof(terminated), &tlv_format_ber, &element, &consumed));
    EXPECT_EQ(terminated + 1, element.length.data);
    EXPECT_EQ(0x80, element.length.data[0]);
    EXPECT_EQ(1u, element.length.size);
    EXPECT_EQ(2u, element.value.size);
    EXPECT_EQ(sizeof(terminated), consumed);
}

TEST(Unit_Tlv_Element, TruncationDoesNotPublishPartialRawFields) {
    const uint8_t data[] = {0x9F, 0x20, 0x82, 0x00, 0x01, 0xAA};
    for (size_t size = 0; size < sizeof(data); ++size) {
        tlv_element_t element{TLV_TAG(9), {data, 1}, {data, 1}};
        size_t        consumed = 99;
        EXPECT_NE(TLV_OK, tlv_read(data, size, &tlv_format_ber, &element, &consumed));
        EXPECT_EQ(99u, consumed);
        EXPECT_EQ(9u, element.tag.data[0]);
        EXPECT_EQ(data, element.length.data);
        EXPECT_EQ(1u, element.length.size);
        EXPECT_EQ(data, element.value.data);
        EXPECT_EQ(1u, element.value.size);
    }
}
#endif

#if OPENTLV_FORMAT_BLUETOOTH_LTV
#include "tlv/builtins/bluetooth/bluetooth_ltv.h"
TEST(Unit_Tlv_Element, LengthBeforeTagKeepsRawCountSeparateFromValueSize) {
    const uint8_t data[] = {3, 0xFF, 0xAA, 0xBB};
    tlv_element_t element{};
    size_t        consumed = 0;
    ASSERT_EQ(TLV_OK, tlv_read(data, sizeof(data), &tlv_format_bluetooth_ltv, &element, &consumed));
    EXPECT_EQ(data, element.length.data);
    EXPECT_EQ(1u, element.length.size);
    EXPECT_EQ(3u, element.length.data[0]);
    EXPECT_EQ(data + 1, element.tag.data);
    EXPECT_EQ(data + 2, element.value.data);
    EXPECT_EQ(2u, element.value.size);
}
#endif

#if OPENTLV_FORMAT_BER
TEST(Unit_Tlv_Element, BerOversizedValueKeepsDecodedAndRawLengthInDiagnostic) {
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

#if OPENTLV_FORMAT_FIXED
#include "tlv/formats/fixed.h"
TEST(Unit_Tlv_Element, FixedSizeDomainIsIndependentOfFieldOrderAndByteOrder) {
    for (auto byte_order : {TLV_BYTE_ORDER_BIG_ENDIAN, TLV_BYTE_ORDER_LITTLE_ENDIAN}) {
        for (auto order : {TLV_ELEMENT_ORDER_TLV, TLV_ELEMENT_ORDER_LTV}) {
            const tlv_fixed_format_t config = {2, 8, byte_order, order, TLV_LENGTH_SCOPE_VALUE};
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
            ASSERT_EQ(TLV_OK, tlv_read(data, sizeof(data), &format, &element, &consumed));
            EXPECT_EQ(data + tag_offset, element.tag.data);
            EXPECT_EQ(data + length_offset, element.length.data);
            EXPECT_EQ(8u, element.length.size);
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
#endif

#if OPENTLV_FORMAT_DER
#include "tlv/builtins/asn1/der.h"
#include "tlv/builtins/asn1/der_profile.h"
TEST(Unit_Tlv_Element, DerRejectsNonminimalLengthButPreservesItsRawFieldInDiagnostic) {
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
TEST(Unit_Tlv_Element, DerProfilePublishesTheSameRawFields) {
    const uint8_t bytes[] = {4, 1, 0xAA};
    tlv_element_t element{};
    size_t        consumed = 0;
    ASSERT_EQ(TLV_OK, tlv_der_read(bytes, sizeof(bytes), nullptr, &element, &consumed, nullptr));
    EXPECT_EQ(bytes + 1, element.length.data);
    EXPECT_EQ(1u, element.length.size);
    EXPECT_EQ(1u, element.value.size);
}
#endif

#if OPENTLV_FORMAT_CER
#include "tlv/builtins/asn1/cer_profile.h"
TEST(Unit_Tlv_Element, CerProfilePreservesPrimitiveAndIndefiniteLengthFields) {
    const uint8_t bytes[] = {0x30, 0x80, 4, 1, 0xAA, 0, 0};
    tlv_element_t element{};
    size_t        consumed = 0;
    ASSERT_EQ(TLV_OK, tlv_cer_read(bytes, sizeof(bytes), nullptr, &element, &consumed, nullptr));
    EXPECT_EQ(bytes + 1, element.length.data);
    EXPECT_EQ(1u, element.length.size);
    EXPECT_EQ(3u, element.value.size);
    ASSERT_EQ(TLV_OK, tlv_cer_read(bytes + 2, 3, nullptr, &element, &consumed, nullptr));
    EXPECT_EQ(bytes + 3, element.length.data);
    EXPECT_EQ(1u, element.length.size);
    EXPECT_EQ(1u, element.value.size);
}
#endif
