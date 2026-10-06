// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/config.h"
#include "tlv/builtins/asn1/identifier.h"
#if OPENTLV_FORMAT_DER
#include "tlv/builtins/asn1/der.h"
#endif
#if OPENTLV_FORMAT_CER
#include "tlv/builtins/asn1/cer.h"
#endif
#include "tlv/formats/compose.h"
#include "tlv/formats/variable.h"
#include "tlv/builtins/asn1/ber.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#include <gtest/gtest.h>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <vector>

namespace {
const auto& ber = tlv_format_ber;
const auto& ber_writer = tlv_format_ber;
} // namespace

TEST(Unit_Tlv_Ber, InvalidAndNonminimalLengths) {
    tlv_size_t length = 42;
    size_t     used = 42;
    for (uint8_t prefix : {0x80, 0xFF})
        EXPECT_EQ(TLV_ERR_INVALID_LENGTH, static_cast<const tlv_field_composition_t*>(ber.context)
                                              ->read_length(nullptr, &prefix, 1, &length, &used));
    std::vector<uint8_t> overflow(sizeof(tlv_size_t) + 2, 0);
    overflow[0] = 0x80 | (sizeof(tlv_size_t) + 1);
    overflow[1] = 1;
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
              static_cast<const tlv_field_composition_t*>(ber.context)
                  ->read_length(nullptr, overflow.data(), overflow.size(), &length, &used));
    EXPECT_EQ(42u, length);
    EXPECT_EQ(overflow.size(), used);
    const uint8_t padded[] = {0x83, 0, 0, 0x7F};
    ASSERT_EQ(TLV_OK, static_cast<const tlv_field_composition_t*>(ber.context)
                          ->read_length(nullptr, padded, sizeof(padded), &length, &used));
    EXPECT_EQ(127u, length);
    EXPECT_EQ(4u, used);
    size_t total = 42;
    EXPECT_EQ(sizeof(size_t) == sizeof(tlv_size_t) ? TLV_ERR_OVERFLOW : TLV_ERR_NATIVE_SIZE,
              tlv_encoded_size((TLV_TAG(0x5A)), SIZE_MAX, &ber_writer, &total));
    EXPECT_EQ(42u, total);
}

TEST(Unit_Tlv_Ber, TagSizeLimitAndContinuation) {
    // The longest tag the format accepts: a high-tag-number identifier of TLV_ASN1_TAG_MAX_SIZE
    // bytes.
    std::vector<uint8_t> bytes(TLV_ASN1_TAG_MAX_SIZE, 0x81);
    bytes.front() = 0x9F;
    bytes.back() = 0x01;
    tlv_tag_t tag{};
    size_t    used = 0;
    ASSERT_EQ(TLV_OK, static_cast<const tlv_field_composition_t*>(ber.context)
                          ->read_tag(nullptr, bytes.data(), bytes.size(), &tag, &used));
    EXPECT_EQ(bytes.size(), used);
    // The tag borrows the input rather than copying it.
    EXPECT_EQ(bytes.data(), tag.data);
    EXPECT_EQ(bytes.size(), tag.size);
    ASSERT_EQ(TLV_OK, static_cast<const tlv_field_composition_t*>(ber_writer.context)
                          ->write_tag(nullptr, nullptr, 0, &tag, &used));
    std::vector<uint8_t> output(bytes.size(), 0xEE);
    for (size_t capacity = 0; capacity < bytes.size(); ++capacity) {
        EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
                  static_cast<const tlv_field_composition_t*>(ber_writer.context)
                      ->write_tag(nullptr, output.data(), capacity, &tag, &used));
        for (auto byte : output) EXPECT_EQ(0xEE, byte);
    }
    ASSERT_EQ(TLV_OK, static_cast<const tlv_field_composition_t*>(ber_writer.context)
                          ->write_tag(nullptr, output.data(), output.size(), &tag, &used));
    EXPECT_EQ(bytes, output);
    // One byte more than the format supports is rejected, however the tag ends.
    bytes.assign(TLV_ASN1_TAG_MAX_SIZE + 1, 0x81);
    bytes[0] = 0x9F;
    bytes.back() = 1;
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE,
              static_cast<const tlv_field_composition_t*>(ber.context)
                  ->read_tag(nullptr, bytes.data(), bytes.size(), &tag, &used));
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE,
              static_cast<const tlv_field_composition_t*>(ber.context)
                  ->read_tag(nullptr, bytes.data(), TLV_ASN1_TAG_MAX_SIZE, &tag, &used));
    tag = tlv_tag(bytes.data(), bytes.size());
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE,
              static_cast<const tlv_field_composition_t*>(ber_writer.context)
                  ->write_tag(nullptr, nullptr, 0, &tag, &used));
    for (size_t size = 0; size < TLV_ASN1_TAG_MAX_SIZE; ++size)
        EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
                  static_cast<const tlv_field_composition_t*>(ber.context)
                      ->read_tag(nullptr, bytes.data(), size, &tag, &used));
}

TEST(Unit_Tlv_Ber, InvalidTagsAndWriterState) {
    const std::vector<std::vector<uint8_t>> invalid = {
        {}, {0x9F}, {0x5A, 1}, {0x9F, 0}, {0x9F, 0x80, 1}, {0x9F, 0x81}, {0x9F, 1, 1}};
    for (const auto& bytes : invalid) {
        const tlv_tag_t tag = tlv_tag(bytes.empty() ? nullptr : bytes.data(), bytes.size());
        uint8_t         data[16];
        std::memset(data, 0xEE, sizeof(data));
        tlv_writer_t writer;
        ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, data, sizeof(data), &ber_writer));
        EXPECT_EQ(bytes.empty() ? TLV_ERR_INVALID_TAG_SIZE : TLV_ERR_INVALID_TAG,
                  tlv_writer_write(&writer, tag, nullptr, 0));
        EXPECT_EQ(0u, writer.pos);
        for (auto byte : data) EXPECT_EQ(0xEE, byte);
    }
    // A tag whose bytes are missing is reported before its size is looked at.
    size_t          used;
    const tlv_tag_t missing = tlv_tag(nullptr, 1);
    EXPECT_EQ(TLV_ERR_NULL_ARG, static_cast<const tlv_field_composition_t*>(ber_writer.context)
                                    ->write_tag(nullptr, nullptr, 0, &missing, &used));
    const uint8_t invalid_tag[] = {0x9F, 0x80, 1};
    tlv_tag_t     tag{};
    EXPECT_EQ(TLV_ERR_INVALID_TAG,
              static_cast<const tlv_field_composition_t*>(ber.context)
                  ->read_tag(nullptr, invalid_tag, sizeof(invalid_tag), &tag, &used));
}

TEST(Unit_Tlv_Ber, TagClassFormAndNumberFromWireBytes) {
    struct Case {
        std::vector<uint8_t> bytes;
        tlv_asn1_class_t     cls;
        int                  constructed;
        uint64_t             number;
    };
    const Case cases[] = {
        {{0x02}, TLV_ASN1_UNIVERSAL, 0, 2},          // Universal, primitive, tag 2
        {{0x30}, TLV_ASN1_UNIVERSAL, 1, 16},         // Universal, constructed, tag 16
        {{0xA0}, TLV_ASN1_CONTEXT_SPECIFIC, 1, 0},   // Context-specific, constructed, tag 0
        {{0x5F, 0x20}, TLV_ASN1_APPLICATION, 0, 32}, // Application, high-tag-number identifier
    };
    for (const auto& c : cases) {
        SCOPED_TRACE(::testing::Message() << "bytes[0]=" << static_cast<unsigned>(c.bytes[0]));
        const tlv_tag_t tag = tlv_tag(c.bytes.data(), c.bytes.size());
        EXPECT_EQ(c.cls, tlv_asn1_tag_class(&tag));
        EXPECT_EQ(c.constructed, tlv_asn1_tag_is_constructed(&tag));
        uint64_t number = 0;
        ASSERT_EQ(TLV_OK, tlv_ber_tag_number(&tag, &number));
        EXPECT_EQ(c.number, number);
    }
}

TEST(Unit_Tlv_Ber, TagMakeRejectsOnlyReservedEocAmongUniversalNumbers) {
    tlv_tag_t tag{};
    uint8_t   storage[TLV_ASN1_TAG_MAX_SIZE];
    // Universal tag 0 is reserved for EOC, in either form.
    EXPECT_EQ(TLV_ERR_INVALID_TAG, tlv_ber_tag_make(TLV_ASN1_UNIVERSAL, 0, 0, storage, &tag));
    EXPECT_EQ(TLV_ERR_INVALID_TAG, tlv_ber_tag_make(TLV_ASN1_UNIVERSAL, 1, 0, storage, &tag));
    // Unlike tlv_der_tag_make() and tlv_cer_tag_make(), no other universal number is
    // restricted to a fixed primitive/constructed form.
    for (uint64_t number : {UINT64_C(1), UINT64_C(8), UINT64_C(11), UINT64_C(15), UINT64_C(16),
                            UINT64_C(17), UINT64_C(29), UINT64_C(36)}) {
        for (int constructed : {0, 1}) {
            ASSERT_EQ(TLV_OK,
                      tlv_ber_tag_make(TLV_ASN1_UNIVERSAL, constructed, number, storage, &tag));
            EXPECT_EQ(constructed, tlv_asn1_tag_is_constructed(&tag));
        }
    }
}

TEST(Unit_Tlv_Ber, TagModelNullArgsAndInvalidClassOrForm) {
    tlv_tag_t tag{};
    uint8_t   storage[TLV_ASN1_TAG_MAX_SIZE];
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_ber_tag_make(TLV_ASN1_PRIVATE, 0, 1, storage, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_ber_tag_make(TLV_ASN1_PRIVATE, 0, 1, nullptr, &tag));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_ber_tag_number(nullptr, nullptr));
    EXPECT_EQ(TLV_ERR_INVALID_TAG, tlv_ber_tag_make(TLV_ASN1_PRIVATE, 2, 1, storage, &tag));
    EXPECT_EQ(TLV_ERR_INVALID_TAG,
              tlv_ber_tag_make(static_cast<tlv_asn1_class_t>(4), 0, 1, storage, &tag));
}

TEST(Unit_Tlv_Ber, TagModelSizeErrorsPreserveOutputs) {
    tlv_tag_t tag{};
    uint64_t  number = 42;
    uint8_t   storage[TLV_ASN1_TAG_MAX_SIZE];
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE, tlv_ber_tag_number(&tag, &number));
    EXPECT_EQ(42u, number);
    // The longest tag the format accepts, with a high-tag-number that never ends.
    const uint8_t unterminated[TLV_ASN1_TAG_MAX_SIZE] = {0x9F, 0x81, 0x81, 0x81,
                                                         0x81, 0x81, 0x81, 0x81};
    tag = tlv_tag(unterminated, sizeof(unterminated));
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE, tlv_ber_tag_number(&tag, &number));
    EXPECT_EQ(42u, number);
    // A well-formed tag one byte over the format limit is rejected by the format, not the type.
    const uint8_t too_long[TLV_ASN1_TAG_MAX_SIZE + 1] = {0x9F, 0x81, 0x81, 0x81, 0x81,
                                                         0x81, 0x81, 0x81, 0x01};
    tag = tlv_tag(too_long, sizeof(too_long));
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE, tlv_ber_tag_number(&tag, &number));
    const tlv_tag_t before = tag;
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE,
              tlv_ber_tag_make(TLV_ASN1_PRIVATE, 0, UINT64_MAX, storage, &tag));
    EXPECT_EQ(before.data, tag.data);
    EXPECT_EQ(before.size, tag.size);
}

TEST(Unit_Tlv_Ber, TruncationPreservesReaderOutput) {
    std::vector<uint8_t> data = {0x5A, 0x81, 0x80};
    data.resize(131, 0xAB);
    for (size_t size = 0; size < data.size(); ++size) {
        tlv_reader_t reader;
        ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data.data(), size, &ber));
        tlv_element_t element = {TLV_TAG(0xEE), {nullptr, 42}};
        EXPECT_EQ(size ? TLV_ERR_BUFFER_TOO_SHORT : TLV_ERR_END_OF_BUFFER,
                  tlv_reader_next(&reader, &element));
        EXPECT_EQ(0u, reader.pos);
        EXPECT_EQ(0xEE, element.tag.data[0]);
        EXPECT_EQ(nullptr, element.value.data);
        EXPECT_EQ(42u, element.value.size);
    }
}

TEST(Unit_Tlv_Ber, IndefiniteWriterCapacityValidationAndDefault) {
    const tlv_tag_t tag = TLV_TAG(0x30);
    const uint8_t   value[] = {0x04, 2, 0, 0};
    uint8_t         output[16];
    size_t          written = 999;
    for (size_t capacity = 0; capacity < 8; ++capacity) {
        std::memset(output, 0xEE, sizeof(output));
        EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
                  tlv_ber_write_indefinite(output, capacity, tag, value, sizeof(value), &written));
        EXPECT_EQ(999u, written);
        for (auto byte : output) EXPECT_EQ(0xEE, byte);
    }
    const std::vector<std::vector<uint8_t>> invalid = {
        {0, 0}, {0x04}, {0x04, 2, 0}, {0x04, 0x80, 0, 0}, {0x30, 0x80}, {0x30, 2, 0, 0}};
    for (const auto& bytes : invalid) {
        EXPECT_NE(TLV_OK, tlv_ber_write_indefinite(output, sizeof(output), tag, bytes.data(),
                                                   bytes.size(), &written));
        EXPECT_EQ(999u, written);
        for (auto byte : output) EXPECT_EQ(0xEE, byte);
    }
    EXPECT_EQ(sizeof(size_t) == sizeof(tlv_size_t) ? TLV_ERR_OVERFLOW : TLV_ERR_NATIVE_SIZE,
              tlv_ber_indefinite_encoded_size(tag, SIZE_MAX, &written));
    EXPECT_EQ(999u, written);
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_ber_indefinite_encoded_size(TLV_TAG(4), 0, &written));
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
              tlv_ber_write_indefinite(output, sizeof(output), TLV_TAG(4), nullptr, 0, &written));
    EXPECT_EQ(999u, written);
    for (auto byte : output) EXPECT_EQ(0xEE, byte);
    EXPECT_EQ(TLV_ERR_INVALID_TAG, tlv_ber_indefinite_encoded_size(TLV_TAG(0), 0, &written));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_ber_indefinite_encoded_size(tag, 0, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_ber_write_indefinite(nullptr, 4, tag, nullptr, 0, &written));
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              tlv_ber_write_indefinite(nullptr, 0, tag, nullptr, 0, &written));
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              tlv_ber_write_indefinite(output, sizeof(output), tag, nullptr, 1, &written));
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              tlv_ber_write_indefinite(output, sizeof(output), tag, nullptr, 0, nullptr));
    tlv_writer_t writer{};
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, output, 10, &ber_writer));
    ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, tag, nullptr, 0));
    EXPECT_EQ(0x30, output[0]);
    EXPECT_EQ(0, output[1]);
    ASSERT_EQ(TLV_OK, tlv_ber_writer_write_indefinite(&writer, tag, value, sizeof(value)));
    EXPECT_EQ(10u, writer.pos);
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_ber_writer_write_indefinite(&writer, tag, nullptr, 0));
    EXPECT_EQ(10u, writer.pos);
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_ber_writer_write_indefinite(nullptr, tag, nullptr, 0));
    writer.format = nullptr;
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_ber_writer_write_indefinite(&writer, tag, nullptr, 0));
}

TEST(Unit_Tlv_Ber, StandaloneLengthDecodeFixtures) {
    const struct {
        std::vector<uint8_t> bytes;
        tlv_size_t           value;
    } cases[] = {
        {{0x00}, 0},
        {{0x7F}, 127},
        {{0x81, 0x80}, 128},
        {{0x81, 0xFF}, 255},
        {{0x82, 0x01, 0x00}, 256},
        {{0x88, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, UINT64_MAX},
    };
    for (const auto& c : cases) {
        tlv_size_t value = 999;
        size_t     consumed = 999;
        ASSERT_EQ(TLV_OK, tlv_ber_length_decode(c.bytes.data(), c.bytes.size(), &value, &consumed));
        EXPECT_EQ(c.value, value);
        EXPECT_EQ(c.bytes.size(), consumed);
    }
}

TEST(Unit_Tlv_Ber, StandaloneLengthEncodeFixtures) {
    const struct {
        tlv_size_t           value;
        std::vector<uint8_t> bytes;
    } cases[] = {
        {0, {0x00}},
        {127, {0x7F}},
        {128, {0x81, 0x80}},
        {255, {0x81, 0xFF}},
        {256, {0x82, 0x01, 0x00}},
        {UINT64_MAX, {0x88, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
    };
    for (const auto& c : cases) {
        uint8_t out[TLV_BER_LENGTH_MAX_ENCODED_SIZE];
        std::memset(out, 0xEE, sizeof(out));
        size_t written = 999;
        ASSERT_EQ(TLV_OK, tlv_ber_length_encode(c.value, out, sizeof(out), &written));
        EXPECT_EQ(c.bytes.size(), written);
        EXPECT_TRUE(std::equal(c.bytes.begin(), c.bytes.end(), out));
    }
    EXPECT_EQ(9u, TLV_BER_LENGTH_MAX_ENCODED_SIZE);
}

TEST(Unit_Tlv_Ber, StandaloneLengthEncodeSizeQueryAndCapacity) {
    size_t written = 999;
    ASSERT_EQ(TLV_OK, tlv_ber_length_encode(UINT64_MAX, nullptr, 0, &written));
    EXPECT_EQ(9u, written);
    ASSERT_EQ(TLV_OK, tlv_ber_length_encode(0, nullptr, 0, &written));
    EXPECT_EQ(1u, written);
    uint8_t out[TLV_BER_LENGTH_MAX_ENCODED_SIZE];
    for (size_t capacity = 0; capacity < 9; ++capacity) {
        std::memset(out, 0xEE, sizeof(out));
        written = 999;
        EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
                  tlv_ber_length_encode(UINT64_MAX, out, capacity, &written));
        EXPECT_EQ(999u, written);
        for (auto byte : out) EXPECT_EQ(0xEE, byte);
    }
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_ber_length_encode(0, nullptr, 1, &written));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_ber_length_encode(0, out, sizeof(out), nullptr));
}

TEST(Unit_Tlv_Ber, StandaloneLengthDecodeRejectsIndefiniteAndReserved) {
    tlv_size_t value = 999;
    size_t     consumed = 999;
    for (uint8_t prefix : {0x80, 0xFF}) {
        EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_ber_length_decode(&prefix, 1, &value, &consumed));
        EXPECT_EQ(999u, value);
        EXPECT_EQ(999u, consumed);
    }
}

TEST(Unit_Tlv_Ber, StandaloneLengthDecodeOverflowAndNonminimalPadding) {
    tlv_size_t value = 999;
    size_t     consumed = 999;
    /* Declared width (9 octets) wider than uint64_t (8 octets), with a
     * nonzero excess octet: not representable in tlv_size_t. */
    std::vector<uint8_t> overflow(10, 0);
    overflow[0] = 0x89;
    overflow[1] = 1;
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
              tlv_ber_length_decode(overflow.data(), overflow.size(), &value, &consumed));
    EXPECT_EQ(999u, value);
    EXPECT_EQ(999u, consumed);
    /* Same width, but the excess octet is zero padding: representable and accepted. */
    overflow[1] = 0;
    overflow.back() = 0x7F;
    ASSERT_EQ(TLV_OK, tlv_ber_length_decode(overflow.data(), overflow.size(), &value, &consumed));
    EXPECT_EQ(127u, value);
    EXPECT_EQ(overflow.size(), consumed);
    /* Nonminimal but representable: a zero-padded long form for a small value. */
    const uint8_t padded[] = {0x83, 0, 0, 0x7F};
    ASSERT_EQ(TLV_OK, tlv_ber_length_decode(padded, sizeof(padded), &value, &consumed));
    EXPECT_EQ(127u, value);
    EXPECT_EQ(4u, consumed);
}

TEST(Unit_Tlv_Ber, StandaloneLengthDecodeTruncationAndNullArgs) {
    const uint8_t bytes[] = {0x82, 0x01, 0x00};
    tlv_size_t    value = 999;
    size_t        consumed = 999;
    for (size_t size = 0; size < sizeof(bytes); ++size) {
        EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_ber_length_decode(bytes, size, &value, &consumed));
        EXPECT_EQ(999u, value);
        EXPECT_EQ(999u, consumed);
    }
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_ber_length_decode(nullptr, 1, &value, &consumed));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_ber_length_decode(bytes, sizeof(bytes), nullptr, &consumed));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_ber_length_decode(bytes, sizeof(bytes), &value, nullptr));
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_ber_length_decode(nullptr, 0, &value, &consumed));
}

TEST(Unit_Tlv_Ber, LongPaddedLengthsAndTruncation) {
    for (size_t width : {sizeof(tlv_size_t) + 1, size_t(9), size_t(126)}) {
        std::vector<uint8_t> bytes(width + 1, 0);
        bytes[0] = static_cast<uint8_t>(0x80 | width);
        bytes.back() = 0x7F;
        tlv_size_t length = 42;
        size_t     used = 43;
        ASSERT_EQ(TLV_OK, static_cast<const tlv_field_composition_t*>(ber.context)
                              ->read_length(nullptr, bytes.data(), bytes.size(), &length, &used));
        EXPECT_EQ(127u, length);
        EXPECT_EQ(bytes.size(), used);
        bytes.back() = 0;
        ASSERT_EQ(TLV_OK, static_cast<const tlv_field_composition_t*>(ber.context)
                              ->read_length(nullptr, bytes.data(), bytes.size(), &length, &used));
        EXPECT_EQ(0u, length);
        std::memset(bytes.data() + bytes.size() - sizeof(tlv_size_t), 255, sizeof(tlv_size_t));
        ASSERT_EQ(TLV_OK, static_cast<const tlv_field_composition_t*>(ber.context)
                              ->read_length(nullptr, bytes.data(), bytes.size(), &length, &used));
        EXPECT_EQ(TLV_SIZE_MAX, length);
        bytes[1] = 1;
        length = 42;
        used = 43;
        for (size_t size = 0; size < bytes.size(); ++size) {
            EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
                      static_cast<const tlv_field_composition_t*>(ber.context)
                          ->read_length(nullptr, bytes.data(), size, &length, &used));
            EXPECT_EQ(42u, length);
            EXPECT_EQ(size, used);
        }
        EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
                  static_cast<const tlv_field_composition_t*>(ber.context)
                      ->read_length(nullptr, bytes.data(), bytes.size(), &length, &used));
        EXPECT_EQ(42u, length);
        EXPECT_EQ(bytes.size(), used);
    }
}

TEST(Unit_Tlv_Ber, IdentifierPolicyIsSeparateFromVariableMechanics) {
    const tlv_variable_identifier_t wire = {0x1F, 0x1F, 0x80, 0x7F, TLV_ASN1_TAG_MAX_SIZE};
    // Exhaust the first octet and first continuation digit. The final zero
    // terminates a continuation, including nonminimal raw identifiers.
    for (unsigned first = 0; first <= 255; ++first) {
        for (unsigned digit = 0; digit <= 255; ++digit) {
            const uint8_t bytes[] = {static_cast<uint8_t>(first), static_cast<uint8_t>(digit), 0};
            tlv_tag_t     generic = {}, concrete = tlv_tag(bytes + 2, 1);
            size_t        generic_used = 0, concrete_used = 99;
            ASSERT_EQ(TLV_OK, tlv_variable_identifier_read(&wire, bytes, sizeof(bytes), &generic,
                                                           &generic_used));
            const bool rejected =
                first == 0 || first == 0x20 || ((first & 0x1F) == 0x1F && (digit & 0x7F) == 0);
            ASSERT_EQ(rejected ? TLV_ERR_INVALID_TAG : TLV_OK,
                      tlv_ber_read_identifier(bytes, sizeof(bytes), &concrete, &concrete_used));
            if (rejected) {
                EXPECT_EQ(bytes + 2, concrete.data);
                EXPECT_EQ(99u, concrete_used);
            } else {
                EXPECT_EQ(generic.data, concrete.data);
                EXPECT_EQ(generic.size, concrete.size);
                EXPECT_EQ(generic_used, concrete_used);
            }
        }
    }
}

TEST(Unit_Tlv_Ber, LeadingDigitPolicyKeepsErrorPrecedence) {
    const std::vector<std::vector<uint8_t>> bytes = {
        {0x9F, 0x80}, {0x9F, 0x80, 0x81}, {0x9F, 0x80, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 1}};
    for (const auto& input : bytes) {
        tlv_tag_t tag = tlv_tag(input.data(), 1);
        size_t    used = 99;
        EXPECT_EQ(TLV_ERR_INVALID_TAG,
                  tlv_ber_read_identifier(input.data(), input.size(), &tag, &used));
        EXPECT_EQ(1u, tag.size);
        EXPECT_EQ(99u, used);
    }
}

TEST(Unit_Tlv_Ber, LengthPolicyAndAtomicPublicOutputsDifferFromVariableMechanics) {
    const tlv_variable_length_t wire = {0x80, 0x7F, TLV_BYTE_ORDER_BIG_ENDIAN};
    std::vector<uint8_t>        reserved(128, 0);
    reserved[0] = 0xFF;
    reserved.back() = 7;
    tlv_size_t value = 99;
    size_t     used = 99;
    ASSERT_EQ(TLV_OK,
              tlv_variable_length_read(&wire, reserved.data(), reserved.size(), &value, &used));
    EXPECT_EQ(7u, value);
    EXPECT_EQ(128u, used);
    value = used = 99;
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
              tlv_ber_length_decode(reserved.data(), reserved.size(), &value, &used));
    EXPECT_EQ(99u, value);
    EXPECT_EQ(99u, used);
    const auto* fields = static_cast<const tlv_field_composition_t*>(ber.context);
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, fields->read_length(fields->context, reserved.data(),
                                                          reserved.size(), &value, &used));
    EXPECT_EQ(1u, used); // Only the reserved prefix belongs to the diagnostic field.

    const uint8_t overflow[] = {0x89, 1, 0, 0, 0, 0, 0, 0, 0, 0};
    EXPECT_EQ(TLV_ERR_OVERFLOW,
              tlv_variable_length_read(&wire, overflow, sizeof(overflow), &value, &used));
    EXPECT_EQ(sizeof(overflow), used);
    used = 99;
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
              tlv_ber_length_decode(overflow, sizeof(overflow), &value, &used));
    EXPECT_EQ(99u, value);
    EXPECT_EQ(99u, used);
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
              fields->read_length(fields->context, overflow, sizeof(overflow), &value, &used));
    EXPECT_EQ(sizeof(overflow), used);
    EXPECT_EQ(99u, value);
}

namespace {
struct Asn1Contract {
    const tlv_format_t* format;
    tlv_result_t (*make)(tlv_asn1_class_t, int, uint64_t, uint8_t*, tlv_tag_t*);
    tlv_result_t (*number)(const tlv_tag_t*, uint64_t*);
    int policy; // 0: raw BER, 1: DER, 2: CER identifier policy
};
const Asn1Contract asn1_contracts[] = {
    {&tlv_format_ber, tlv_ber_tag_make, tlv_ber_tag_number, 0},
#if OPENTLV_FORMAT_DER
    {&tlv_format_der, tlv_der_tag_make, tlv_der_tag_number, 1},
#endif
#if OPENTLV_FORMAT_CER
    {&tlv_format_cer, tlv_cer_tag_make, tlv_cer_tag_number, 2},
#endif
};
} // namespace

TEST(Unit_Tlv_Asn1, SharedIdentifierMechanicsRetainFormatPolicies) {
    for (const auto& contract : asn1_contracts) {
        for (unsigned cls = 0; cls < 4; ++cls) {
            for (int constructed = 0; constructed <= 1; ++constructed) {
                for (uint64_t number = 0; number <= 256; ++number) {
                    SCOPED_TRACE(::testing::Message() << contract.policy << ":" << cls << ":"
                                                      << constructed << ":" << number);
                    bool valid = cls != 0 || number != 0;
                    if (cls == 0 && contract.policy != 0) {
                        const bool must_construct = number == 8 || number == 11 || number == 16 ||
                                                    number == 17 || number == 29;
                        valid = valid && number != 15 && (!must_construct || constructed);
                        if (contract.policy == 1 && number <= 36)
                            valid = valid && ((constructed != 0) == must_construct);
                    }
                    uint8_t storage[TLV_ASN1_TAG_MAX_SIZE];
                    std::fill(std::begin(storage), std::end(storage), 0xA5);
                    const uint8_t sentinel[] = {0x81};
                    tlv_tag_t     tag = tlv_tag(sentinel, sizeof(sentinel));
                    EXPECT_EQ(valid ? TLV_OK : TLV_ERR_INVALID_TAG,
                              contract.make(static_cast<tlv_asn1_class_t>(cls), constructed, number,
                                            storage, &tag));
                    if (!valid) {
                        EXPECT_EQ(sentinel, tag.data);
                        EXPECT_EQ(1u, tag.size);
                        for (uint8_t byte : storage) EXPECT_EQ(0xA5, byte);
                        continue;
                    }
                    EXPECT_EQ(storage, tag.data);
                    EXPECT_EQ(cls, static_cast<unsigned>(tlv_asn1_tag_class(&tag)));
                    EXPECT_EQ(constructed, tlv_asn1_tag_is_constructed(&tag));
                    EXPECT_EQ(constructed, contract.format->is_constructed(nullptr, &tag));
                    uint64_t extracted = UINT64_MAX;
                    ASSERT_EQ(TLV_OK, contract.number(&tag, &extracted));
                    EXPECT_EQ(number, extracted);
                    tlv_element_t  element = {tag, {nullptr, 0}};
                    tlv_encoding_t encoding;
                    EXPECT_EQ(TLV_OK,
                              tlv_format_measure(contract.format, &element, &encoding, nullptr));
                }
            }
        }
        // High-tag-number raw BER compatibility is deliberately not ASN.1 canonical.
        const uint8_t   raw[] = {0x9F, 0x1C};
        const tlv_tag_t tag = tlv_tag(raw, sizeof(raw));
        uint64_t        number = 777;
        EXPECT_EQ(contract.policy == 0 ? TLV_OK : TLV_ERR_INVALID_TAG,
                  contract.number(&tag, &number));
        EXPECT_EQ(contract.policy == 0 ? 28u : 777u, number);
    }
}

TEST(Unit_Tlv_Asn1, SharedDefiniteEncodingAndCanonicalReadPolicy) {
    for (size_t length : {0u, 1u, 127u, 128u, 255u, 256u, 1000u}) {
        std::vector<uint8_t> value(length, 0xAB);
        const tlv_element_t  element = {TLV_TAG(0x04), {value.data(), length}};
        std::vector<uint8_t> reference(length + 10);
        size_t               reference_size = 0;
        ASSERT_EQ(TLV_OK, tlv_format_encode(&tlv_format_ber, &element, reference.data(),
                                            reference.size(), &reference_size, nullptr));
        reference.resize(reference_size);
        for (const auto& contract : asn1_contracts) {
            std::vector<uint8_t> output(length + 10, 0xCC);
            size_t               written = 0;
            ASSERT_EQ(TLV_OK, tlv_format_encode(contract.format, &element, output.data(),
                                                output.size(), &written, nullptr));
            output.resize(written);
            EXPECT_EQ(reference, output);
            tlv_decoded_t decoded;
            ASSERT_EQ(TLV_OK, tlv_format_decode(contract.format, output.data(), output.size(),
                                                &decoded, nullptr));
            EXPECT_EQ(length, decoded.element.value.size);
        }
    }
    const uint8_t padded[] = {0x04, 0x81, 0x01, 0xAB};
    for (const auto& contract : asn1_contracts) {
        tlv_decoded_t decoded;
        EXPECT_EQ(contract.policy == 0 ? TLV_OK : TLV_ERR_INVALID_LENGTH,
                  tlv_format_decode(contract.format, padded, sizeof(padded), &decoded, nullptr));
    }
}

TEST(Unit_Tlv_Asn1, LengthPoliciesKeepBorrowedContentsAndEocTrailerSeparate) {
    const uint8_t definite[] = {0x30, 0x04, 0x04, 0x02, 0, 0};
    const uint8_t indefinite[] = {0x30, 0x80, 0x30, 0x80, 0x04, 0x02, 0, 0, 0, 0, 0, 0};
    for (const auto& contract : asn1_contracts) {
        tlv_decoded_t decoded{};
        EXPECT_EQ(
            contract.policy == 2 ? TLV_ERR_INVALID_LENGTH : TLV_OK,
            tlv_format_decode(contract.format, definite, sizeof(definite), &decoded, nullptr));
        if (contract.policy == 1) {
            EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
                      tlv_format_decode(contract.format, indefinite, sizeof(indefinite), &decoded,
                                        nullptr));
            continue;
        }
        ASSERT_EQ(TLV_OK, tlv_format_decode(contract.format, indefinite, sizeof(indefinite),
                                            &decoded, nullptr));
        EXPECT_EQ(indefinite + 2, decoded.element.value.data);
        EXPECT_EQ(8u, decoded.element.value.size);
        EXPECT_EQ(10u, decoded.source.trailer.offset);
        EXPECT_EQ(2u, decoded.source.trailer.size);
        EXPECT_EQ(sizeof(indefinite), decoded.source.size);
        uint8_t copied[sizeof(indefinite)] = {};
        size_t  written = 0;
        ASSERT_EQ(TLV_OK, tlv_source_preserve(&decoded.source, &decoded.element, copied,
                                              sizeof(copied), &written));
        EXPECT_EQ(sizeof(indefinite), written);
        EXPECT_EQ(0, std::memcmp(copied, indefinite, written));
        // The two zero bytes inside OCTET STRING are contents, not a closing EOC.
        tlv_format_error_t error{};
        EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
                  tlv_format_decode(contract.format, indefinite, sizeof(indefinite) - 2, &decoded,
                                    &error));
        EXPECT_EQ(TLV_REGION_TRAILER, error.region);
        EXPECT_TRUE(error.has_offset);
        EXPECT_EQ(10u, error.offset);
        EXPECT_EQ(sizeof(indefinite), decoded.source.size); // failure leaves output intact
    }
}
