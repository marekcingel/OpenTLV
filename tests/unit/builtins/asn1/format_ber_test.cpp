#include "tlv/builtins/asn1/ber.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#include <gtest/gtest.h>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <vector>

namespace {
const auto& ber = tlv_reader_format_ber;
const auto& ber_writer = tlv_writer_format_ber;
} // namespace

TEST(Unit_Tlv_Ber, InvalidAndNonminimalLengths) {
    size_t length = 42, used = 42;
    for (uint8_t prefix : {0x80, 0xFF})
        EXPECT_EQ(TLV_ERR_INVALID_LENGTH, ber.read_length(nullptr, &prefix, 1, &length, &used));
    std::vector<uint8_t> overflow(sizeof(size_t) + 2, 0);
    overflow[0] = 0x80 | (sizeof(size_t) + 1);
    overflow[1] = 1;
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
              ber.read_length(nullptr, overflow.data(), overflow.size(), &length, &used));
    EXPECT_EQ(42u, length);
    EXPECT_EQ(42u, used);
    const uint8_t padded[] = {0x83, 0, 0, 0x7F};
    ASSERT_EQ(TLV_OK, ber.read_length(nullptr, padded, sizeof(padded), &length, &used));
    EXPECT_EQ(127u, length);
    EXPECT_EQ(4u, used);
    size_t total = 42;
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
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
    ASSERT_EQ(TLV_OK, ber.read_tag(nullptr, bytes.data(), bytes.size(), &tag, &used));
    EXPECT_EQ(bytes.size(), used);
    // The tag borrows the input rather than copying it.
    EXPECT_EQ(bytes.data(), tag.data);
    EXPECT_EQ(bytes.size(), tag.size);
    ASSERT_EQ(TLV_OK, ber_writer.write_tag(nullptr, nullptr, 0, &tag, &used));
    std::vector<uint8_t> output(bytes.size(), 0xEE);
    for (size_t capacity = 0; capacity < bytes.size(); ++capacity) {
        EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
                  ber_writer.write_tag(nullptr, output.data(), capacity, &tag, &used));
        for (auto byte : output) EXPECT_EQ(0xEE, byte);
    }
    ASSERT_EQ(TLV_OK, ber_writer.write_tag(nullptr, output.data(), output.size(), &tag, &used));
    EXPECT_EQ(bytes, output);
    // One byte more than the format supports is rejected, however the tag ends.
    bytes.assign(TLV_ASN1_TAG_MAX_SIZE + 1, 0x81);
    bytes[0] = 0x9F;
    bytes.back() = 1;
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE,
              ber.read_tag(nullptr, bytes.data(), bytes.size(), &tag, &used));
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE,
              ber.read_tag(nullptr, bytes.data(), TLV_ASN1_TAG_MAX_SIZE, &tag, &used));
    tag = tlv_tag(bytes.data(), bytes.size());
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE, ber_writer.write_tag(nullptr, nullptr, 0, &tag, &used));
    for (size_t size = 0; size < TLV_ASN1_TAG_MAX_SIZE; ++size)
        EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, ber.read_tag(nullptr, bytes.data(), size, &tag, &used));
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
    EXPECT_EQ(TLV_ERR_NULL_ARG, ber_writer.write_tag(nullptr, nullptr, 0, &missing, &used));
    const uint8_t invalid_tag[] = {0x9F, 0x80, 1};
    tlv_tag_t     tag{};
    EXPECT_EQ(TLV_ERR_INVALID_TAG,
              ber.read_tag(nullptr, invalid_tag, sizeof(invalid_tag), &tag, &used));
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
        EXPECT_EQ(c.cls, tlv_ber_tag_class(&tag));
        EXPECT_EQ(c.constructed, tlv_ber_tag_is_constructed(&tag));
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
            EXPECT_EQ(constructed, tlv_ber_tag_is_constructed(&tag));
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
        tlv_view_t view = {TLV_TAG(0xEE), {nullptr, 42}};
        EXPECT_EQ(size ? TLV_ERR_BUFFER_TOO_SHORT : TLV_ERR_END_OF_BUFFER,
                  tlv_reader_next(&reader, &view));
        EXPECT_EQ(0u, reader.pos);
        EXPECT_EQ(0xEE, view.tag.data[0]);
        EXPECT_EQ(nullptr, view.value.data);
        EXPECT_EQ(42u, view.value.length);
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
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_ber_indefinite_encoded_size(tag, SIZE_MAX, &written));
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
        tlv_length_t         value;
    } cases[] = {
        {{0x00}, 0},
        {{0x7F}, 127},
        {{0x81, 0x80}, 128},
        {{0x81, 0xFF}, 255},
        {{0x82, 0x01, 0x00}, 256},
        {{0x88, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, UINT64_MAX},
    };
    for (const auto& c : cases) {
        tlv_length_t value = 999;
        size_t       consumed = 999;
        ASSERT_EQ(TLV_OK, tlv_ber_length_decode(c.bytes.data(), c.bytes.size(), &value, &consumed));
        EXPECT_EQ(c.value, value);
        EXPECT_EQ(c.bytes.size(), consumed);
    }
}

TEST(Unit_Tlv_Ber, StandaloneLengthEncodeFixtures) {
    const struct {
        tlv_length_t         value;
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
    tlv_length_t value = 999;
    size_t       consumed = 999;
    for (uint8_t prefix : {0x80, 0xFF}) {
        EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_ber_length_decode(&prefix, 1, &value, &consumed));
        EXPECT_EQ(999u, value);
        EXPECT_EQ(999u, consumed);
    }
}

TEST(Unit_Tlv_Ber, StandaloneLengthDecodeOverflowAndNonminimalPadding) {
    tlv_length_t value = 999;
    size_t       consumed = 999;
    /* Declared width (9 octets) wider than uint64_t (8 octets), with a
     * nonzero excess octet: not representable in tlv_length_t. */
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
    tlv_length_t  value = 999;
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
    for (size_t width : {sizeof(size_t) + 1, size_t(9), size_t(126)}) {
        std::vector<uint8_t> bytes(width + 1, 0);
        bytes[0] = static_cast<uint8_t>(0x80 | width);
        bytes.back() = 0x7F;
        size_t length = 42, used = 43;
        ASSERT_EQ(TLV_OK, ber.read_length(nullptr, bytes.data(), bytes.size(), &length, &used));
        EXPECT_EQ(127u, length);
        EXPECT_EQ(bytes.size(), used);
        bytes.back() = 0;
        ASSERT_EQ(TLV_OK, ber.read_length(nullptr, bytes.data(), bytes.size(), &length, &used));
        EXPECT_EQ(0u, length);
        std::memset(bytes.data() + bytes.size() - sizeof(size_t), 255, sizeof(size_t));
        ASSERT_EQ(TLV_OK, ber.read_length(nullptr, bytes.data(), bytes.size(), &length, &used));
        EXPECT_EQ(SIZE_MAX, length);
        bytes[1] = 1;
        length = 42;
        used = 43;
        for (size_t size = 0; size < bytes.size(); ++size) {
            EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
                      ber.read_length(nullptr, bytes.data(), size, &length, &used));
            EXPECT_EQ(42u, length);
            EXPECT_EQ(43u, used);
        }
        EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
                  ber.read_length(nullptr, bytes.data(), bytes.size(), &length, &used));
        EXPECT_EQ(42u, length);
        EXPECT_EQ(43u, used);
    }
}
