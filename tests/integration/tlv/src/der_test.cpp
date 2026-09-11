#include "tlv/config.h"
#if OPENTLV_FORMAT_BER
#include "tlv/formats/asn1/ber.h"
#endif
#include "tlv/formats/asn1/der.h"
#include "tlv/profiles/der.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#include <gtest/gtest.h>
#include <cstring>
#include <vector>

TEST(Integration_Der, TagClassesNumbersAndForms) {
    for (auto cls : {TLV_ASN1_UNIVERSAL, TLV_ASN1_APPLICATION,
                     TLV_ASN1_CONTEXT_SPECIFIC, TLV_ASN1_PRIVATE}) {
        for (uint64_t number : {UINT64_C(4), UINT64_C(30), UINT64_C(31), UINT64_C(127),
                                UINT64_C(128), UINT64_C(16384), UINT64_MAX}) {
            for (int constructed : {0, 1}) {
                tlv_tag_t tag{};
                size_t digits = 1;
                if (number >= 31) for (uint64_t n = number; n; n >>= 7) ++digits;
                const bool invalid = digits > TLV_TAG_MAX_SIZE ||
                    (cls == TLV_ASN1_UNIVERSAL && number <= 36 && constructed);
                ASSERT_EQ(invalid ? TLV_ERR_INVALID_TAG : TLV_OK,
                          tlv_der_tag_make(cls, constructed, number, &tag));
                if (invalid) continue;
                EXPECT_EQ(cls, tlv_der_tag_class(&tag));
                EXPECT_EQ(constructed, tlv_der_tag_is_constructed(&tag));
                uint64_t actual = 0;
                ASSERT_EQ(TLV_OK, tlv_der_tag_number(&tag, &actual));
                EXPECT_EQ(number, actual);
                uint8_t encoded[TLV_TAG_MAX_SIZE + 1];
                size_t written = 0, consumed = 0;
                ASSERT_EQ(TLV_OK, tlv_der_write(encoded, sizeof(encoded), tag, nullptr,
                                               0, nullptr, &written, nullptr));
                tlv_view_t view{};
                ASSERT_EQ(TLV_OK, tlv_der_read(encoded, written, nullptr, &view, &consumed, nullptr));
                EXPECT_EQ(written, consumed);
                EXPECT_EQ(0, std::memcmp(tag.data, view.tag.data, tag.size));
            }
        }
    }
}

TEST(Integration_Der, CanonicalLengthBytesAndRoundTrip) {
    const tlv_tag_t tag = {{0x04}, 1};
    for (size_t length : {0u, 1u, 127u, 128u, 255u, 256u, 65535u, 65536u}) {
        std::vector<uint8_t> value(length, 0xAB);
        size_t required = 0, used = 0, written = 0;
        ASSERT_EQ(TLV_OK, tlv_der_write(nullptr, 0, tag, value.data(), length,
                                       nullptr, &required, nullptr));
        std::vector<uint8_t> data(required), again(required);
        ASSERT_EQ(TLV_OK, tlv_der_write(data.data(), data.size(), tag, value.data(), length,
                                       nullptr, &written, nullptr));
        EXPECT_EQ(required, written);
        if (length < 128) EXPECT_EQ(length, data[1]);
        else {
            size_t octets = 0;
            for (size_t n = length; n; n >>= 8) ++octets;
            EXPECT_EQ(0x80 | octets, data[1]);
            EXPECT_NE(0, data[2]);
        }
        tlv_view_t view{};
        ASSERT_EQ(TLV_OK, tlv_der_read(data.data(), data.size(), nullptr, &view, &used, nullptr));
        EXPECT_EQ(required, used);
        EXPECT_EQ(length, view.value.length);
        ASSERT_EQ(TLV_OK, tlv_der_write(again.data(), again.size(), view.tag, view.value.data,
                                       view.value.length, nullptr, &written, nullptr));
        EXPECT_EQ(data, again);
    }
    const auto& format = tlv_reader_format_der;
    uint8_t bytes[sizeof(size_t) + 1];
    size_t written, actual, used;
    ASSERT_EQ(TLV_OK, tlv_writer_format_der.write_length(nullptr, bytes, sizeof(bytes), SIZE_MAX, &written));
    ASSERT_EQ(TLV_OK, format.read_length(nullptr, bytes, written, &actual, &used));
    EXPECT_EQ(SIZE_MAX, actual);
    EXPECT_EQ(written, used);
}

TEST(Integration_Der, InvalidFieldsHaveOffsetsAndPreserveOutputs) {
    struct Case { std::vector<uint8_t> bytes; tlv_result_t error; size_t offset; };
    std::vector<Case> cases = {
        {{0x04}, TLV_ERR_BUFFER_TOO_SHORT, 1},
        {{0x04, 0x80}, TLV_ERR_INVALID_LENGTH, 1},
        {{0x04, 0xFF}, TLV_ERR_INVALID_LENGTH, 1},
        {{0x04, 0x81, 0x7F}, TLV_ERR_INVALID_LENGTH, 1},
        {{0x04, 0x82, 0, 0x80}, TLV_ERR_INVALID_LENGTH, 1},
        {{0x04, 0x82, 1}, TLV_ERR_BUFFER_TOO_SHORT, 1},
        {{0x04, 2, 0}, TLV_ERR_BUFFER_TOO_SHORT, 2},
        {{0x30, 3, 0x04, 2, 0}, TLV_ERR_BUFFER_TOO_SHORT, 4},
        {{0x30, 2, 0x04, 0x80}, TLV_ERR_INVALID_LENGTH, 3},
        {{0x30, 1, 0x04, 0}, TLV_ERR_BUFFER_TOO_SHORT, 3},
        {{0, 0}, TLV_ERR_INVALID_TAG, 0},
        {{0x0F, 0}, TLV_ERR_INVALID_TAG, 0},
        {{0x24, 0}, TLV_ERR_INVALID_TAG, 0},
        {{0x10, 0}, TLV_ERR_INVALID_TAG, 0},
        {{0x30, 2, 0x21, 0}, TLV_ERR_INVALID_TAG, 2}
    };
    if (TLV_TAG_MAX_SIZE > 1) {
        cases.push_back({{0x9F, 0x1E, 0}, TLV_ERR_INVALID_TAG, 0});
        cases.push_back({{0x9F, 0x80, 0x1F, 0}, TLV_ERR_INVALID_TAG, 0});
        cases.push_back({{0x9F}, TLV_ERR_BUFFER_TOO_SHORT, 0});
    }
    std::vector<uint8_t> overflow(sizeof(size_t) + 3, 0);
    overflow[0] = 4;
    overflow[1] = static_cast<uint8_t>(0x80 | (sizeof(size_t) + 1));
    overflow[2] = 1;
    cases.push_back({overflow, TLV_ERR_INVALID_LENGTH, 1});
    for (const auto& item : cases) {
        SCOPED_TRACE(::testing::PrintToString(item.bytes));
        tlv_view_t view{{{0x55}, 1}, {nullptr, 42}};
        size_t consumed = 42, offset = 99;
        EXPECT_EQ(item.error, tlv_der_read(item.bytes.data(), item.bytes.size(), nullptr,
                                          &view, &consumed, &offset));
        EXPECT_EQ(item.offset, offset);
        EXPECT_EQ(42u, consumed);
        EXPECT_EQ(0x55, view.tag.data[0]);
        EXPECT_EQ(42u, view.value.length);
    }
}

namespace {
struct Visit { size_t offset; size_t depth; uint8_t tag; };
tlv_visit_result_t collect(const tlv_view_t* view, size_t depth, size_t offset, void* context) {
    static_cast<std::vector<Visit>*>(context)->push_back({offset, depth, view->tag.data[0]});
    return TLV_VISIT_CONTINUE;
}
}

TEST(Integration_Der, NestedTraversalAndEncoding) {
    const uint8_t data[] = {0x30, 9, 0x02, 1, 5, 0xA0, 4, 0x04, 0, 0x30, 0, 0x05, 0};
    std::vector<Visit> visits;
    size_t offset = 99;
    ASSERT_EQ(TLV_OK, tlv_der_walk(data, sizeof(data), nullptr, collect, &visits, &offset));
    ASSERT_EQ(6u, visits.size());
    const size_t offsets[] = {0, 2, 5, 7, 9, 11}, depths[] = {0, 1, 1, 2, 2, 0};
    for (size_t i = 0; i < visits.size(); ++i) {
        EXPECT_EQ(offsets[i], visits[i].offset);
        EXPECT_EQ(depths[i], visits[i].depth);
        EXPECT_EQ(data[offsets[i]], visits[i].tag);
    }
    EXPECT_EQ(99u, offset);
    tlv_view_t view{};
    size_t consumed, written;
    ASSERT_EQ(TLV_OK, tlv_der_read(data, sizeof(data), nullptr, &view, &consumed, nullptr));
    EXPECT_EQ(11u, consumed);
    EXPECT_EQ(data + 2, view.value.data);
    uint8_t output[11];
    ASSERT_EQ(TLV_OK, tlv_der_write(output, sizeof(output), view.tag, view.value.data,
                                   view.value.length, nullptr, &written, nullptr));
    EXPECT_EQ(11u, written);
    EXPECT_EQ(0, std::memcmp(data, output, written));
}

TEST(Integration_Der, LimitsAndWriterValidation) {
    const uint8_t data[] = {0x30, 4, 0xA0, 2, 0x04, 0};
    tlv_der_limits_t limits = {2, sizeof(data), 4, 3};
    size_t offset = 99, written = 99;
    ASSERT_EQ(TLV_OK, tlv_der_walk(data, sizeof(data), &limits, nullptr, nullptr, &offset));
    for (int limit = 0; limit < 4; ++limit) {
        auto restricted = limits;
        size_t expected;
        switch (limit) {
            case 0: restricted.max_depth = 1; expected = 4; break;
            case 1: restricted.max_input_size = 5; expected = 0; break;
            case 2: restricted.max_value_size = 3; expected = 1; break;
            default: restricted.max_elements = 2; expected = 4; break;
        }
        EXPECT_EQ(TLV_ERR_LIMIT, tlv_der_walk(data, sizeof(data), &restricted, nullptr, nullptr, &offset));
        EXPECT_EQ(expected, offset);
        EXPECT_EQ(TLV_ERR_LIMIT, tlv_der_write(nullptr, 0, (tlv_tag_t{{0x30}, 1}),
                                              data + 2, 4, &restricted, &written, &offset));
        EXPECT_EQ(expected, offset);
        EXPECT_EQ(99u, written);
    }
    limits.max_depth = TLV_DER_MAX_DEPTH + 1;
    EXPECT_EQ(TLV_ERR_LIMIT, tlv_der_walk(nullptr, 0, &limits, nullptr, nullptr, &offset));
    limits = {0, 2, 0, 1};
    EXPECT_EQ(TLV_OK, tlv_der_walk(data + 4, 2, &limits, nullptr, nullptr, &offset));
    const uint8_t invalid[] = {0x04, 0x81, 0};
    uint8_t output[8];
    std::memset(output, 0xEE, sizeof(output));
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_der_write(output, sizeof(output), (tlv_tag_t{{0x30}, 1}),
                                                  invalid, sizeof(invalid), nullptr, &written, &offset));
    EXPECT_EQ(3u, offset);
    EXPECT_EQ(99u, written);
    for (auto byte : output) EXPECT_EQ(0xEE, byte);
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_der_write(output, 1, (tlv_tag_t{{4}, 1}),
                                                    nullptr, 0, nullptr, &written, &offset));
    for (auto byte : output) EXPECT_EQ(0xEE, byte);
}

TEST(Integration_Der, DeepNestingUsesBoundedTraversal) {
    std::vector<uint8_t> data = {4, 0};
    for (size_t depth = 1; depth <= TLV_DER_MAX_DEPTH + 1; ++depth) {
        size_t size;
        ASSERT_EQ(TLV_OK, tlv_encoded_size((tlv_tag_t{{0xA0}, 1}), data.size(), &tlv_writer_format_der, &size));
        std::vector<uint8_t> outer(size);
        ASSERT_EQ(TLV_OK, tlv_write(outer.data(), outer.size(), &tlv_writer_format_der,
                                    (tlv_tag_t{{0xA0}, 1}), data.data(), data.size(), &size));
        data.swap(outer);
        auto limits = tlv_der_default_limits;
        limits.max_depth = TLV_DER_MAX_DEPTH;
        EXPECT_EQ(depth <= TLV_DER_MAX_DEPTH ? TLV_OK : TLV_ERR_LIMIT,
                  tlv_der_walk(data.data(), data.size(), &limits, nullptr, nullptr, nullptr));
    }
}

TEST(Integration_Der, BerCompatibilityAndGenericFormat) {
    std::vector<std::vector<uint8_t>> cases = {{4, 0x81, 0}, {4, 0x82, 0, 0}, {0x24, 0}};
    if (TLV_TAG_MAX_SIZE > 1) cases.push_back({0x9F, 0x1C, 0});
    for (const auto& data : cases) {
        tlv_view_t view{};
        size_t used;
#if OPENTLV_FORMAT_BER
        ASSERT_EQ(TLV_OK, tlv_read(data.data(), data.size(), &tlv_reader_format_ber, &view, &used));
#endif
        EXPECT_NE(TLV_OK, tlv_read(data.data(), data.size(), &tlv_reader_format_der, &view, &used));
    }
    // Generic I/O intentionally only validates the outer header.
    const uint8_t data[] = {0x30, 2, 0, 0};
    tlv_view_t view{};
    size_t used;
    ASSERT_EQ(TLV_OK, tlv_read(data, sizeof(data), &tlv_reader_format_der, &view, &used));
    EXPECT_EQ(TLV_ERR_INVALID_TAG, tlv_der_read(data, sizeof(data), nullptr, &view, &used, nullptr));
}

TEST(Integration_Der, TagCapacityAndNumericOverflow) {
    std::vector<uint8_t> data(TLV_TAG_MAX_SIZE + 1, 0x81);
    data[0] = 0x9F;
    tlv_view_t view{};
    size_t used;
    EXPECT_EQ(TLV_ERR_INVALID_TAG, tlv_der_read(data.data(), data.size(), nullptr, &view, &used, nullptr));
    if (TLV_TAG_MAX_SIZE > 1) {
        data[TLV_TAG_MAX_SIZE - 1] = 0x7F;
        data[TLV_TAG_MAX_SIZE] = 0;
        ASSERT_EQ(TLV_OK, tlv_der_read(data.data(), data.size(), nullptr, &view, &used, nullptr));
        uint64_t number = 42;
        EXPECT_EQ(TLV_TAG_MAX_SIZE > 11 ? TLV_ERR_INVALID_TAG : TLV_OK,
                  tlv_der_tag_number(&view.tag, &number));
        if (TLV_TAG_MAX_SIZE > 11) EXPECT_EQ(42u, number);
    }
}

