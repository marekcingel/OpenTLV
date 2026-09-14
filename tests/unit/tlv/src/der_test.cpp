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

TEST(Unit_Der, UniversalPrimitiveConstructedRules) {
    for (uint64_t number = 0; number <= 36; ++number) {
        if (number >= 31 && TLV_TAG_CAPACITY < 2) continue;
        const bool must_construct = number == 8 || number == 11 || number == 16 ||
                                    number == 17 || number == 29;
        for (int constructed : {0, 1}) {
            tlv_tag_t tag{};
            EXPECT_EQ(number == 0 || number == 15 || ((constructed != 0) != must_construct)
                          ? TLV_ERR_INVALID_TAG : TLV_OK,
                      tlv_der_tag_make(TLV_ASN1_UNIVERSAL, constructed, number, &tag));
            EXPECT_EQ(TLV_OK, tlv_der_tag_make(TLV_ASN1_CONTEXT_SPECIFIC, constructed, number, &tag));
        }
    }
}



TEST(Unit_Der, EmptyArgumentsAndVisitorControl) {
    tlv_view_t view{};
    size_t used = 99, offset = 99;
    EXPECT_EQ(TLV_ERR_END_OF_BUFFER, tlv_der_read(nullptr, 0, nullptr, &view, &used, &offset));
    EXPECT_EQ(0u, offset);
    EXPECT_EQ(99u, used);
    EXPECT_EQ(TLV_OK, tlv_der_walk(nullptr, 0, nullptr, nullptr, nullptr, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_der_walk(nullptr, 1, nullptr, nullptr, nullptr, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_der_read(nullptr, 0, nullptr, nullptr, &used, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_der_tag_make(TLV_ASN1_PRIVATE, 0, 1, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_der_tag_number(nullptr, nullptr));
    EXPECT_EQ(TLV_ERR_INVALID_TAG, tlv_der_tag_make(TLV_ASN1_PRIVATE, 2, 1, &view.tag));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_der_write(nullptr, 1, (tlv_tag_t{{4}, 1}), nullptr, 0,
                                            nullptr, &used, nullptr));
    const uint8_t data[] = {4, 0, 0xFF};
    auto stop = [](const tlv_view_t*, size_t, size_t, void*) { return TLV_VISIT_STOP; };
    auto error = [](const tlv_view_t*, size_t, size_t, void*) { return TLV_VISIT_ERROR; };
    EXPECT_EQ(TLV_OK, tlv_der_walk(data, sizeof(data), nullptr, stop, nullptr, nullptr));
    EXPECT_EQ(TLV_ERR_VISITOR, tlv_der_walk(data, sizeof(data), nullptr, error, nullptr, &offset));
    EXPECT_EQ(0u, offset);
    EXPECT_NE(TLV_OK, tlv_der_walk(data, sizeof(data), nullptr, nullptr, nullptr, nullptr));
}

TEST(Unit_Der, TagSizeErrorsPreserveOutputs) {
    tlv_tag_t tag{};
    uint64_t number = 42;
    size_t written = 99;
    uint8_t output[TLV_TAG_CAPACITY] = {0xEE};
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE, tlv_der_tag_number(&tag, &number));
    EXPECT_EQ(42u, number);
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE,
              tlv_writer_format_der.write_tag(nullptr, output, sizeof(output), &tag, &written));
    EXPECT_EQ(99u, written);
    EXPECT_EQ(0xEE, output[0]);
#if TLV_TAG_CAPACITY < TLV_TAG_MAX_SUPPORTED_SIZE
    tag.size = TLV_TAG_CAPACITY + 1;
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE, tlv_der_tag_number(&tag, &number));
    EXPECT_EQ(42u, number);
#endif
    tag = tlv_tag_t{{0x9F}, TLV_TAG_CAPACITY};
    for (size_t i = 1; i < TLV_TAG_CAPACITY; ++i) tag.data[i] = 0x81;
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE, tlv_der_tag_number(&tag, &number));
    EXPECT_EQ(42u, number);
#if TLV_TAG_CAPACITY < 11
    const tlv_tag_t before = tag;
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE,
              tlv_der_tag_make(TLV_ASN1_PRIVATE, 0, UINT64_MAX, &tag));
    EXPECT_EQ(0, std::memcmp(&before, &tag, sizeof(tag)));
#endif
}
