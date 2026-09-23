#include "tlv/config.h"
#if OPENTLV_FORMAT_BER
#include "tlv/builtins/asn1/ber.h"
#endif
#include "tlv/builtins/asn1/der.h"
#include "tlv/builtins/asn1/der_profile.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#include <gtest/gtest.h>
#include <cstring>
#include <vector>

TEST(Unit_Tlv_Der, UniversalPrimitiveConstructedRules) {
    for (uint64_t number = 0; number <= 36; ++number) {
        const bool must_construct =
            number == 8 || number == 11 || number == 16 || number == 17 || number == 29;
        for (int constructed : {0, 1}) {
            tlv_tag_t tag{};
            uint8_t   storage[TLV_ASN1_TAG_MAX_SIZE];
            EXPECT_EQ(number == 0 || number == 15 || ((constructed != 0) != must_construct)
                          ? TLV_ERR_INVALID_TAG
                          : TLV_OK,
                      tlv_der_tag_make(TLV_ASN1_UNIVERSAL, constructed, number, storage, &tag));
            EXPECT_EQ(TLV_OK, tlv_der_tag_make(TLV_ASN1_CONTEXT_SPECIFIC, constructed, number,
                                               storage, &tag));
        }
    }
}

TEST(Unit_Tlv_Der, EmptyArgumentsAndVisitorControl) {
    tlv_view_t view{};
    size_t     used = 99, offset = 99;
    EXPECT_EQ(TLV_ERR_END_OF_BUFFER, tlv_der_read(nullptr, 0, nullptr, &view, &used, &offset));
    EXPECT_EQ(0u, offset);
    EXPECT_EQ(99u, used);
    EXPECT_EQ(TLV_OK, tlv_der_walk(nullptr, 0, nullptr, nullptr, nullptr, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_der_walk(nullptr, 1, nullptr, nullptr, nullptr, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_der_read(nullptr, 0, nullptr, nullptr, &used, nullptr));
    uint8_t storage[TLV_ASN1_TAG_MAX_SIZE];
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_der_tag_make(TLV_ASN1_PRIVATE, 0, 1, storage, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_der_tag_make(TLV_ASN1_PRIVATE, 0, 1, nullptr, &view.tag));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_der_tag_number(nullptr, nullptr));
    EXPECT_EQ(TLV_ERR_INVALID_TAG, tlv_der_tag_make(TLV_ASN1_PRIVATE, 2, 1, storage, &view.tag));
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              tlv_der_write(nullptr, 1, (TLV_TAG(4)), nullptr, 0, nullptr, &used, nullptr));
    const uint8_t data[] = {4, 0, 0xFF};
    auto          stop = [](const tlv_view_t*, size_t, size_t, void*) { return TLV_VISIT_STOP; };
    auto          error = [](const tlv_view_t*, size_t, size_t, void*) { return TLV_VISIT_ERROR; };
    EXPECT_EQ(TLV_OK, tlv_der_walk(data, sizeof(data), nullptr, stop, nullptr, nullptr));
    EXPECT_EQ(TLV_ERR_VISITOR, tlv_der_walk(data, sizeof(data), nullptr, error, nullptr, &offset));
    EXPECT_EQ(0u, offset);
    EXPECT_NE(TLV_OK, tlv_der_walk(data, sizeof(data), nullptr, nullptr, nullptr, nullptr));
}

TEST(Unit_Tlv_Der, TagSizeErrorsPreserveOutputs) {
    tlv_tag_t tag{};
    uint64_t  number = 42;
    size_t    written = 99;
    uint8_t   output[TLV_ASN1_TAG_MAX_SIZE] = {0xEE};
    uint8_t   storage[TLV_ASN1_TAG_MAX_SIZE];
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE, tlv_der_tag_number(&tag, &number));
    EXPECT_EQ(42u, number);
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE,
              tlv_writer_format_der.write_tag(nullptr, output, sizeof(output), &tag, &written));
    EXPECT_EQ(99u, written);
    EXPECT_EQ(0xEE, output[0]);
    // The longest tag the format accepts, with a high-tag-number that never ends.
    const uint8_t unterminated[TLV_ASN1_TAG_MAX_SIZE] = {0x9F, 0x81, 0x81, 0x81,
                                                         0x81, 0x81, 0x81, 0x81};
    tag = tlv_tag(unterminated, sizeof(unterminated));
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE, tlv_der_tag_number(&tag, &number));
    EXPECT_EQ(42u, number);
    // A well-formed tag one byte over the format limit is rejected by the format, not the type.
    const uint8_t too_long[TLV_ASN1_TAG_MAX_SIZE + 1] = {0x9F, 0x81, 0x81, 0x81, 0x81,
                                                         0x81, 0x81, 0x81, 0x01};
    tag = tlv_tag(too_long, sizeof(too_long));
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE, tlv_der_tag_number(&tag, &number));
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE,
              tlv_writer_format_der.write_tag(nullptr, output, sizeof(output), &tag, &written));
    EXPECT_EQ(99u, written);
    const tlv_tag_t before = tag;
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE,
              tlv_der_tag_make(TLV_ASN1_PRIVATE, 0, UINT64_MAX, storage, &tag));
    EXPECT_EQ(before.data, tag.data);
    EXPECT_EQ(before.size, tag.size);
}
