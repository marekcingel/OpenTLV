#include "tlv/config.h"
#if OPENTLV_FORMAT_BER
#include "tlv/formats/asn1/ber.h"
#endif
#include "tlv/formats/asn1/cer.h"
#include "tlv/profiles/cer.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#include <gtest/gtest.h>
#include <cstring>
#include <vector>

TEST(Unit_Cer, AlwaysConstructedSetRequiresConstructedForm) {
    /* EXTERNAL(8), EMBEDDED PDV(11), SEQUENCE(16), SET(17), CHARACTER STRING(29)
     * must be constructed; unlike DER, every other assigned number accepts
     * either form at the raw tag level -- CER's own profile decides the
     * legal form contextually (segmentable vs. not, and by content length). */
    for (uint64_t number = 0; number <= 36; ++number) {
        const bool must_construct =
            number == 8 || number == 11 || number == 16 || number == 17 || number == 29;
        for (int constructed : {0, 1}) {
            tlv_tag_t  tag{};
            uint8_t    storage[TLV_ASN1_TAG_MAX_SIZE];
            const bool invalid_universal =
                number == 0 || number == 15 || (must_construct && !constructed);
            EXPECT_EQ(invalid_universal ? TLV_ERR_INVALID_TAG : TLV_OK,
                      tlv_cer_tag_make(TLV_ASN1_UNIVERSAL, constructed, number, storage, &tag));
            EXPECT_EQ(TLV_OK, tlv_cer_tag_make(TLV_ASN1_CONTEXT_SPECIFIC, constructed, number,
                                               storage, &tag));
        }
    }
}

TEST(Unit_Cer, TagClassAndConstructedAccessors) {
    tlv_tag_t tag{};
    uint8_t   storage[TLV_ASN1_TAG_MAX_SIZE];
    ASSERT_EQ(TLV_OK, tlv_cer_tag_make(TLV_ASN1_APPLICATION, 1, 4, storage, &tag));
    EXPECT_EQ(storage, tag.data);
    EXPECT_EQ(TLV_ASN1_APPLICATION, tlv_cer_tag_class(&tag));
    EXPECT_EQ(1, tlv_cer_tag_is_constructed(&tag));
    uint64_t number = 0;
    ASSERT_EQ(TLV_OK, tlv_cer_tag_number(&tag, &number));
    EXPECT_EQ(4u, number);
}

TEST(Unit_Cer, EmptyArgumentsAndVisitorControl) {
    tlv_view_t view{};
    size_t     used = 99, offset = 99;
    EXPECT_EQ(TLV_ERR_END_OF_BUFFER, tlv_cer_read(nullptr, 0, nullptr, &view, &used, &offset));
    EXPECT_EQ(0u, offset);
    EXPECT_EQ(99u, used);
    EXPECT_EQ(TLV_OK, tlv_cer_walk(nullptr, 0, nullptr, nullptr, nullptr, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_cer_walk(nullptr, 1, nullptr, nullptr, nullptr, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_cer_read(nullptr, 0, nullptr, nullptr, &used, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              tlv_cer_write(nullptr, 1, (TLV_TAG(4)), nullptr, 0, nullptr, &used, nullptr));
    const uint8_t data[] = {4, 0, 0xFF};
    auto          stop = [](const tlv_view_t*, size_t, size_t, void*) { return TLV_VISIT_STOP; };
    auto          error = [](const tlv_view_t*, size_t, size_t, void*) { return TLV_VISIT_ERROR; };
    EXPECT_EQ(TLV_OK, tlv_cer_walk(data, sizeof(data), nullptr, stop, nullptr, nullptr));
    EXPECT_EQ(TLV_ERR_VISITOR, tlv_cer_walk(data, sizeof(data), nullptr, error, nullptr, &offset));
    EXPECT_EQ(0u, offset);
    EXPECT_NE(TLV_OK, tlv_cer_walk(data, sizeof(data), nullptr, nullptr, nullptr, nullptr));
}

TEST(Unit_Cer, TagSizeErrorsPreserveOutputs) {
    tlv_tag_t tag{};
    uint64_t  number = 42;
    size_t    written = 99;
    uint8_t   output[TLV_ASN1_TAG_MAX_SIZE] = {0xEE};
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE, tlv_cer_tag_number(&tag, &number));
    EXPECT_EQ(42u, number);
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE,
              tlv_writer_format_cer.write_tag(nullptr, output, sizeof(output), &tag, &written));
    EXPECT_EQ(99u, written);
    EXPECT_EQ(0xEE, output[0]);
}

TEST(Unit_Cer, PrimitiveIndefiniteAndConstructedDefiniteAreRejected) {
    /* Primitive tag with the indefinite marker. */
    const uint8_t primitive_indefinite[] = {0x04, 0x80};
    tlv_view_t    view{};
    size_t        consumed = 42, offset = 99;
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
              tlv_cer_read(primitive_indefinite, sizeof(primitive_indefinite), nullptr, &view,
                           &consumed, &offset));
    EXPECT_EQ(1u, offset);

    /* Constructed tag with a definite length. */
    const uint8_t constructed_definite[] = {0x30, 3, 0x02, 1, 5};
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
              tlv_cer_read(constructed_definite, sizeof(constructed_definite), nullptr, &view,
                           &consumed, &offset));
    EXPECT_EQ(1u, offset);
}

TEST(Unit_Cer, NonSegmentableUniversalTypeRejectsConstructedForm) {
    /* INTEGER is UNIVERSAL, not segmentable, and not in the always-
     * constructed set: CER never permits a constructed encoding of it,
     * even though the raw identifier octet alone would parse. */
    const uint8_t data[] = {0x22, 0x80, 0x02, 1, 5, 0, 0}; /* 0x22 = constructed INTEGER */
    tlv_view_t    view{};
    size_t        consumed, offset = 99;
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
              tlv_cer_read(data, sizeof(data), nullptr, &view, &consumed, &offset));
    EXPECT_EQ(1u, offset);
}
