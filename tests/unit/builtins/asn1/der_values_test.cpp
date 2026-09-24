#include "tlv/config.h"
#if OPENTLV_FORMAT_BER
#include "tlv/builtins/asn1/ber.h"
#endif
#include "tlv/builtins/asn1/der.h"
#include "tlv/builtins/asn1/der_profile.h"
#include <gtest/gtest.h>
#include <vector>

namespace {

std::vector<uint8_t> wrap(uint8_t tag_byte, const std::vector<uint8_t>& content) {
    const tlv_tag_t tag = tlv_tag(&tag_byte, 1);
    size_t          required = 0, written = 0;
    EXPECT_EQ(TLV_OK, tlv_der_write(nullptr, 0, tag, content.empty() ? nullptr : content.data(),
                                    content.size(), nullptr, &required, nullptr));
    std::vector<uint8_t> data(required);
    EXPECT_EQ(TLV_OK, tlv_der_write(data.data(), data.size(), tag,
                                    content.empty() ? nullptr : content.data(), content.size(),
                                    nullptr, &written, nullptr));
    EXPECT_EQ(required, written);
    return data;
}

/* Every case must structurally validate under the non-strict, opaque-content
 * functions (existing DER-TLV behavior is unaffected by this story). */
void check(uint8_t tag_byte, const std::vector<uint8_t>& content, tlv_result_t expect) {
    const std::vector<uint8_t> data = wrap(tag_byte, content);
    tlv_view_t                 view{};
    size_t                     consumed = 0, offset = 99;
    EXPECT_EQ(TLV_OK, tlv_der_read(data.data(), data.size(), nullptr, &view, &consumed, nullptr));
    EXPECT_EQ(expect,
              tlv_der_read_strict(data.data(), data.size(), nullptr, &view, &consumed, &offset));
    if (expect != TLV_OK) EXPECT_EQ(data.size() - content.size(), offset);
}

/* Same as wrap()/check(), but for a universal tag number that may need the
 * high-tag-number form (31 and above), unlike wrap()'s single tag byte. */
std::vector<uint8_t> wrap_number(uint64_t number, const std::vector<uint8_t>& content) {
    tlv_tag_t tag{};
    uint8_t   storage[TLV_ASN1_TAG_MAX_SIZE];
    EXPECT_EQ(TLV_OK, tlv_der_tag_make(TLV_ASN1_UNIVERSAL, 0, number, storage, &tag));
    size_t required = 0, written = 0;
    EXPECT_EQ(TLV_OK, tlv_der_write(nullptr, 0, tag, content.empty() ? nullptr : content.data(),
                                    content.size(), nullptr, &required, nullptr));
    std::vector<uint8_t> data(required);
    EXPECT_EQ(TLV_OK, tlv_der_write(data.data(), data.size(), tag,
                                    content.empty() ? nullptr : content.data(), content.size(),
                                    nullptr, &written, nullptr));
    EXPECT_EQ(required, written);
    return data;
}

void check_number(uint64_t number, const std::vector<uint8_t>& content, tlv_result_t expect) {
    const std::vector<uint8_t> data = wrap_number(number, content);
    tlv_view_t                 view{};
    size_t                     consumed = 0, offset = 99;
    EXPECT_EQ(TLV_OK, tlv_der_read(data.data(), data.size(), nullptr, &view, &consumed, nullptr));
    EXPECT_EQ(expect,
              tlv_der_read_strict(data.data(), data.size(), nullptr, &view, &consumed, &offset));
    if (expect != TLV_OK) EXPECT_EQ(data.size() - content.size(), offset);
}

} // namespace

TEST(Unit_Tlv_DerValues, Boolean) {
    check(0x01, {0x00}, TLV_OK);
    check(0x01, {0xFF}, TLV_OK);
    check(0x01, {0x01}, TLV_ERR_INVALID_VALUE);
    check(0x01, {}, TLV_ERR_INVALID_VALUE);
    check(0x01, {0x00, 0x00}, TLV_ERR_INVALID_VALUE);
}

TEST(Unit_Tlv_DerValues, IntegerAndEnumerated) {
    for (uint8_t tag_byte : {0x02, 0x0A}) {
        check(tag_byte, {0x00}, TLV_OK);
        check(tag_byte, {0x7F}, TLV_OK);
        check(tag_byte, {0xFF}, TLV_OK);
        check(tag_byte, {0x00, 0x80}, TLV_OK);
        check(tag_byte, {0xFF, 0x7F}, TLV_OK);
        check(tag_byte, {}, TLV_ERR_INVALID_VALUE);
        check(tag_byte, {0x00, 0x7F}, TLV_ERR_INVALID_VALUE);
        check(tag_byte, {0xFF, 0x80}, TLV_ERR_INVALID_VALUE);
    }
}

TEST(Unit_Tlv_DerValues, BitString) {
    check(0x03, {0x00}, TLV_OK);
    check(0x03, {0x00, 0xFF}, TLV_OK);
    check(0x03, {0x04, 0xF0}, TLV_OK);
    check(0x03, {0x07, 0x80}, TLV_OK);
    check(0x03, {}, TLV_ERR_INVALID_VALUE);
    check(0x03, {0x08, 0x00}, TLV_ERR_INVALID_VALUE);
    check(0x03, {0x01}, TLV_ERR_INVALID_VALUE);
    check(0x03, {0x04, 0xFF}, TLV_ERR_INVALID_VALUE);
}

TEST(Unit_Tlv_DerValues, OctetStringIsUnconstrained) {
    check(0x04, {}, TLV_OK);
    check(0x04, {0x00, 0xFF, 0x7F}, TLV_OK);
}

TEST(Unit_Tlv_DerValues, Null) {
    check(0x05, {}, TLV_OK);
    check(0x05, {0x00}, TLV_ERR_INVALID_VALUE);
}

TEST(Unit_Tlv_DerValues, ObjectIdentifierAndRelativeOid) {
    for (uint8_t tag_byte : {0x06, 0x0D}) {
        check(tag_byte, {0x2A, 0x03}, TLV_OK);
        check(tag_byte, {0x81, 0x00}, TLV_OK);
        check(tag_byte, {}, TLV_ERR_INVALID_VALUE);
        check(tag_byte, {0x80, 0x01}, TLV_ERR_INVALID_VALUE);
        check(tag_byte, {0x81}, TLV_ERR_INVALID_VALUE);
    }
}

TEST(Unit_Tlv_DerValues, Real) {
    check(0x09, {}, TLV_OK);
    check(0x09, {0x40}, TLV_OK);
    check(0x09, {0x41}, TLV_OK);
    check(0x09, {0x42}, TLV_OK);
    check(0x09, {0x43}, TLV_OK);
    check(0x09, {0x80, 0x00, 0x01}, TLV_OK);
    check(0x09, {0x80, 0xFF, 0x01}, TLV_OK);
    check(0x09, {0x80, 0x00, 0x03}, TLV_OK);
    check(0x09, {0x44}, TLV_ERR_INVALID_VALUE);
    check(0x09, {0x01, 0x31}, TLV_ERR_INVALID_VALUE);
    check(0x09, {0x40, 0x00}, TLV_ERR_INVALID_VALUE);
    check(0x09, {0xB0, 0x00, 0x01}, TLV_ERR_INVALID_VALUE);
    check(0x09, {0x84, 0x00, 0x01}, TLV_ERR_INVALID_VALUE);
    check(0x09, {0x83, 0x00, 0x01}, TLV_ERR_INVALID_VALUE);
    check(0x09, {0x80, 0x00, 0x02}, TLV_ERR_INVALID_VALUE);
    check(0x09, {0x80, 0x00, 0x00}, TLV_ERR_INVALID_VALUE);
    check(0x09, {0x80, 0x00, 0x00, 0x01}, TLV_ERR_INVALID_VALUE);
}

TEST(Unit_Tlv_DerValues, Utf8String) {
    check(0x0C, {}, TLV_OK);
    check(0x0C, {'A', 'z'}, TLV_OK);
    check(0x0C, {0xC2, 0xA9}, TLV_OK);
    check(0x0C, {0xE2, 0x82, 0xAC}, TLV_OK);
    check(0x0C, {0xF0, 0x9F, 0x92, 0xA9}, TLV_OK);
    check(0x0C, {0xC0, 0x80}, TLV_ERR_INVALID_VALUE);
    check(0x0C, {0xED, 0xA0, 0x80}, TLV_ERR_INVALID_VALUE);
    check(0x0C, {0xC2}, TLV_ERR_INVALID_VALUE);
    check(0x0C, {0xF4, 0x90, 0x80, 0x80}, TLV_ERR_INVALID_VALUE);
}

TEST(Unit_Tlv_DerValues, RestrictedCharacterRepertoires) {
    check(0x12, {'0', '9', ' '}, TLV_OK);
    check(0x12, {'A'}, TLV_ERR_INVALID_VALUE);
    check(0x13, {'A', 'z', '0', ' ', '\'', '(', ')', '+', ',', '-', '.', '/', ':', '=', '?'},
          TLV_OK);
    check(0x13, {'_'}, TLV_ERR_INVALID_VALUE);
    check(0x16, {0x00, 0x7F}, TLV_OK);
    check(0x16, {0x80}, TLV_ERR_INVALID_VALUE);
    check(0x1A, {0x20, 0x7E}, TLV_OK);
    check(0x1A, {0x1F}, TLV_ERR_INVALID_VALUE);
    check(0x1A, {0x7F}, TLV_ERR_INVALID_VALUE);
}

TEST(Unit_Tlv_DerValues, UniversalAndBmpStrings) {
    check(0x1C, {0, 0, 0, 'A'}, TLV_OK);
    check(0x1C, {0, 0, 0, 0}, TLV_OK);
    check(0x1C, {0, 0, 0}, TLV_ERR_INVALID_VALUE);
    check(0x1C, {0, 0x11, 0, 0}, TLV_ERR_INVALID_VALUE);
    check(0x1C, {0, 0, 0xD8, 0x00}, TLV_ERR_INVALID_VALUE);
    check(0x1E, {0, 'A'}, TLV_OK);
    check(0x1E, {0}, TLV_ERR_INVALID_VALUE);
    check(0x1E, {0xD8, 0x00}, TLV_ERR_INVALID_VALUE);
}

TEST(Unit_Tlv_DerValues, UtcTime) {
    check(0x17, {'2', '5', '0', '1', '0', '2', '1', '2', '0', '0', '0', '0', 'Z'}, TLV_OK);
    check(0x17, {'2', '5', '0', '1', '0', '2', '1', '2', '0', '0', '0', '0'},
          TLV_ERR_INVALID_VALUE);
    check(0x17, {'2', '5', '1', '3', '0', '2', '1', '2', '0', '0', '0', '0', 'Z'},
          TLV_ERR_INVALID_VALUE);
    check(0x17, {'2', '5', '0', '1', '0', '2', '1', '2', '0', '0', '0', '0', '+'},
          TLV_ERR_INVALID_VALUE);
}

TEST(Unit_Tlv_DerValues, GeneralizedTime) {
    const std::vector<uint8_t> base = {'2', '0', '2', '5', '0', '1', '0',
                                       '2', '1', '2', '0', '0', '0', '0'};
    auto                       with = [&](std::vector<uint8_t> suffix) {
        std::vector<uint8_t> full = base;
        full.insert(full.end(), suffix.begin(), suffix.end());
        return full;
    };
    check(0x18, with({'Z'}), TLV_OK);
    check(0x18, with({'.', '5', 'Z'}), TLV_OK);
    check(0x18, with({'.', '1', '2', '5', 'Z'}), TLV_OK);
    check(0x18, with({}), TLV_ERR_INVALID_VALUE);
    check(0x18, with({'+', '0', '1', '0', '0'}), TLV_ERR_INVALID_VALUE);
    check(0x18, with({'.', '5', '0', 'Z'}), TLV_ERR_INVALID_VALUE);
    check(0x18, with({'.', 'Z'}), TLV_ERR_INVALID_VALUE);
}

TEST(Unit_Tlv_DerValues, UnconstrainedLegacyStrings) {
    /* ObjectDescriptor (7), TeletexString (20), VideotexString (21),
     * GraphicString (25) and GeneralString (27) accept any byte sequence,
     * exactly like OCTET STRING (4). */
    for (uint64_t number : {7, 20, 21, 25, 27}) {
        check_number(number, {}, TLV_OK);
        check_number(number, {0x00, 0xFF, 0x7F}, TLV_OK);
    }
}

TEST(Unit_Tlv_DerValues, GenericTime) {
    check_number(14, {'1', '5', ':', '2', '7', ':', '3', '5'}, TLV_OK);
    check_number(14, {}, TLV_ERR_INVALID_VALUE);
    check_number(14, {0x1F}, TLV_ERR_INVALID_VALUE);
}

TEST(Unit_Tlv_DerValues, Date) {
    check_number(31, {'2', '0', '1', '2', '1', '2', '2', '1'}, TLV_OK);
    check_number(31, {'2', '0', '1', '2', '1', '3', '2', '1'}, TLV_ERR_INVALID_VALUE);
    check_number(31, {'2', '0', '1', '2', '1', '2', '2'}, TLV_ERR_INVALID_VALUE);
}

TEST(Unit_Tlv_DerValues, TimeOfDay) {
    check_number(32, {'0', '6', '3', '0', '0', '0'}, TLV_OK);
    check_number(32, {'2', '4', '0', '0', '0', '0'}, TLV_ERR_INVALID_VALUE);
}

TEST(Unit_Tlv_DerValues, DateTime) {
    check_number(33, {'1', '9', '5', '1', '1', '0', '1', '4', '1', '5', '3', '0', '0', '0'},
                 TLV_OK);
    check_number(33, {'1', '9', '5', '1'}, TLV_ERR_INVALID_VALUE);
}

TEST(Unit_Tlv_DerValues, Duration) {
    check_number(
        34,
        {'2', 'Y', '1', '0', 'M', '1', '5', 'D', 'T', '1', '0', 'H', '2', '0', 'M', '3', '0', 'S'},
        TLV_OK);
    check_number(34, {}, TLV_ERR_INVALID_VALUE);
    check_number(34, {'P', '1', 'Y'}, TLV_ERR_INVALID_VALUE);
}

TEST(Unit_Tlv_DerValues, OidIriAndRelativeOidIri) {
    check_number(35, {'/', 'a', '/', 'b'}, TLV_OK);
    check_number(35, {'a', '/', 'b'}, TLV_ERR_INVALID_VALUE);
    check_number(36, {'a', '/', 'b'}, TLV_OK);
    check_number(36, {'/', 'a'}, TLV_ERR_INVALID_VALUE);
}

TEST(Unit_Tlv_DerValues, UnsupportedTypesAreExplicitInStrictMode) {
    /* Every primitive-capable universal number through 36 now has an
     * implemented rule (0 and 15 are reserved and rejected earlier, at tag
     * validation, and 8/11/16/17/29 must be constructed, so strict mode never
     * reaches value validation for them); tag number 37 is beyond that
     * documented range and needs the high-tag-number form, so it is built
     * directly rather than through the single-byte-tag wrap() helper. */
    tlv_tag_t tag{};
    uint8_t   storage[TLV_ASN1_TAG_MAX_SIZE];
    ASSERT_EQ(TLV_OK, tlv_der_tag_make(TLV_ASN1_UNIVERSAL, 0, 37, storage, &tag));
    size_t required = 0, written = 0;
    ASSERT_EQ(TLV_OK, tlv_der_write(nullptr, 0, tag, nullptr, 0, nullptr, &required, nullptr));
    std::vector<uint8_t> data(required);
    ASSERT_EQ(TLV_OK,
              tlv_der_write(data.data(), data.size(), tag, nullptr, 0, nullptr, &written, nullptr));
    tlv_view_t view{};
    size_t     consumed = 0;
    EXPECT_EQ(TLV_ERR_UNSUPPORTED_TYPE,
              tlv_der_read_strict(data.data(), data.size(), nullptr, &view, &consumed, nullptr));
}

TEST(Unit_Tlv_DerValues, NonUniversalClassesAreUnaffected) {
    for (uint8_t tag_byte :
         {0x81 /* context-specific, primitive */, 0xC1 /* private, primitive */}) {
        const std::vector<uint8_t> data = wrap(tag_byte, {0x02});
        tlv_view_t                 view{};
        size_t                     consumed = 0;
        EXPECT_EQ(TLV_OK, tlv_der_read_strict(data.data(), data.size(), nullptr, &view, &consumed,
                                              nullptr));
    }
    /* Constructed, non-UNIVERSAL: content must still be a valid nested DER-TLV
     * element, but its bytes are never passed to universal value validation. */
    const std::vector<uint8_t> data = wrap(0xA1 /* context-specific, constructed */, {0x05, 0x00});
    tlv_view_t                 view{};
    size_t                     consumed = 0;
    EXPECT_EQ(TLV_OK,
              tlv_der_read_strict(data.data(), data.size(), nullptr, &view, &consumed, nullptr));
}

TEST(Unit_Tlv_DerValues, NestedValueReportsOffsetOfOffendingElement) {
    const uint8_t data[] = {0x30, 6, 0x02, 1, 0, 0x01, 1, 1};
    tlv_view_t    view{};
    size_t        consumed = 0, offset = 99;
    EXPECT_EQ(TLV_ERR_INVALID_VALUE,
              tlv_der_read_strict(data, sizeof(data), nullptr, &view, &consumed, &offset));
    EXPECT_EQ(7u, offset);
}

TEST(Unit_Tlv_DerValues, WalkStrictVisitsAndReportsInvalidContent) {
    const uint8_t data[] = {0x01, 1, 0x02};
    size_t        offset = 99;
    EXPECT_EQ(TLV_OK, tlv_der_walk(data, sizeof(data), nullptr, nullptr, nullptr, nullptr));
    EXPECT_EQ(TLV_ERR_INVALID_VALUE,
              tlv_der_walk_strict(data, sizeof(data), nullptr, nullptr, nullptr, &offset));
    EXPECT_EQ(2u, offset);
}

TEST(Unit_Tlv_DerValues, WriteStrictLeavesOutputAndWrittenUnchangedOnFailure) {
    const tlv_tag_t tag = TLV_TAG(0x01);
    const uint8_t   bad_value[] = {0x02};
    uint8_t         output[8];
    std::fill(std::begin(output), std::end(output), 0xEE);
    size_t written = 99, offset = 0, required = 99;
    EXPECT_EQ(TLV_ERR_INVALID_VALUE,
              tlv_der_write_strict(output, sizeof(output), tag, bad_value, sizeof(bad_value),
                                   nullptr, &written, &offset));
    EXPECT_EQ(99u, written);
    EXPECT_EQ(2u, offset); /* value start: 1 tag byte + 1 length byte */
    for (auto byte : output) EXPECT_EQ(0xEE, byte);
    EXPECT_EQ(TLV_ERR_INVALID_VALUE,
              tlv_der_write_strict(nullptr, 0, tag, bad_value, sizeof(bad_value), nullptr,
                                   &required, &offset));
    EXPECT_EQ(99u, required);
    /* A valid BOOLEAN still writes successfully in strict mode. */
    const uint8_t good_value[] = {0xFF};
    EXPECT_EQ(TLV_OK, tlv_der_write_strict(output, sizeof(output), tag, good_value,
                                           sizeof(good_value), nullptr, &written, nullptr));
    EXPECT_EQ(3u, written);
    EXPECT_EQ(0x01, output[0]);
    EXPECT_EQ(0x01, output[1]);
    EXPECT_EQ(0xFF, output[2]);
}
