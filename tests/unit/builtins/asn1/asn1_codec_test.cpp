#include "tlv/builtins/asn1/asn1_codec.h"
#include <cstdint>
#include <cstring>
#include <gtest/gtest.h>
#include <vector>

namespace {

template <class T>
void check_vector(const tlv_codec_t* codec, const T& expected, std::initializer_list<uint8_t> raw) {
    ASSERT_NE(nullptr, codec);
    const std::vector<uint8_t> bytes(raw);
    T                          decoded{};
    ASSERT_EQ(TLV_CODEC_OK,
              tlv_codec_decode(codec, bytes.data(), bytes.size(), &decoded, sizeof(decoded)));
    EXPECT_EQ(0, std::memcmp(&expected, &decoded, sizeof(T)));
    uint8_t encoded[16] = {};
    size_t  count = 99;
    ASSERT_EQ(TLV_CODEC_OK,
              tlv_codec_encode(codec, &expected, sizeof(expected), nullptr, 0, &count));
    ASSERT_EQ(bytes.size(), count);
    ASSERT_EQ(TLV_CODEC_OK,
              tlv_codec_encode(codec, &decoded, sizeof(decoded), encoded, sizeof(encoded), &count));
    EXPECT_EQ(bytes.size(), count);
    EXPECT_EQ(0, std::memcmp(encoded, bytes.data(), count));
    EXPECT_EQ(TLV_CODEC_ERR_BUFFER_TOO_SHORT,
              tlv_codec_decode(codec, bytes.data(), bytes.size(), &decoded, sizeof(decoded) - 1));
    EXPECT_EQ(TLV_CODEC_ERR_BUFFER_TOO_SHORT, tlv_codec_encode(codec, &expected, sizeof(expected),
                                                               encoded, bytes.size() - 1, &count));
    EXPECT_EQ(0u, count);
}

} // namespace

TEST(Unit_Tlv_Asn1Codec, Boolean) {
    check_vector<bool>(&tlv_asn1_codec_boolean, false, {0x00});
    check_vector<bool>(&tlv_asn1_codec_boolean, true, {0xFF});

    bool          decoded = false;
    const uint8_t non_canonical[] = {0x01};
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_decode(&tlv_asn1_codec_boolean, non_canonical, sizeof(non_canonical),
                               &decoded, sizeof(decoded)));
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_decode(&tlv_asn1_codec_boolean, nullptr, 0, &decoded, sizeof(decoded)));
}

TEST(Unit_Tlv_Asn1Codec, IntegerAndEnumerated) {
    for (const tlv_codec_t* codec : {&tlv_asn1_codec_integer, &tlv_asn1_codec_enumerated}) {
        check_vector<int64_t>(codec, 0, {0x00});
        check_vector<int64_t>(codec, 127, {0x7F});
        check_vector<int64_t>(codec, -1, {0xFF});
        check_vector<int64_t>(codec, 128, {0x00, 0x80});
        check_vector<int64_t>(codec, -129, {0xFF, 0x7F});
        check_vector<int64_t>(codec, INT64_MAX, {0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF});
        check_vector<int64_t>(codec, INT64_MIN, {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});

        int64_t       decoded = 0;
        const uint8_t empty_content[1] = {};
        EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
                  tlv_codec_decode(codec, empty_content, 0, &decoded, sizeof(decoded)));
        const uint8_t redundant_zero[] = {0x00, 0x7F};
        EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
                  tlv_codec_decode(codec, redundant_zero, sizeof(redundant_zero), &decoded,
                                   sizeof(decoded)));
        const uint8_t redundant_ones[] = {0xFF, 0x80};
        EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
                  tlv_codec_decode(codec, redundant_ones, sizeof(redundant_ones), &decoded,
                                   sizeof(decoded)));
        const uint8_t too_wide[] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
                  tlv_codec_decode(codec, too_wide, sizeof(too_wide), &decoded, sizeof(decoded)));
    }
}

TEST(Unit_Tlv_Asn1Codec, BitString) {
    const std::vector<uint8_t> raw = {0x04, 0xF0};
    tlv_asn1_bit_string_t      decoded{};
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_decode(&tlv_asn1_codec_bit_string, raw.data(), raw.size(),
                                             &decoded, sizeof(decoded)));
    EXPECT_EQ(4, decoded.unused_bits);
    ASSERT_EQ(1u, decoded.length);
    ASSERT_NE(nullptr, decoded.data);
    EXPECT_EQ(0xF0, decoded.data[0]);

    uint8_t encoded[8] = {};
    size_t  written = 0;
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_encode(&tlv_asn1_codec_bit_string, &decoded, sizeof(decoded),
                                             encoded, sizeof(encoded), &written));
    EXPECT_EQ(raw.size(), written);
    EXPECT_EQ(0, std::memcmp(encoded, raw.data(), written));

    const std::vector<uint8_t> empty_raw = {0x00};
    tlv_asn1_bit_string_t      empty_decoded{};
    ASSERT_EQ(TLV_CODEC_OK,
              tlv_codec_decode(&tlv_asn1_codec_bit_string, empty_raw.data(), empty_raw.size(),
                               &empty_decoded, sizeof(empty_decoded)));
    EXPECT_EQ(0, empty_decoded.unused_bits);
    EXPECT_EQ(0u, empty_decoded.length);
    EXPECT_EQ(nullptr, empty_decoded.data);

    tlv_asn1_bit_string_t placeholder{};
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE, tlv_codec_decode(&tlv_asn1_codec_bit_string, nullptr, 0,
                                                            &placeholder, sizeof(placeholder)));
    const uint8_t set_padding[] = {0x04, 0xFF};
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_decode(&tlv_asn1_codec_bit_string, set_padding, sizeof(set_padding),
                               &placeholder, sizeof(placeholder)));

    const tlv_asn1_bit_string_t invalid_unused = {9, nullptr, 0};
    size_t                      count = 99;
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_encode(&tlv_asn1_codec_bit_string, &invalid_unused, sizeof(invalid_unused),
                               encoded, sizeof(encoded), &count));

    uint8_t small[1] = {};
    EXPECT_EQ(TLV_CODEC_ERR_BUFFER_TOO_SHORT,
              tlv_codec_encode(&tlv_asn1_codec_bit_string, &decoded, sizeof(decoded), small,
                               sizeof(small), &count));
    EXPECT_EQ(0u, count);
}

TEST(Unit_Tlv_Asn1Codec, OctetString) {
    const std::vector<uint8_t> raw = {0x00, 0xFF, 0x7F};
    tlv_asn1_octet_string_t    decoded{};
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_decode(&tlv_asn1_codec_octet_string, raw.data(), raw.size(),
                                             &decoded, sizeof(decoded)));
    ASSERT_EQ(raw.size(), decoded.length);
    EXPECT_EQ(0, std::memcmp(decoded.data, raw.data(), raw.size()));

    uint8_t encoded[8] = {};
    size_t  written = 0;
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_encode(&tlv_asn1_codec_octet_string, &decoded,
                                             sizeof(decoded), encoded, sizeof(encoded), &written));
    EXPECT_EQ(raw.size(), written);
    EXPECT_EQ(0, std::memcmp(encoded, raw.data(), written));

    tlv_asn1_octet_string_t empty_decoded{};
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_decode(&tlv_asn1_codec_octet_string, nullptr, 0,
                                             &empty_decoded, sizeof(empty_decoded)));
    EXPECT_EQ(0u, empty_decoded.length);
    EXPECT_EQ(nullptr, empty_decoded.data);

    uint8_t small[1] = {};
    size_t  count = 99;
    EXPECT_EQ(TLV_CODEC_ERR_BUFFER_TOO_SHORT,
              tlv_codec_encode(&tlv_asn1_codec_octet_string, &decoded, sizeof(decoded), small,
                               sizeof(small), &count));
    EXPECT_EQ(0u, count);
}

TEST(Unit_Tlv_Asn1Codec, Null) {
    int placeholder = 0;
    EXPECT_EQ(TLV_CODEC_OK, tlv_codec_decode(&tlv_asn1_codec_null, nullptr, 0, &placeholder, 0));
    const uint8_t nonempty[] = {0x00};
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_decode(&tlv_asn1_codec_null, nonempty, sizeof(nonempty), &placeholder, 0));

    size_t written = 99;
    EXPECT_EQ(TLV_CODEC_OK, tlv_codec_encode(&tlv_asn1_codec_null, &placeholder,
                                             sizeof(placeholder), nullptr, 0, &written));
    EXPECT_EQ(0u, written);
    uint8_t buf[1] = {};
    EXPECT_EQ(TLV_CODEC_OK, tlv_codec_encode(&tlv_asn1_codec_null, &placeholder,
                                             sizeof(placeholder), buf, sizeof(buf), &written));
    EXPECT_EQ(0u, written);
}

TEST(Unit_Tlv_Asn1Codec, ObjectIdentifier) {
    const std::vector<uint8_t> raw = {0x2A, 0x03}; /* 1.2.3 */
    tlv_asn1_oid_t             decoded{};
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_decode(&tlv_asn1_codec_oid, raw.data(), raw.size(), &decoded,
                                             sizeof(decoded)));
    ASSERT_EQ(3u, decoded.count);
    EXPECT_EQ(1u, decoded.arcs[0]);
    EXPECT_EQ(2u, decoded.arcs[1]);
    EXPECT_EQ(3u, decoded.arcs[2]);

    uint8_t encoded[8] = {};
    size_t  written = 0;
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_encode(&tlv_asn1_codec_oid, &decoded, sizeof(decoded),
                                             encoded, sizeof(encoded), &written));
    EXPECT_EQ(raw.size(), written);
    EXPECT_EQ(0, std::memcmp(encoded, raw.data(), written));

    /* First subidentifier >= 80: X=2, Y=value-80, unbounded. */
    const std::vector<uint8_t> raw_x2 = {0x81, 0x00};
    tlv_asn1_oid_t             decoded_x2{};
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_decode(&tlv_asn1_codec_oid, raw_x2.data(), raw_x2.size(),
                                             &decoded_x2, sizeof(decoded_x2)));
    ASSERT_EQ(2u, decoded_x2.count);
    EXPECT_EQ(2u, decoded_x2.arcs[0]);
    EXPECT_EQ(48u, decoded_x2.arcs[1]);

    tlv_asn1_oid_t placeholder{};
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_decode(&tlv_asn1_codec_oid, nullptr, 0, &placeholder, sizeof(placeholder)));
    const uint8_t redundant[] = {0x80, 0x01};
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_decode(&tlv_asn1_codec_oid, redundant, sizeof(redundant), &placeholder,
                               sizeof(placeholder)));

    tlv_asn1_oid_t out_of_range{};
    out_of_range.count = 2;
    out_of_range.arcs[0] = 3;
    size_t count = 99;
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_encode(&tlv_asn1_codec_oid, &out_of_range, sizeof(out_of_range), encoded,
                               sizeof(encoded), &count));

    tlv_asn1_oid_t too_short{};
    too_short.count = 1;
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_encode(&tlv_asn1_codec_oid, &too_short, sizeof(too_short), encoded,
                               sizeof(encoded), &count));
}

TEST(Unit_Tlv_Asn1Codec, RelativeOid) {
    const std::vector<uint8_t> raw = {0x2A, 0x03};
    tlv_asn1_oid_t             decoded{};
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_decode(&tlv_asn1_codec_relative_oid, raw.data(), raw.size(),
                                             &decoded, sizeof(decoded)));
    ASSERT_EQ(2u, decoded.count);
    EXPECT_EQ(42u, decoded.arcs[0]);
    EXPECT_EQ(3u, decoded.arcs[1]);

    uint8_t encoded[8] = {};
    size_t  written = 0;
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_encode(&tlv_asn1_codec_relative_oid, &decoded,
                                             sizeof(decoded), encoded, sizeof(encoded), &written));
    EXPECT_EQ(raw.size(), written);
    EXPECT_EQ(0, std::memcmp(encoded, raw.data(), written));

    tlv_asn1_oid_t empty{};
    size_t         count = 99;
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_encode(&tlv_asn1_codec_relative_oid, &empty, sizeof(empty), encoded,
                               sizeof(encoded), &count));
}

TEST(Unit_Tlv_Asn1Codec, OidArcCountLimit) {
    const std::vector<uint8_t> too_many(TLV_ASN1_OID_MAX_ARCS + 1, 0x00);
    tlv_asn1_oid_t             decoded{};
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_decode(&tlv_asn1_codec_relative_oid, too_many.data(), too_many.size(),
                               &decoded, sizeof(decoded)));

    const std::vector<uint8_t> exactly_enough(TLV_ASN1_OID_MAX_ARCS, 0x00);
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_decode(&tlv_asn1_codec_relative_oid, exactly_enough.data(),
                                             exactly_enough.size(), &decoded, sizeof(decoded)));
    EXPECT_EQ(static_cast<size_t>(TLV_ASN1_OID_MAX_ARCS), decoded.count);

    /* OBJECT IDENTIFIER reserves one slot for the combined first subidentifier. */
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_decode(&tlv_asn1_codec_oid, exactly_enough.data(), exactly_enough.size(),
                               &decoded, sizeof(decoded)));
}
