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

TEST(Unit_Tlv_Asn1Codec, RestrictedCharacterStrings) {
    struct Case {
        const tlv_codec_t*   codec;
        std::vector<uint8_t> valid;
        std::vector<uint8_t> invalid;
    };
    const std::vector<Case> cases = {
        {&tlv_asn1_codec_utf8_string, {'a', 0xC2, 0xA9, 'z'}, {0xC0, 0x80}},
        {&tlv_asn1_codec_numeric_string, {'1', ' ', '2'}, {'a'}},
        {&tlv_asn1_codec_printable_string, {'A', 'z', '0', ' ', '\''}, {'_'}},
        {&tlv_asn1_codec_ia5_string, {0x00, 0x7F, 'x'}, {0x80}},
        {&tlv_asn1_codec_visible_string, {' ', '~', 'M'}, {0x1F}},
    };
    for (const Case& c : cases) {
        tlv_asn1_string_t decoded{};
        ASSERT_EQ(TLV_CODEC_OK, tlv_codec_decode(c.codec, c.valid.data(), c.valid.size(), &decoded,
                                                 sizeof(decoded)));
        ASSERT_EQ(c.valid.size(), decoded.length);
        EXPECT_EQ(0, std::memcmp(decoded.data, c.valid.data(), c.valid.size()));

        uint8_t encoded[16] = {};
        size_t  written = 0;
        ASSERT_EQ(TLV_CODEC_OK, tlv_codec_encode(c.codec, &decoded, sizeof(decoded), encoded,
                                                 sizeof(encoded), &written));
        EXPECT_EQ(c.valid.size(), written);
        EXPECT_EQ(0, std::memcmp(encoded, c.valid.data(), written));

        tlv_asn1_string_t placeholder{};
        EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
                  tlv_codec_decode(c.codec, c.invalid.data(), c.invalid.size(), &placeholder,
                                   sizeof(placeholder)));

        const tlv_asn1_string_t bad_encode = {c.invalid.data(), c.invalid.size()};
        size_t                  count = 99;
        EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
                  tlv_codec_encode(c.codec, &bad_encode, sizeof(bad_encode), encoded,
                                   sizeof(encoded), &count));

        uint8_t small[1] = {};
        EXPECT_EQ(
            TLV_CODEC_ERR_BUFFER_TOO_SHORT,
            tlv_codec_encode(c.codec, &decoded, sizeof(decoded), small, sizeof(small), &count));
    }

    tlv_asn1_string_t empty_decoded{};
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_decode(&tlv_asn1_codec_utf8_string, nullptr, 0,
                                             &empty_decoded, sizeof(empty_decoded)));
    EXPECT_EQ(0u, empty_decoded.length);
    EXPECT_EQ(nullptr, empty_decoded.data);
}

TEST(Unit_Tlv_Asn1Codec, BmpString) {
    const std::vector<uint8_t> raw = {0x00, 0x48, 0x00, 0x69}; /* "Hi" */
    tlv_asn1_bmp_string_t      decoded{};
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_decode(&tlv_asn1_codec_bmp_string, raw.data(), raw.size(),
                                             &decoded, sizeof(decoded)));
    ASSERT_EQ(2u, decoded.length);
    ASSERT_NE(nullptr, decoded.data);
    EXPECT_EQ(0, std::memcmp(decoded.data, raw.data(), raw.size()));

    uint8_t encoded[8] = {};
    size_t  written = 0;
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_encode(&tlv_asn1_codec_bmp_string, &decoded, sizeof(decoded),
                                             encoded, sizeof(encoded), &written));
    EXPECT_EQ(raw.size(), written);
    EXPECT_EQ(0, std::memcmp(encoded, raw.data(), written));

    tlv_asn1_bmp_string_t empty_decoded{};
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_decode(&tlv_asn1_codec_bmp_string, nullptr, 0, &empty_decoded,
                                             sizeof(empty_decoded)));
    EXPECT_EQ(0u, empty_decoded.length);
    EXPECT_EQ(nullptr, empty_decoded.data);

    tlv_asn1_bmp_string_t placeholder{};
    const uint8_t         odd_length[] = {0x00};
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_decode(&tlv_asn1_codec_bmp_string, odd_length, sizeof(odd_length),
                               &placeholder, sizeof(placeholder)));
    const uint8_t surrogate[] = {0xD8, 0x00};
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_decode(&tlv_asn1_codec_bmp_string, surrogate, sizeof(surrogate),
                               &placeholder, sizeof(placeholder)));

    const tlv_asn1_bmp_string_t bad_encode = {surrogate, 1};
    size_t                      count = 99;
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_encode(&tlv_asn1_codec_bmp_string, &bad_encode, sizeof(bad_encode), encoded,
                               sizeof(encoded), &count));

    uint8_t small[1] = {};
    EXPECT_EQ(TLV_CODEC_ERR_BUFFER_TOO_SHORT,
              tlv_codec_encode(&tlv_asn1_codec_bmp_string, &decoded, sizeof(decoded), small,
                               sizeof(small), &count));
}

TEST(Unit_Tlv_Asn1Codec, UniversalString) {
    const std::vector<uint8_t>  raw = {0x00, 0x00, 0x00, 0x41}; /* 'A' */
    tlv_asn1_universal_string_t decoded{};
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_decode(&tlv_asn1_codec_universal_string, raw.data(),
                                             raw.size(), &decoded, sizeof(decoded)));
    ASSERT_EQ(1u, decoded.length);
    ASSERT_NE(nullptr, decoded.data);
    EXPECT_EQ(0, std::memcmp(decoded.data, raw.data(), raw.size()));

    uint8_t encoded[8] = {};
    size_t  written = 0;
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_encode(&tlv_asn1_codec_universal_string, &decoded,
                                             sizeof(decoded), encoded, sizeof(encoded), &written));
    EXPECT_EQ(raw.size(), written);
    EXPECT_EQ(0, std::memcmp(encoded, raw.data(), written));

    tlv_asn1_universal_string_t empty_decoded{};
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_decode(&tlv_asn1_codec_universal_string, nullptr, 0,
                                             &empty_decoded, sizeof(empty_decoded)));
    EXPECT_EQ(0u, empty_decoded.length);
    EXPECT_EQ(nullptr, empty_decoded.data);

    tlv_asn1_universal_string_t placeholder{};
    const uint8_t               truncated[] = {0x00, 0x00, 0x00};
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_decode(&tlv_asn1_codec_universal_string, truncated, sizeof(truncated),
                               &placeholder, sizeof(placeholder)));
    const uint8_t surrogate[] = {0x00, 0x00, 0xD8, 0x00};
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_decode(&tlv_asn1_codec_universal_string, surrogate, sizeof(surrogate),
                               &placeholder, sizeof(placeholder)));
    const uint8_t too_large[] = {0x00, 0x11, 0x00, 0x00};
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_decode(&tlv_asn1_codec_universal_string, too_large, sizeof(too_large),
                               &placeholder, sizeof(placeholder)));

    const tlv_asn1_universal_string_t bad_encode = {surrogate, 1};
    size_t                            count = 99;
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_encode(&tlv_asn1_codec_universal_string, &bad_encode, sizeof(bad_encode),
                               encoded, sizeof(encoded), &count));

    uint8_t small[1] = {};
    EXPECT_EQ(TLV_CODEC_ERR_BUFFER_TOO_SHORT,
              tlv_codec_encode(&tlv_asn1_codec_universal_string, &decoded, sizeof(decoded), small,
                               sizeof(small), &count));
}

TEST(Unit_Tlv_Asn1Codec, UtcTime) {
    /* YYMMDDHHMMSSZ, 1999-12-31 23:59:59. */
    const std::vector<uint8_t> raw = {'9', '9', '1', '2', '3', '1', '2',
                                      '3', '5', '9', '5', '9', 'Z'};
    tlv_asn1_utc_time_t        decoded{};
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_decode(&tlv_asn1_codec_utc_time, raw.data(), raw.size(),
                                             &decoded, sizeof(decoded)));
    EXPECT_EQ(1999, decoded.year);
    EXPECT_EQ(12, decoded.month);
    EXPECT_EQ(31, decoded.day);
    EXPECT_EQ(23, decoded.hour);
    EXPECT_EQ(59, decoded.minute);
    EXPECT_EQ(59, decoded.second);

    uint8_t encoded[16] = {};
    size_t  written = 0;
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_encode(&tlv_asn1_codec_utc_time, &decoded, sizeof(decoded),
                                             encoded, sizeof(encoded), &written));
    EXPECT_EQ(raw.size(), written);
    EXPECT_EQ(0, std::memcmp(encoded, raw.data(), written));

    /* YY 00 maps to the year 2000, not 1900. */
    const std::vector<uint8_t> raw2000 = {'0', '0', '0', '1', '0', '1', '0',
                                          '0', '0', '0', '0', '0', 'Z'};
    tlv_asn1_utc_time_t        decoded2000{};
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_decode(&tlv_asn1_codec_utc_time, raw2000.data(),
                                             raw2000.size(), &decoded2000, sizeof(decoded2000)));
    EXPECT_EQ(2000, decoded2000.year);

    tlv_asn1_utc_time_t placeholder{};
    const uint8_t bad_month[] = {'9', '9', '1', '3', '0', '1', '0', '0', '0', '0', '0', '0', 'Z'};
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_decode(&tlv_asn1_codec_utc_time, bad_month, sizeof(bad_month), &placeholder,
                               sizeof(placeholder)));

    tlv_asn1_utc_time_t out_of_range = decoded;
    out_of_range.year = 2050; /* no two-digit representation under the codec's convention */
    size_t count = 99;
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_encode(&tlv_asn1_codec_utc_time, &out_of_range, sizeof(out_of_range),
                               encoded, sizeof(encoded), &count));

    tlv_asn1_utc_time_t bad_field = decoded;
    bad_field.month = 13;
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_encode(&tlv_asn1_codec_utc_time, &bad_field, sizeof(bad_field), encoded,
                               sizeof(encoded), &count));

    uint8_t small[1] = {};
    EXPECT_EQ(TLV_CODEC_ERR_BUFFER_TOO_SHORT,
              tlv_codec_encode(&tlv_asn1_codec_utc_time, &decoded, sizeof(decoded), small,
                               sizeof(small), &count));
}

TEST(Unit_Tlv_Asn1Codec, GeneralizedTime) {
    const std::vector<uint8_t>  raw = {'2', '0', '2', '5', '0', '9', '2', '4',
                                       '1', '2', '3', '0', '4', '5', 'Z'};
    tlv_asn1_generalized_time_t decoded{};
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_decode(&tlv_asn1_codec_generalized_time, raw.data(),
                                             raw.size(), &decoded, sizeof(decoded)));
    EXPECT_EQ(2025, decoded.year);
    EXPECT_EQ(9, decoded.month);
    EXPECT_EQ(24, decoded.day);
    EXPECT_EQ(12, decoded.hour);
    EXPECT_EQ(30, decoded.minute);
    EXPECT_EQ(45, decoded.second);
    EXPECT_EQ(nullptr, decoded.fraction_digits);
    EXPECT_EQ(0u, decoded.fraction_digits_length);

    uint8_t encoded[32] = {};
    size_t  written = 0;
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_encode(&tlv_asn1_codec_generalized_time, &decoded,
                                             sizeof(decoded), encoded, sizeof(encoded), &written));
    EXPECT_EQ(raw.size(), written);
    EXPECT_EQ(0, std::memcmp(encoded, raw.data(), written));

    const std::vector<uint8_t>  raw_frac = {'2', '0', '2', '5', '0', '9', '2', '4', '1', '2',
                                            '3', '0', '4', '5', '.', '1', '2', '5', 'Z'};
    tlv_asn1_generalized_time_t decoded_frac{};
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_decode(&tlv_asn1_codec_generalized_time, raw_frac.data(),
                                             raw_frac.size(), &decoded_frac, sizeof(decoded_frac)));
    ASSERT_NE(nullptr, decoded_frac.fraction_digits);
    ASSERT_EQ(3u, decoded_frac.fraction_digits_length);
    EXPECT_EQ(0, std::memcmp(decoded_frac.fraction_digits, "125", 3));

    written = 0;
    ASSERT_EQ(TLV_CODEC_OK,
              tlv_codec_encode(&tlv_asn1_codec_generalized_time, &decoded_frac,
                               sizeof(decoded_frac), encoded, sizeof(encoded), &written));
    EXPECT_EQ(raw_frac.size(), written);
    EXPECT_EQ(0, std::memcmp(encoded, raw_frac.data(), written));

    tlv_asn1_generalized_time_t placeholder{};
    const uint8_t too_short[] = {'2', '0', '2', '5', '0', '9', '2', '4', '1', '2', '3', '0', 'Z'};
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_decode(&tlv_asn1_codec_generalized_time, too_short, sizeof(too_short),
                               &placeholder, sizeof(placeholder)));
    const uint8_t trailing_zero_fraction[] = {'2', '0', '2', '5', '0', '9', '2', '4', '1',
                                              '2', '3', '0', '4', '5', '.', '1', '0', 'Z'};
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_decode(&tlv_asn1_codec_generalized_time, trailing_zero_fraction,
                               sizeof(trailing_zero_fraction), &placeholder, sizeof(placeholder)));

    tlv_asn1_generalized_time_t out_of_range = decoded;
    out_of_range.month = 0;
    size_t count = 99;
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_encode(&tlv_asn1_codec_generalized_time, &out_of_range,
                               sizeof(out_of_range), encoded, sizeof(encoded), &count));

    tlv_asn1_generalized_time_t bad_fraction = decoded;
    const uint8_t               zero_digit[] = {'0'};
    bad_fraction.fraction_digits = zero_digit;
    bad_fraction.fraction_digits_length = 1;
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_encode(&tlv_asn1_codec_generalized_time, &bad_fraction,
                               sizeof(bad_fraction), encoded, sizeof(encoded), &count));

    tlv_asn1_generalized_time_t mismatched = decoded;
    mismatched.fraction_digits_length = 1; /* fraction_digits still NULL */
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_encode(&tlv_asn1_codec_generalized_time, &mismatched, sizeof(mismatched),
                               encoded, sizeof(encoded), &count));

    uint8_t small[1] = {};
    EXPECT_EQ(TLV_CODEC_ERR_BUFFER_TOO_SHORT,
              tlv_codec_encode(&tlv_asn1_codec_generalized_time, &decoded, sizeof(decoded), small,
                               sizeof(small), &count));
}
