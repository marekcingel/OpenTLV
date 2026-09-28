#include "tlv/codec/ipv4.h"
#include "tlv/codec/values.h"
#include <gtest/gtest.h>
#include <cstring>
#include <limits>

namespace {
template <typename T>
void check_fixed(const tlv_codec_t* codec, T input, const uint8_t* wire, size_t length) {
    uint8_t output[8] = {};
    T       decoded{};
    size_t  written = 99;
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_decode(codec, wire, length, &decoded, sizeof(decoded)));
    EXPECT_EQ(0, std::memcmp(&input, &decoded, sizeof(input)));
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_encode(codec, &input, sizeof(input), nullptr, 0, &written));
    EXPECT_EQ(length, written);
    ASSERT_EQ(TLV_CODEC_OK,
              tlv_codec_encode(codec, &decoded, sizeof(decoded), output, length, &written));
    EXPECT_EQ(length, written);
    EXPECT_EQ(0, std::memcmp(wire, output, length));
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_decode(codec, wire, length - 1, &decoded, sizeof(decoded)));
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_decode(codec, output, length + 1, &decoded, sizeof(decoded)));
    EXPECT_EQ(TLV_CODEC_ERR_BUFFER_TOO_SHORT,
              tlv_codec_decode(codec, wire, length, &decoded, sizeof(decoded) - 1));
    EXPECT_EQ(TLV_CODEC_ERR_BUFFER_TOO_SHORT,
              tlv_codec_encode(codec, &input, sizeof(input), output, length - 1, &written));
    EXPECT_EQ(0u, written);
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_encode(codec, &input, sizeof(input) - 1, nullptr, 0, &written));
    EXPECT_EQ(0u, written);
    EXPECT_EQ(TLV_CODEC_ERR_NULL_ARG,
              tlv_codec_decode(codec, nullptr, length, &decoded, sizeof(decoded)));
    EXPECT_EQ(TLV_CODEC_ERR_NULL_ARG,
              tlv_codec_encode(codec, &input, sizeof(input), nullptr, 1, &written));
}
} // namespace

TEST(Unit_Tlv_ValueCodecs, FixedValuesAndBounds) {
    const uint8_t u8[] = {0xFF};
    const uint8_t u16[] = {0x12, 0xAB};
    const uint8_t u32[] = {0x89, 0xAB, 0xCD, 0xEF};
    const uint8_t ip[] = {192, 0, 2, 1};
    check_fixed(&tlv_codec_uint8, uint8_t{255}, u8, sizeof(u8));
    check_fixed(&tlv_codec_uint16_be, uint16_t{0x12AB}, u16, sizeof(u16));
    check_fixed(&tlv_codec_uint32_be, uint32_t{0x89ABCDEF}, u32, sizeof(u32));
    check_fixed(&tlv_codec_ipv4, tlv_ipv4_t{{192, 0, 2, 1}}, ip, sizeof(ip));
    const uint8_t zero[4] = {};
    const uint8_t maximum[4] = {255, 255, 255, 255};
    check_fixed(&tlv_codec_uint8, uint8_t{0}, zero, 1);
    check_fixed(&tlv_codec_uint16_be, uint16_t{0}, zero, 2);
    check_fixed(&tlv_codec_uint32_be, uint32_t{0}, zero, 4);
    check_fixed(&tlv_codec_uint16_be, uint16_t{UINT16_MAX}, maximum, 2);
    check_fixed(&tlv_codec_uint32_be, uint32_t{UINT32_MAX}, maximum, 4);
}

TEST(Unit_Tlv_ValueCodecs, BytesBorrowAndPreserveEveryOctet) {
    const uint8_t wire[] = {1, 0, 255, 1, 224};
    tlv_value_t   value{};
    ASSERT_EQ(TLV_CODEC_OK,
              tlv_codec_decode(&tlv_codec_bytes, wire, sizeof(wire), &value, sizeof(value)));
    EXPECT_EQ(wire, value.data);
    EXPECT_EQ(sizeof(wire), value.size);
    uint8_t output[sizeof(wire)] = {};
    size_t  written = 0;
    ASSERT_EQ(TLV_CODEC_OK,
              tlv_codec_encode(&tlv_codec_bytes, &value, sizeof(value), nullptr, 0, &written));
    EXPECT_EQ(sizeof(wire), written);
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_encode(&tlv_codec_bytes, &value, sizeof(value), output,
                                             sizeof(output), &written));
    EXPECT_EQ(0, std::memcmp(wire, output, sizeof(wire)));
    EXPECT_EQ(TLV_CODEC_ERR_BUFFER_TOO_SHORT,
              tlv_codec_encode(&tlv_codec_bytes, &value, sizeof(value), output, sizeof(output) - 1,
                               &written));
    EXPECT_EQ(0u, written);
    EXPECT_EQ(TLV_CODEC_ERR_BUFFER_TOO_SHORT,
              tlv_codec_decode(&tlv_codec_bytes, wire, sizeof(wire), &value, sizeof(value) - 1));
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_encode(&tlv_codec_bytes, &value, sizeof(value) - 1, nullptr, 0, &written));
    value = {nullptr, 1};
    EXPECT_EQ(TLV_CODEC_ERR_NULL_ARG,
              tlv_codec_encode(&tlv_codec_bytes, &value, sizeof(value), nullptr, 0, &written));
    EXPECT_EQ(0u, written);
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_decode(&tlv_codec_bytes, nullptr, 0, &value, sizeof(value)));
    EXPECT_EQ(nullptr, value.data);
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_encode(&tlv_codec_bytes, &value, sizeof(value), output,
                                             sizeof(output), &written));
    EXPECT_EQ(0u, written);
}

TEST(Unit_Tlv_ValueCodecs, Ipv4ListsValidateBorrowAndIndex) {
    const uint8_t   wire[] = {192, 0, 2, 1, 203, 0, 113, 9, 192, 0, 2, 1};
    tlv_ipv4_list_t list{};
    ASSERT_EQ(TLV_CODEC_OK,
              tlv_codec_decode(&tlv_codec_ipv4_list, wire, sizeof(wire), &list, sizeof(list)));
    EXPECT_EQ(wire, list.raw.data);
    uint8_t output[sizeof(wire)] = {};
    size_t  written = 0;
    ASSERT_EQ(TLV_CODEC_OK,
              tlv_codec_encode(&tlv_codec_ipv4_list, &list, sizeof(list), nullptr, 0, &written));
    EXPECT_EQ(sizeof(wire), written);
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_encode(&tlv_codec_ipv4_list, &list, sizeof(list), output,
                                             sizeof(output), &written));
    EXPECT_EQ(0, std::memcmp(wire, output, sizeof(wire)));
    tlv_ipv4_t ip{};
    for (size_t i = 0; i < 3; ++i) {
        ASSERT_EQ(TLV_CODEC_OK, tlv_ipv4_list_at(&list, i, &ip));
        EXPECT_EQ(0, std::memcmp(wire + 4 * i, ip.bytes, 4));
    }
    const tlv_ipv4_t saved = ip;
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE, tlv_ipv4_list_at(&list, 3, &ip));
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE, tlv_ipv4_list_at(&list, SIZE_MAX, &ip));
    EXPECT_EQ(0, std::memcmp(ip.bytes, saved.bytes, 4));
    EXPECT_EQ(TLV_CODEC_ERR_NULL_ARG, tlv_ipv4_list_at(nullptr, 0, &ip));
    EXPECT_EQ(TLV_CODEC_ERR_NULL_ARG, tlv_ipv4_list_at(&list, 0, nullptr));
    EXPECT_EQ(TLV_CODEC_ERR_BUFFER_TOO_SHORT,
              tlv_codec_encode(&tlv_codec_ipv4_list, &list, sizeof(list), output,
                               sizeof(output) - 1, &written));
    EXPECT_EQ(0u, written);
    EXPECT_EQ(TLV_CODEC_ERR_BUFFER_TOO_SHORT,
              tlv_codec_decode(&tlv_codec_ipv4_list, wire, sizeof(wire), &list, sizeof(list) - 1));
    EXPECT_EQ(
        TLV_CODEC_ERR_INVALID_VALUE,
        tlv_codec_encode(&tlv_codec_ipv4_list, &list, sizeof(list) - 1, nullptr, 0, &written));
    for (size_t size = 1; size < 4; ++size) {
        EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
                  tlv_codec_decode(&tlv_codec_ipv4_list, wire, size, &list, sizeof(list)));
        list.raw = {wire, size};
        EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE, tlv_ipv4_list_at(&list, 0, &ip));
        EXPECT_EQ(
            TLV_CODEC_ERR_INVALID_VALUE,
            tlv_codec_encode(&tlv_codec_ipv4_list, &list, sizeof(list), nullptr, 0, &written));
        EXPECT_EQ(0u, written);
    }
    list.raw = {nullptr, 4};
    EXPECT_EQ(TLV_CODEC_ERR_NULL_ARG, tlv_ipv4_list_at(&list, 0, &ip));
    EXPECT_EQ(TLV_CODEC_ERR_NULL_ARG,
              tlv_codec_encode(&tlv_codec_ipv4_list, &list, sizeof(list), nullptr, 0, &written));
    ASSERT_EQ(TLV_CODEC_OK,
              tlv_codec_decode(&tlv_codec_ipv4_list, nullptr, 0, &list, sizeof(list)));
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE, tlv_ipv4_list_at(&list, 0, &ip));
    ASSERT_EQ(TLV_CODEC_OK,
              tlv_codec_encode(&tlv_codec_ipv4_list, &list, sizeof(list), nullptr, 0, &written));
    EXPECT_EQ(0u, written);
}

TEST(Unit_Tlv_ValueCodecs, NonNativeViewsFailBeforeAccess) {
    if (sizeof(size_t) >= sizeof(tlv_size_t)) return;
    const uint8_t    byte = 0;
    const tlv_size_t too_large = static_cast<tlv_size_t>(SIZE_MAX) + 1;
    tlv_value_t      bytes{&byte, too_large};
    tlv_ipv4_list_t  list{bytes};
    tlv_ipv4_t       ip{};
    size_t           written = 99;
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_encode(&tlv_codec_bytes, &bytes, sizeof(bytes), nullptr, 0, &written));
    EXPECT_EQ(0u, written);
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_encode(&tlv_codec_ipv4_list, &list, sizeof(list), nullptr, 0, &written));
    EXPECT_EQ(0u, written);
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE, tlv_ipv4_list_at(&list, 0, &ip));
}
