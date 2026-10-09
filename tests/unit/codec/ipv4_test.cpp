// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/codec/ipv4.h"
#include "fixed_value_checks.h"

TEST(Unit_Tlv_Ipv4Codecs, FixedValuesAndBounds) {
    const uint8_t ip[] = {192, 0, 2, 1};
    check_fixed(&tlv_codec_ipv4, tlv_ipv4_t{{192, 0, 2, 1}}, ip, sizeof(ip));
}

TEST(Unit_Tlv_Ipv4Codecs, Ipv4ListsValidateBorrowAndIndex) {
    const uint8_t   wire[] = {192, 0, 2, 1, 203, 0, 113, 9, 192, 0, 2, 1};
    tlv_ipv4_list_t list{};
    ASSERT_EQ(TLV_OK, tlv_codec_decode(&tlv_codec_ipv4_list, wire, sizeof(wire), &list,
                                       sizeof(list), NULL));
    EXPECT_EQ(wire, list.raw.data);
    uint8_t output[sizeof(wire)] = {};
    size_t  written = 0;
    ASSERT_EQ(TLV_OK, tlv_codec_encode(&tlv_codec_ipv4_list, &list, sizeof(list), nullptr, 0,
                                       &written, NULL));
    EXPECT_EQ(sizeof(wire), written);
    ASSERT_EQ(TLV_OK, tlv_codec_encode(&tlv_codec_ipv4_list, &list, sizeof(list), output,
                                       sizeof(output), &written, NULL));
    EXPECT_EQ(0, std::memcmp(wire, output, sizeof(wire)));
    tlv_ipv4_t ip{};
    for (size_t i = 0; i < 3; ++i) {
        ASSERT_EQ(TLV_OK, tlv_ipv4_list_at(&list, i, &ip));
        EXPECT_EQ(0, std::memcmp(wire + 4 * i, ip.bytes, 4));
    }
    const tlv_ipv4_t saved = ip;
    EXPECT_EQ(TLV_ERR_INVALID_VALUE, tlv_ipv4_list_at(&list, 3, &ip));
    EXPECT_EQ(TLV_ERR_INVALID_VALUE, tlv_ipv4_list_at(&list, SIZE_MAX, &ip));
    EXPECT_EQ(0, std::memcmp(ip.bytes, saved.bytes, 4));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_ipv4_list_at(nullptr, 0, &ip));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_ipv4_list_at(&list, 0, nullptr));
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              tlv_codec_encode(&tlv_codec_ipv4_list, &list, sizeof(list), output,
                               sizeof(output) - 1, &written, NULL));
    EXPECT_EQ(0u, written);
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_codec_decode(&tlv_codec_ipv4_list, wire, sizeof(wire),
                                                         &list, sizeof(list) - 1, NULL));
    EXPECT_EQ(TLV_ERR_INVALID_VALUE, tlv_codec_encode(&tlv_codec_ipv4_list, &list, sizeof(list) - 1,
                                                      nullptr, 0, &written, NULL));
    for (size_t size = 1; size < 4; ++size) {
        EXPECT_EQ(TLV_ERR_INVALID_VALUE,
                  tlv_codec_decode(&tlv_codec_ipv4_list, wire, size, &list, sizeof(list), NULL));
        list.raw = {wire, size};
        EXPECT_EQ(TLV_ERR_INVALID_VALUE, tlv_ipv4_list_at(&list, 0, &ip));
        EXPECT_EQ(TLV_ERR_INVALID_VALUE, tlv_codec_encode(&tlv_codec_ipv4_list, &list, sizeof(list),
                                                          nullptr, 0, &written, NULL));
        EXPECT_EQ(0u, written);
    }
    list.raw = {nullptr, 4};
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_ipv4_list_at(&list, 0, &ip));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_codec_encode(&tlv_codec_ipv4_list, &list, sizeof(list), nullptr,
                                                 0, &written, NULL));
    ASSERT_EQ(TLV_OK,
              tlv_codec_decode(&tlv_codec_ipv4_list, nullptr, 0, &list, sizeof(list), NULL));
    EXPECT_EQ(TLV_ERR_INVALID_VALUE, tlv_ipv4_list_at(&list, 0, &ip));
    ASSERT_EQ(TLV_OK, tlv_codec_encode(&tlv_codec_ipv4_list, &list, sizeof(list), nullptr, 0,
                                       &written, NULL));
    EXPECT_EQ(0u, written);
}

TEST(Unit_Tlv_Ipv4Codecs, NonNativeViewsFailBeforeAccess) {
    if (sizeof(size_t) >= sizeof(tlv_size_t)) return;
    const uint8_t    byte = 0;
    const tlv_size_t too_large = static_cast<tlv_size_t>(SIZE_MAX) + 1;
    tlv_ipv4_list_t  list{{&byte, too_large}};
    tlv_ipv4_t       ip{};
    size_t           written = 99;
    EXPECT_EQ(TLV_ERR_INVALID_VALUE, tlv_codec_encode(&tlv_codec_ipv4_list, &list, sizeof(list),
                                                      nullptr, 0, &written, NULL));
    EXPECT_EQ(0u, written);
    EXPECT_EQ(TLV_ERR_INVALID_VALUE, tlv_ipv4_list_at(&list, 0, &ip));
}
