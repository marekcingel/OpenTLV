// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_TEST_FIXED_VALUE_CHECKS_H
#define OPENTLV_TEST_FIXED_VALUE_CHECKS_H

#include "tlv/codec/codec.h"
#include <gtest/gtest.h>
#include <cstring>

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

#endif
