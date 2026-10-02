// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "controlled_format.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#include <gtest/gtest.h>
#include <cstring>
TEST(Unit_Tlv_FormatInit, IndependentCapabilitiesAndAtomicFailure) {
    tlv_format_t read{}, write{}, both{};
    const auto&  f = controlled::format;
    ASSERT_EQ(TLV_OK, tlv_format_init(&read, f.context, f.decode, nullptr, nullptr));
    ASSERT_EQ(TLV_OK, tlv_format_init(&write, f.context, nullptr, f.measure, f.encode));
    ASSERT_EQ(TLV_OK, tlv_format_init(&both, f.context, f.decode, f.measure, f.encode));
    EXPECT_TRUE(tlv_format_can_read(&read));
    EXPECT_FALSE(tlv_format_can_write(&read));
    EXPECT_FALSE(tlv_format_can_read(&write));
    EXPECT_TRUE(tlv_format_can_write(&write));
    auto before = both;
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_format_init(&both, nullptr, nullptr, nullptr, nullptr));
    EXPECT_EQ(0, std::memcmp(&before, &both, sizeof(both)));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_format_init(&both, nullptr, f.decode, f.measure, nullptr));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_format_init(&both, nullptr, f.decode, nullptr, f.encode));
    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              tlv_format_init(nullptr, nullptr, f.decode, f.measure, f.encode));
    EXPECT_EQ(0, std::memcmp(&before, &both, sizeof(both)));
    tlv_reader_t reader{};
    tlv_writer_t writer{};
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_reader_init(&reader, nullptr, 0, &write));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_writer_init(&writer, nullptr, 0, &read));
}
