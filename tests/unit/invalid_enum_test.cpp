// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include <gtest/gtest.h>

extern "C" int tlv_test_invalid_enum_fields(void);
extern "C" int tlv_test_invalid_enum_visitors(void);

TEST(Unit_Tlv_InvalidEnum, FieldConfigurationAndEndianValidationInC) {
    EXPECT_EQ(0, tlv_test_invalid_enum_fields());
}

TEST(Unit_Tlv_InvalidEnum, VisitorErrorsAndResumeInC) {
    EXPECT_EQ(0, tlv_test_invalid_enum_visitors());
}
