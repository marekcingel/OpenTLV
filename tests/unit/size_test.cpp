#include "tlv/size.h"

#include <gtest/gtest.h>
#include <limits>

TEST(Unit_Tlv_Size, FromSizeConvertsZeroAndMaximumLosslessly) {
    tlv_size_t length = 42;
    ASSERT_EQ(TLV_OK, tlv_size_from_native(0, &length));
    EXPECT_EQ(0u, length);

    length = 42;
    ASSERT_EQ(TLV_OK, tlv_size_from_native(std::numeric_limits<size_t>::max(), &length));
    EXPECT_EQ(static_cast<tlv_size_t>(std::numeric_limits<size_t>::max()), length);
}

TEST(Unit_Tlv_Size, FromSizeRejectsNullOutputAndLeavesItUnchanged) {
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_size_from_native(0, nullptr));
}

TEST(Unit_Tlv_Size, ToSizeAcceptsZeroAndNativeMaximum) {
    size_t size = 99;
    ASSERT_EQ(TLV_OK, tlv_size_to_native(0, &size));
    EXPECT_EQ(0u, size);

    size = 99;
    const tlv_size_t native_maximum = std::numeric_limits<size_t>::max();
    ASSERT_EQ(TLV_OK, tlv_size_to_native(native_maximum, &size));
    EXPECT_EQ(std::numeric_limits<size_t>::max(), size);
}

TEST(Unit_Tlv_Size, ToSizeRejectsNullOutput) {
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_size_to_native(0, nullptr));
}

TEST(Unit_Tlv_Size, ToSizeRejectsLengthsBeyondSizeMaxAndLeavesOutputUnchanged) {
    size_t size = 99;
    if (std::numeric_limits<size_t>::max() < UINT64_MAX) {
        // 32-bit builds: a length one past UINT32_MAX is a real 64-bit
        // number but does not fit the native size_t.
        const tlv_size_t oversized =
            static_cast<tlv_size_t>(std::numeric_limits<size_t>::max()) + 1;
        EXPECT_EQ(TLV_ERR_NATIVE_SIZE, tlv_size_to_native(oversized, &size));
        EXPECT_EQ(99u, size);
    }
    // On a 64-bit build UINT64_MAX fits size_t; on a 32-bit build it does not.
    size = 99;
    tlv_result_t rc = tlv_size_to_native(UINT64_MAX, &size);
    if (std::numeric_limits<size_t>::max() == UINT64_MAX) {
        EXPECT_EQ(TLV_OK, rc);
        EXPECT_EQ(std::numeric_limits<size_t>::max(), size);
    } else {
        EXPECT_EQ(TLV_ERR_NATIVE_SIZE, rc);
        EXPECT_EQ(99u, size);
    }
}

TEST(Unit_Tlv_Size, ValidateNativeAcceptsEverythingWithinSizeTRange) {
    EXPECT_EQ(TLV_OK, tlv_size_validate_native(0));
    EXPECT_EQ(TLV_OK, tlv_size_validate_native(std::numeric_limits<size_t>::max()));
}

TEST(Unit_Tlv_Size, ValidateNativeDoesNotAccessMemoryForOversizedLength) {
    // No pointer is passed; a value beyond SIZE_MAX is rejected purely
    // numerically, without touching any buffer.
    if (std::numeric_limits<size_t>::max() < UINT64_MAX) {
        EXPECT_EQ(TLV_ERR_NATIVE_SIZE, tlv_size_validate_native(UINT64_MAX));
    } else {
        EXPECT_EQ(TLV_OK, tlv_size_validate_native(UINT64_MAX));
    }
}

TEST(Unit_Tlv_Size, MaxIsTheFull64BitRange) {
    EXPECT_EQ(UINT64_MAX, static_cast<uint64_t>(TLV_SIZE_MAX));
}

TEST(Unit_Tlv_Size, AddSumsWithinRange) {
    tlv_size_t sum = 99;
    ASSERT_EQ(TLV_OK, tlv_size_add(2, 3, &sum));
    EXPECT_EQ(5u, sum);
    sum = 99;
    ASSERT_EQ(TLV_OK, tlv_size_add(0, 0, &sum));
    EXPECT_EQ(0u, sum);
    sum = 99;
    ASSERT_EQ(TLV_OK, tlv_size_add(TLV_SIZE_MAX, 0, &sum));
    EXPECT_EQ(TLV_SIZE_MAX, sum);
}

TEST(Unit_Tlv_Size, AddDetectsOverflowAndLeavesOutputUnchanged) {
    tlv_size_t sum = 99;
    EXPECT_EQ(TLV_ERR_OVERFLOW, tlv_size_add(TLV_SIZE_MAX, 1, &sum));
    EXPECT_EQ(99u, sum);
    sum = 99;
    EXPECT_EQ(TLV_ERR_OVERFLOW, tlv_size_add(1, TLV_SIZE_MAX, &sum));
    EXPECT_EQ(99u, sum);
}

TEST(Unit_Tlv_Size, AddRejectsNullOutput) {
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_size_add(1, 2, nullptr));
}
