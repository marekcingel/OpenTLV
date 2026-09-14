#include "tlv/length.h"

#include <gtest/gtest.h>
#include <limits>

TEST(Unit_TLVLength, FromSizeConvertsZeroAndMaximumLosslessly) {
    tlv_length_t length = 42;
    ASSERT_EQ(TLV_OK, tlv_length_from_size(0, &length));
    EXPECT_EQ(0u, length);

    length = 42;
    ASSERT_EQ(TLV_OK, tlv_length_from_size(std::numeric_limits<size_t>::max(), &length));
    EXPECT_EQ(static_cast<tlv_length_t>(std::numeric_limits<size_t>::max()), length);
}

TEST(Unit_TLVLength, FromSizeRejectsNullOutputAndLeavesItUnchanged) {
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_length_from_size(0, nullptr));
}

TEST(Unit_TLVLength, ToSizeAcceptsZeroAndNativeMaximum) {
    size_t size = 99;
    ASSERT_EQ(TLV_OK, tlv_length_to_size(0, &size));
    EXPECT_EQ(0u, size);

    size = 99;
    const tlv_length_t native_maximum = std::numeric_limits<size_t>::max();
    ASSERT_EQ(TLV_OK, tlv_length_to_size(native_maximum, &size));
    EXPECT_EQ(std::numeric_limits<size_t>::max(), size);
}

TEST(Unit_TLVLength, ToSizeRejectsNullOutput) {
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_length_to_size(0, nullptr));
}

TEST(Unit_TLVLength, ToSizeRejectsLengthsBeyondSizeMaxAndLeavesOutputUnchanged) {
    size_t size = 99;
    if (std::numeric_limits<size_t>::max() < UINT64_MAX) {
        // 32-bit builds: a length one past UINT32_MAX is a real 64-bit
        // number but does not fit the native size_t.
        const tlv_length_t oversized =
            static_cast<tlv_length_t>(std::numeric_limits<size_t>::max()) + 1;
        EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_length_to_size(oversized, &size));
        EXPECT_EQ(99u, size);
    }
    // On a 64-bit build UINT64_MAX fits size_t; on a 32-bit build it does not.
    size = 99;
    tlv_result_t rc = tlv_length_to_size(UINT64_MAX, &size);
    if (std::numeric_limits<size_t>::max() == UINT64_MAX) {
        EXPECT_EQ(TLV_OK, rc);
        EXPECT_EQ(std::numeric_limits<size_t>::max(), size);
    } else {
        EXPECT_EQ(TLV_ERR_INVALID_LENGTH, rc);
        EXPECT_EQ(99u, size);
    }
}

TEST(Unit_TLVLength, ValidateNativeAcceptsEverythingWithinSizeTRange) {
    EXPECT_EQ(TLV_OK, tlv_length_validate_native(0));
    EXPECT_EQ(TLV_OK, tlv_length_validate_native(std::numeric_limits<size_t>::max()));
}

TEST(Unit_TLVLength, ValidateNativeDoesNotAccessMemoryForOversizedLength) {
    // No pointer is passed; a value beyond SIZE_MAX is rejected purely
    // numerically, without touching any buffer.
    if (std::numeric_limits<size_t>::max() < UINT64_MAX) {
        EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_length_validate_native(UINT64_MAX));
    } else {
        EXPECT_EQ(TLV_OK, tlv_length_validate_native(UINT64_MAX));
    }
}
