#include "tlv/value.h"

#include <gtest/gtest.h>
#include <cstring>
#include <limits>

TEST(Unit_TLVValue, InitBorrowsDataAndLength) {
    uint8_t     storage[] = {0x12, 0x34, 0x56};
    tlv_value_t value{};
    ASSERT_EQ(TLV_OK, tlv_value_init(storage + 1, 2, &value));
    EXPECT_EQ(storage + 1, value.data);
    EXPECT_EQ(2u, value.length);
    storage[1] = 0xAB;
    EXPECT_EQ(0xAB, value.data[0]);
}

TEST(Unit_TLVValue, InitAcceptsZeroLengthWithNullData) {
    tlv_value_t value{};
    ASSERT_EQ(TLV_OK, tlv_value_init(nullptr, 0, &value));
    EXPECT_EQ(nullptr, value.data);
    EXPECT_EQ(0u, value.length);
}

TEST(Unit_TLVValue, InitRejectsNullDataWithNonzeroLengthAndLeavesOutputUnchanged) {
    tlv_value_t value{reinterpret_cast<const uint8_t*>(0x1), 7};
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_value_init(nullptr, 1, &value));
    EXPECT_EQ(reinterpret_cast<const uint8_t*>(0x1), value.data);
    EXPECT_EQ(7u, value.length);
}

TEST(Unit_TLVValue, InitRejectsNullOutput) {
    uint8_t byte = 0;
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_value_init(&byte, 1, nullptr));
}

TEST(Unit_TLVValue, InitChecksNullPointersBeforeNativeRange) {
    // A length that does not fit size_t and a NULL data pointer both apply;
    // the pointer check must win, matching tlv_value_init's documented order.
    if (std::numeric_limits<size_t>::max() < UINT64_MAX) {
        tlv_value_t value{reinterpret_cast<const uint8_t*>(0x1), 7};
        EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_value_init(nullptr, UINT64_MAX, &value));
        EXPECT_EQ(reinterpret_cast<const uint8_t*>(0x1), value.data);
        EXPECT_EQ(7u, value.length);
    }
}

TEST(Unit_TLVValue, InitRejectsLengthBeyondNativeSizeAndLeavesOutputUnchanged) {
    if (std::numeric_limits<size_t>::max() < UINT64_MAX) {
        uint8_t     byte = 0;
        tlv_value_t value{reinterpret_cast<const uint8_t*>(0x1), 7};
        EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_value_init(&byte, UINT64_MAX, &value));
        EXPECT_EQ(reinterpret_cast<const uint8_t*>(0x1), value.data);
        EXPECT_EQ(7u, value.length);
    }
}

TEST(Unit_TLVValue, InitAcceptsNativeMaximumLength) {
    uint8_t            byte = 0;
    tlv_value_t        value{};
    const tlv_length_t native_maximum = std::numeric_limits<size_t>::max();
    ASSERT_EQ(TLV_OK, tlv_value_init(&byte, native_maximum, &value));
    EXPECT_EQ(&byte, value.data);
    EXPECT_EQ(native_maximum, value.length);
}

TEST(Unit_TLVValue, ValidateAcceptsBorrowedRangeAndEmptyValue) {
    uint8_t           byte = 0;
    const tlv_value_t borrowed = {&byte, 1};
    EXPECT_EQ(TLV_OK, tlv_value_validate(&borrowed));
    const tlv_value_t empty = {nullptr, 0};
    EXPECT_EQ(TLV_OK, tlv_value_validate(&empty));
}

TEST(Unit_TLVValue, ValidateRejectsNullValue) {
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_value_validate(nullptr));
}

TEST(Unit_TLVValue, ValidateRejectsNullDataWithNonzeroLength) {
    const tlv_value_t value = {nullptr, 1};
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_value_validate(&value));
}

TEST(Unit_TLVValue, ValidateRejectsLengthBeyondNativeSize) {
    uint8_t           byte = 0;
    const tlv_value_t value = {&byte, UINT64_MAX};
    tlv_result_t      rc = tlv_value_validate(&value);
    if (std::numeric_limits<size_t>::max() < UINT64_MAX) {
        EXPECT_EQ(TLV_ERR_INVALID_LENGTH, rc);
    } else {
        EXPECT_EQ(TLV_OK, rc);
    }
}

TEST(Unit_TLVValue, ValidateDoesNotProveSufficientAllocationBounds) {
    // A one-byte object described as a much longer value still validates:
    // validation checks representation only, never actual bounds.
    uint8_t           byte = 0;
    const tlv_value_t value = {&byte, 1000};
    EXPECT_EQ(TLV_OK, tlv_value_validate(&value));
}
