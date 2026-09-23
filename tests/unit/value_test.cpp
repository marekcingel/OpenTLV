#include "tlv/value.h"

#include <gtest/gtest.h>
#include <cstring>
#include <limits>

TEST(Unit_Tlv_Value, InitBorrowsDataAndLength) {
    uint8_t     storage[] = {0x12, 0x34, 0x56};
    tlv_value_t value{};
    ASSERT_EQ(TLV_OK, tlv_value_init(storage + 1, 2, &value));
    EXPECT_EQ(storage + 1, value.data);
    EXPECT_EQ(2u, value.length);
    storage[1] = 0xAB;
    EXPECT_EQ(0xAB, value.data[0]);
}

TEST(Unit_Tlv_Value, InitAcceptsZeroLengthWithNullData) {
    tlv_value_t value{};
    ASSERT_EQ(TLV_OK, tlv_value_init(nullptr, 0, &value));
    EXPECT_EQ(nullptr, value.data);
    EXPECT_EQ(0u, value.length);
}

TEST(Unit_Tlv_Value, InitRejectsNullDataWithNonzeroLengthAndLeavesOutputUnchanged) {
    tlv_value_t value{reinterpret_cast<const uint8_t*>(0x1), 7};
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_value_init(nullptr, 1, &value));
    EXPECT_EQ(reinterpret_cast<const uint8_t*>(0x1), value.data);
    EXPECT_EQ(7u, value.length);
}

TEST(Unit_Tlv_Value, InitRejectsNullOutput) {
    uint8_t byte = 0;
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_value_init(&byte, 1, nullptr));
}

TEST(Unit_Tlv_Value, InitChecksNullPointersBeforeNativeRange) {
    // A length that does not fit size_t and a NULL data pointer both apply;
    // the pointer check must win, matching tlv_value_init's documented order.
    if (std::numeric_limits<size_t>::max() < UINT64_MAX) {
        tlv_value_t value{reinterpret_cast<const uint8_t*>(0x1), 7};
        EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_value_init(nullptr, UINT64_MAX, &value));
        EXPECT_EQ(reinterpret_cast<const uint8_t*>(0x1), value.data);
        EXPECT_EQ(7u, value.length);
    }
}

TEST(Unit_Tlv_Value, InitRejectsLengthBeyondNativeSizeAndLeavesOutputUnchanged) {
    if (std::numeric_limits<size_t>::max() < UINT64_MAX) {
        uint8_t     byte = 0;
        tlv_value_t value{reinterpret_cast<const uint8_t*>(0x1), 7};
        EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_value_init(&byte, UINT64_MAX, &value));
        EXPECT_EQ(reinterpret_cast<const uint8_t*>(0x1), value.data);
        EXPECT_EQ(7u, value.length);
    }
}

TEST(Unit_Tlv_Value, InitAcceptsNativeMaximumLength) {
    uint8_t            byte = 0;
    tlv_value_t        value{};
    const tlv_length_t native_maximum = std::numeric_limits<size_t>::max();
    ASSERT_EQ(TLV_OK, tlv_value_init(&byte, native_maximum, &value));
    EXPECT_EQ(&byte, value.data);
    EXPECT_EQ(native_maximum, value.length);
}

TEST(Unit_Tlv_Value, ValidateAcceptsBorrowedRangeAndEmptyValue) {
    uint8_t           byte = 0;
    const tlv_value_t borrowed = {&byte, 1};
    EXPECT_EQ(TLV_OK, tlv_value_validate(&borrowed));
    const tlv_value_t empty = {nullptr, 0};
    EXPECT_EQ(TLV_OK, tlv_value_validate(&empty));
}

TEST(Unit_Tlv_Value, ValidateRejectsNullValue) {
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_value_validate(nullptr));
}

TEST(Unit_Tlv_Value, ValidateRejectsNullDataWithNonzeroLength) {
    const tlv_value_t value = {nullptr, 1};
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_value_validate(&value));
}

TEST(Unit_Tlv_Value, ValidateRejectsLengthBeyondNativeSize) {
    uint8_t           byte = 0;
    const tlv_value_t value = {&byte, UINT64_MAX};
    tlv_result_t      rc = tlv_value_validate(&value);
    if (std::numeric_limits<size_t>::max() < UINT64_MAX) {
        EXPECT_EQ(TLV_ERR_INVALID_LENGTH, rc);
    } else {
        EXPECT_EQ(TLV_OK, rc);
    }
}

TEST(Unit_Tlv_Value, ValidateDoesNotProveSufficientAllocationBounds) {
    // A one-byte object described as a much longer value still validates:
    // validation checks representation only, never actual bounds.
    uint8_t           byte = 0;
    const tlv_value_t value = {&byte, 1000};
    EXPECT_EQ(TLV_OK, tlv_value_validate(&value));
}

TEST(Unit_Tlv_Value, EqualComparesContentsNotPointers) {
    const uint8_t a[] = {0x01, 0x02, 0x03};
    const uint8_t b[] = {0x01, 0x02, 0x03};
    ASSERT_NE(a, b);
    EXPECT_TRUE(tlv_value_equal({a, sizeof(a)}, {b, sizeof(b)}));
    EXPECT_TRUE(tlv_value_equal({a, sizeof(a)}, {a, sizeof(a)}));
    EXPECT_TRUE(tlv_value_equal({nullptr, 0}, {nullptr, 0}));
}

TEST(Unit_Tlv_Value, EqualRejectsDifferentBytesAndLengths) {
    const uint8_t a[] = {0x01, 0x02, 0x03};
    const uint8_t b[] = {0x01, 0x02, 0x04};
    EXPECT_FALSE(tlv_value_equal({a, sizeof(a)}, {b, sizeof(b)}));
    EXPECT_FALSE(tlv_value_equal({a, sizeof(a)}, {a, 2}));
}

TEST(Unit_Tlv_Value, CompareIsLexicographicAndAgreesWithEqual) {
    const uint8_t a[] = {0x01, 0xFF};
    const uint8_t b[] = {0x02, 0x00};
    const uint8_t prefix[] = {0x01};
    EXPECT_LT(tlv_value_compare({a, sizeof(a)}, {b, sizeof(b)}), 0);
    EXPECT_GT(tlv_value_compare({b, sizeof(b)}, {a, sizeof(a)}), 0);
    EXPECT_LT(tlv_value_compare({prefix, sizeof(prefix)}, {a, sizeof(a)}), 0);
    EXPECT_EQ(0, tlv_value_compare({a, sizeof(a)}, {a, sizeof(a)}));
    EXPECT_EQ(tlv_value_equal({a, sizeof(a)}, {b, sizeof(b)}),
              tlv_value_compare({a, sizeof(a)}, {b, sizeof(b)}) == 0);
}

TEST(Unit_Tlv_Value, IsEmpty) {
    const uint8_t byte = 0;
    EXPECT_TRUE(tlv_value_is_empty({nullptr, 0}));
    EXPECT_TRUE(tlv_value_is_empty({&byte, 0}));
    EXPECT_FALSE(tlv_value_is_empty({&byte, 1}));
}

TEST(Unit_Tlv_Value, SliceBorrowsASubRange) {
    const uint8_t     bytes[] = {0x10, 0x11, 0x12, 0x13, 0x14};
    const tlv_value_t value = {bytes, sizeof(bytes)};
    tlv_value_t       part{reinterpret_cast<const uint8_t*>(0x1), 99};
    ASSERT_EQ(TLV_OK, tlv_value_slice(value, 1, 3, &part));
    EXPECT_EQ(bytes + 1, part.data);
    EXPECT_EQ(3u, part.length);
    EXPECT_TRUE(tlv_value_equal(part, tlv_value_t{bytes + 1, 3}));
}

TEST(Unit_Tlv_Value, SliceAcceptsTheFullRangeAndAnEmptyTrailingRange) {
    const uint8_t     bytes[] = {0x10, 0x11};
    const tlv_value_t value = {bytes, sizeof(bytes)};
    tlv_value_t       part{};
    ASSERT_EQ(TLV_OK, tlv_value_slice(value, 0, 2, &part));
    EXPECT_EQ(bytes, part.data);
    EXPECT_EQ(2u, part.length);
    ASSERT_EQ(TLV_OK, tlv_value_slice(value, 2, 0, &part));
    EXPECT_EQ(nullptr, part.data);
    EXPECT_EQ(0u, part.length);
}

TEST(Unit_Tlv_Value, SliceRejectsNullOutput) {
    const uint8_t bytes[] = {0x10};
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_value_slice({bytes, 1}, 0, 1, nullptr));
}

TEST(Unit_Tlv_Value, SliceRejectsARangeExceedingTheValue) {
    const uint8_t     bytes[] = {0x10, 0x11};
    const tlv_value_t value = {bytes, sizeof(bytes)};
    tlv_value_t       part{reinterpret_cast<const uint8_t*>(0x1), 99};
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_value_slice(value, 1, 2, &part));
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_value_slice(value, 3, 0, &part));
    EXPECT_EQ(reinterpret_cast<const uint8_t*>(0x1), part.data);
    EXPECT_EQ(99u, part.length);
}

TEST(Unit_Tlv_Value, SliceDetectsOffsetPlusLengthOverflow) {
    const uint8_t bytes[] = {0x10};
    tlv_value_t   part{};
    EXPECT_EQ(TLV_ERR_OVERFLOW, tlv_value_slice({bytes, 1}, UINT64_MAX, 1, &part));
}

TEST(Unit_Tlv_Value, CopyReportsRequiredSizeWithNullDestination) {
    const uint8_t bytes[] = {0x01, 0x02, 0x03};
    size_t        written = 0;
    EXPECT_EQ(TLV_OK, tlv_value_copy({bytes, sizeof(bytes)}, nullptr, 0, &written));
    EXPECT_EQ(3u, written);
}

TEST(Unit_Tlv_Value, CopyWritesBytesAndSupportsOverlap) {
    uint8_t bytes[] = {1, 2, 3, 4};
    size_t  written = 0;
    ASSERT_EQ(TLV_OK, tlv_value_copy({bytes, 3}, bytes + 1, 3, &written));
    EXPECT_EQ(3u, written);
    const uint8_t expected[] = {1, 1, 2, 3};
    EXPECT_EQ(0, std::memcmp(expected, bytes, 4));
}

TEST(Unit_Tlv_Value, CopyRejectsInsufficientCapacityAndLeavesOutputsUnchanged) {
    const uint8_t bytes[] = {1, 2, 3};
    uint8_t       output[2] = {0xEE, 0xEE};
    size_t        written = 99;
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_value_copy({bytes, 3}, output, 2, &written));
    EXPECT_EQ(99u, written);
    EXPECT_EQ(0xEE, output[0]);
}

TEST(Unit_Tlv_Value, CopyRejectsNullArguments) {
    uint8_t byte = 0xEE;
    size_t  written = 99;
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_value_copy({&byte, 1}, nullptr, 1, &written));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_value_copy({&byte, 1}, &byte, 1, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_value_copy({nullptr, 1}, nullptr, 0, &written));
}
