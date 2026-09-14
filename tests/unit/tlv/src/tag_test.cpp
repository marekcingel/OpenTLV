#include "tlv/tag.h"
#include <gtest/gtest.h>
#include <cstring>

namespace {
template<typename Function, typename... Args>
void check_comparison(tlv_result_t status, int expected, Function compare, Args... args) {
    int equal = 42;
    EXPECT_EQ(status, compare(args..., &equal));
    EXPECT_EQ(status == TLV_OK ? expected : 42, equal);
}
void check_numeric_equality(const tlv_tag_t* tag, uint64_t value, int expected, tlv_result_t status = TLV_OK) {
    check_comparison(status, expected, tlv_tag_equal_u64, tag, value, TLV_BYTE_ORDER_BIG_ENDIAN);
}
}

TEST(Unit_Tag, ExactComparison) {
    tlv_tag_t a = {{0x82}, 1};
    tlv_tag_t b = a;
    check_comparison(TLV_OK, 1, tlv_tag_equal, &a, &b);
    b.data[0] = 0x83;
    check_comparison(TLV_OK, 0, tlv_tag_equal, &a, &b);
    a.size = b.size = 0;
    check_comparison(TLV_OK, 1, tlv_tag_equal, &a, &b);
    b.size = 1;
    check_comparison(TLV_OK, 0, tlv_tag_equal, &a, &b);
#if TLV_TAG_CAPACITY >= 2
    a.size = 1;
    b = a;
    b.data[1] = 0xff;
    check_comparison(TLV_OK, 1, tlv_tag_equal, &a, &b);
#endif
    check_comparison(TLV_ERR_NULL_ARG, 0, tlv_tag_equal, nullptr, &b);
    check_comparison(TLV_ERR_NULL_ARG, 0, tlv_tag_equal, &a, nullptr);
#if TLV_TAG_CAPACITY < TLV_TAG_MAX_SUPPORTED_SIZE
    a.size = TLV_TAG_CAPACITY + 1;
    check_comparison(TLV_ERR_INVALID_TAG_SIZE, 0, tlv_tag_equal, &a, &a);
    check_comparison(TLV_ERR_INVALID_TAG_SIZE, 0, tlv_tag_equal, &b, &a);
#endif
}

TEST(Unit_Tag, ByteArrayComparisonAcrossFullCapacity) {
    tlv_tag_t tag = {{0}, TLV_TAG_CAPACITY};
    uint8_t bytes[TLV_TAG_CAPACITY] = {};
    for (size_t i = 0; i < sizeof(bytes); ++i)
        tag.data[i] = bytes[i] = static_cast<uint8_t>(i);
    check_comparison(TLV_OK, 1, tlv_tag_equal_bytes, &tag, bytes, sizeof(bytes));
    tlv_tag_t other = tag;
    check_comparison(TLV_OK, 1, tlv_tag_equal, &tag, &other);
    bytes[sizeof(bytes) - 1] ^= 1;
    check_comparison(TLV_OK, 0, tlv_tag_equal_bytes, &tag, bytes, sizeof(bytes));
    other.data[sizeof(bytes) - 1] ^= 1;
    check_comparison(TLV_OK, 0, tlv_tag_equal, &tag, &other);
    check_comparison(TLV_OK, 0, tlv_tag_equal_bytes, &tag, bytes, sizeof(bytes) - 1);
    tag.size = 0;
    check_comparison(TLV_OK, 1, tlv_tag_equal_bytes, &tag, nullptr, 0);
    tag.size = 1;
    check_comparison(TLV_OK, 0, tlv_tag_equal_bytes, &tag, nullptr, 0);
    check_comparison(TLV_ERR_NULL_ARG, 0, tlv_tag_equal_bytes, nullptr, bytes, 1);
    check_comparison(TLV_ERR_NULL_ARG, 0, tlv_tag_equal_bytes, &tag, nullptr, 1);
    check_comparison(TLV_ERR_INVALID_TAG_SIZE, 0, tlv_tag_equal_bytes, &tag, bytes, SIZE_MAX);
#if TLV_TAG_CAPACITY < TLV_TAG_MAX_SUPPORTED_SIZE
    tag.size = TLV_TAG_CAPACITY + 1;
    check_comparison(TLV_ERR_INVALID_TAG_SIZE, 0, tlv_tag_equal_bytes, &tag, bytes, 1);
#endif
}

TEST(Unit_Tag, NumericConversion) {
    tlv_tag_t tag = {{0x82}, 1};
    uint64_t value = 0;
    ASSERT_EQ(TLV_OK, tlv_tag_to_u64(&tag, TLV_BYTE_ORDER_BIG_ENDIAN, &value));
    EXPECT_EQ(UINT64_C(0x82), value);
    check_numeric_equality(&tag, 0x82, 1);
    check_numeric_equality(&tag, 0x83, 0);
    tag.data[0] = 0;
    check_numeric_equality(&tag, 0, 1);
#if TLV_TAG_CAPACITY >= 2
    tag = {{0x9f, 0x02}, 2};
    check_numeric_equality(&tag, 0x9f02, 1);
    const tlv_tag_t short_tag = {{0x82}, 1};
    tag = {{0, 0x82}, 2};
    check_comparison(TLV_OK, 0, tlv_tag_equal, &tag, &short_tag);
    check_numeric_equality(&tag, 0x82, 1);
#endif
#if TLV_TAG_CAPACITY >= 8
    tag = {{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}, 8};
    check_numeric_equality(&tag, UINT64_C(0x0123456789abcdef), 1);
    std::memset(tag.data, 0xff, 8);
    check_numeric_equality(&tag, UINT64_MAX, 1);
#endif
}

TEST(Unit_Tag, ConversionFailurePreservesOutput) {
    tlv_tag_t tag = {{0}, 0};
    uint64_t value = 123;
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_tag_to_u64(nullptr, TLV_BYTE_ORDER_BIG_ENDIAN, &value));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_tag_to_u64(&tag, TLV_BYTE_ORDER_BIG_ENDIAN, nullptr));
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE, tlv_tag_to_u64(&tag, TLV_BYTE_ORDER_BIG_ENDIAN, &value));
    EXPECT_EQ(123u, value);
    check_numeric_equality(&tag, 0, 0, TLV_ERR_INVALID_TAG_SIZE);
    check_numeric_equality(nullptr, 0, 0, TLV_ERR_NULL_ARG);
#if TLV_TAG_CAPACITY < TLV_TAG_MAX_SUPPORTED_SIZE
    tag.size = TLV_TAG_CAPACITY + 1;
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE, tlv_tag_to_u64(&tag, TLV_BYTE_ORDER_BIG_ENDIAN, &value));
    EXPECT_EQ(123u, value);
#endif
#if TLV_TAG_CAPACITY > 8
    tag.size = 9;
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE, tlv_tag_to_u64(&tag, TLV_BYTE_ORDER_BIG_ENDIAN, &value));
    EXPECT_EQ(123u, value);
    check_numeric_equality(&tag, 0, 0, TLV_ERR_INVALID_TAG_SIZE);
    tag.size = TLV_TAG_CAPACITY;
    check_comparison(TLV_OK, 1, tlv_tag_equal, &tag, &tag);
#endif
}

namespace {
template<typename T>
void check_narrow_conversion(tlv_result_t (*convert)(const tlv_tag_t*, tlv_byte_order_t, T*)) {
    tlv_tag_t tag = {{0}, 1};
    T value = 123;
    ASSERT_EQ(TLV_OK, convert(&tag, TLV_BYTE_ORDER_BIG_ENDIAN, &value));
    EXPECT_EQ(0u, value);
    tag.data[0] = 0x82;
    ASSERT_EQ(TLV_OK, convert(&tag, TLV_BYTE_ORDER_BIG_ENDIAN, &value));
    EXPECT_EQ(0x82u, value);
    value = 123;
    EXPECT_EQ(TLV_ERR_NULL_ARG, convert(nullptr, TLV_BYTE_ORDER_BIG_ENDIAN, &value));
    EXPECT_EQ(123u, value);
    EXPECT_EQ(TLV_ERR_NULL_ARG, convert(&tag, TLV_BYTE_ORDER_BIG_ENDIAN, nullptr));
    tag.size = 0;
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE, convert(&tag, TLV_BYTE_ORDER_BIG_ENDIAN, &value));
    EXPECT_EQ(123u, value);
#if TLV_TAG_CAPACITY < TLV_TAG_MAX_SUPPORTED_SIZE
    tag.size = TLV_TAG_CAPACITY + 1;
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE, convert(&tag, TLV_BYTE_ORDER_BIG_ENDIAN, &value));
    EXPECT_EQ(123u, value);
#endif
#if TLV_TAG_CAPACITY > 8
    tag.size = 9;
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE, convert(&tag, TLV_BYTE_ORDER_BIG_ENDIAN, &value));
    EXPECT_EQ(123u, value);
#endif
    if (sizeof(T) <= TLV_TAG_CAPACITY) {
        tag.size = static_cast<uint8_t>(sizeof(T));
        std::memset(tag.data, 0xff, tag.size);
        ASSERT_EQ(TLV_OK, convert(&tag, TLV_BYTE_ORDER_BIG_ENDIAN, &value));
        EXPECT_EQ(static_cast<T>(~T(0)), value);
    }
    if (sizeof(T) < TLV_TAG_CAPACITY) {
        tag.size = static_cast<uint8_t>(sizeof(T) + 1);
        std::memset(tag.data, 0, tag.size);
        tag.data[0] = 1;
        value = 123;
        EXPECT_EQ(TLV_ERR_INVALID_TAG, convert(&tag, TLV_BYTE_ORDER_BIG_ENDIAN, &value));
        EXPECT_EQ(123u, value);
        std::memset(tag.data, 0xff, tag.size);
        tag.data[0] = 0;
        ASSERT_EQ(TLV_OK, convert(&tag, TLV_BYTE_ORDER_BIG_ENDIAN, &value));
        EXPECT_EQ(static_cast<T>(~T(0)), value);
    }
#if TLV_TAG_CAPACITY >= 8
    tag.size = 8;
    std::memset(tag.data, 0, 8);
    tag.data[7] = 0x82;
    ASSERT_EQ(TLV_OK, convert(&tag, TLV_BYTE_ORDER_BIG_ENDIAN, &value));
    EXPECT_EQ(0x82u, value);
#endif
}
}

TEST(Unit_Tag, CheckedU8Conversion) { check_narrow_conversion(tlv_tag_to_u8); }
TEST(Unit_Tag, CheckedU16Conversion) { check_narrow_conversion(tlv_tag_to_u16); }
TEST(Unit_Tag, CheckedU32Conversion) { check_narrow_conversion(tlv_tag_to_u32); }

namespace {
template<typename T>
void check_narrow_equality(tlv_result_t (*compare)(const tlv_tag_t*, T, tlv_byte_order_t, int*)) {
    tlv_tag_t tag = {{0x82}, 1};
    EXPECT_EQ(TLV_ERR_NULL_ARG, compare(&tag, T(0x82), TLV_BYTE_ORDER_BIG_ENDIAN, nullptr));
    check_comparison(TLV_OK, 1, compare, &tag, T(0x82), TLV_BYTE_ORDER_BIG_ENDIAN);
    check_comparison(TLV_OK, 0, compare, &tag, T(0x83), TLV_BYTE_ORDER_BIG_ENDIAN);
    tag.data[0] = 0;
    check_comparison(TLV_OK, 1, compare, &tag, T(0), TLV_BYTE_ORDER_BIG_ENDIAN);
    check_comparison(TLV_ERR_NULL_ARG, 0, compare, nullptr, T(0), TLV_BYTE_ORDER_BIG_ENDIAN);
    tag.size = 0;
    check_comparison(TLV_ERR_INVALID_TAG_SIZE, 0, compare, &tag, T(0), TLV_BYTE_ORDER_BIG_ENDIAN);
#if TLV_TAG_CAPACITY < TLV_TAG_MAX_SUPPORTED_SIZE
    tag.size = TLV_TAG_CAPACITY + 1;
    check_comparison(TLV_ERR_INVALID_TAG_SIZE, 0, compare, &tag, T(0), TLV_BYTE_ORDER_BIG_ENDIAN);
#endif
#if TLV_TAG_CAPACITY > 8
    tag.size = 9;
    check_comparison(TLV_ERR_INVALID_TAG_SIZE, 0, compare, &tag, T(0), TLV_BYTE_ORDER_BIG_ENDIAN);
#endif
    if (sizeof(T) <= TLV_TAG_CAPACITY) {
        tag.size = static_cast<uint8_t>(sizeof(T));
        std::memset(tag.data, 0xff, tag.size);
        check_comparison(TLV_OK, 1, compare, &tag, static_cast<T>(~T(0)), TLV_BYTE_ORDER_BIG_ENDIAN);
    }
    if (sizeof(T) < TLV_TAG_CAPACITY && sizeof(T) < 8) {
        tag.size = static_cast<uint8_t>(sizeof(T) + 1);
        std::memset(tag.data, 0, tag.size);
        tag.data[0] = 1;
        check_comparison(TLV_OK, 0, compare, &tag, T(0), TLV_BYTE_ORDER_BIG_ENDIAN);
        std::memset(tag.data, 0xff, tag.size);
        tag.data[0] = 0;
        check_comparison(TLV_OK, 1, compare, &tag, static_cast<T>(~T(0)), TLV_BYTE_ORDER_BIG_ENDIAN);
    }
#if TLV_TAG_CAPACITY >= 8
    tag.size = 8;
    std::memset(tag.data, 0, 8);
    tag.data[7] = 0x82;
    check_comparison(TLV_OK, 1, compare, &tag, T(0x82), TLV_BYTE_ORDER_BIG_ENDIAN);
#endif
}
}

TEST(Unit_Tag, U8Equality) { check_narrow_equality(tlv_tag_equal_u8); }
TEST(Unit_Tag, U16Equality) { check_narrow_equality(tlv_tag_equal_u16); }
TEST(Unit_Tag, U32Equality) { check_narrow_equality(tlv_tag_equal_u32); }
TEST(Unit_Tag, U64Equality) { check_narrow_equality(tlv_tag_equal_u64); }

namespace {
template<typename T>
void check_byte_orders(tlv_result_t (*convert)(const tlv_tag_t*, tlv_byte_order_t, T*),
                       tlv_result_t (*compare)(const tlv_tag_t*, T, tlv_byte_order_t, int*)) {
    tlv_tag_t tag = {{0x82}, 1};
    T value = 0;
    ASSERT_EQ(TLV_OK, convert(&tag, TLV_BYTE_ORDER_LITTLE_ENDIAN, &value));
    EXPECT_EQ(0x82u, value);
    check_comparison(TLV_OK, 1, compare, &tag, T(0x82), TLV_BYTE_ORDER_LITTLE_ENDIAN);
    check_comparison(TLV_OK, 0, compare, &tag, T(0x83), TLV_BYTE_ORDER_LITTLE_ENDIAN);
    for (auto invalid : {TLV_BYTE_ORDER_UNKNOWN, static_cast<tlv_byte_order_t>(99)}) {
        value = 123;
        EXPECT_EQ(TLV_ERR_INVALID_BYTE_ORDER, convert(&tag, invalid, &value));
        EXPECT_EQ(123u, value);
        check_comparison(TLV_ERR_INVALID_BYTE_ORDER, 0, compare, &tag, T(0x82), invalid);
    }
#if TLV_TAG_CAPACITY >= 2
    tag = {{0x82, 0}, 2};
    ASSERT_EQ(TLV_OK, convert(&tag, TLV_BYTE_ORDER_LITTLE_ENDIAN, &value));
    EXPECT_EQ(0x82u, value);
    check_comparison(TLV_OK, 1, compare, &tag, T(0x82), TLV_BYTE_ORDER_LITTLE_ENDIAN);
    check_comparison(TLV_OK, 0, compare, &tag, T(0x82), TLV_BYTE_ORDER_BIG_ENDIAN);
    if (sizeof(T) >= 2) {
        tag = {{0x9f, 0x02}, 2};
        ASSERT_EQ(TLV_OK, convert(&tag, TLV_BYTE_ORDER_BIG_ENDIAN, &value));
        EXPECT_EQ(0x9f02u, value);
        ASSERT_EQ(TLV_OK, convert(&tag, TLV_BYTE_ORDER_LITTLE_ENDIAN, &value));
        EXPECT_EQ(0x029fu, value);
    }
#endif
    if (sizeof(T) < 8 && sizeof(T) < TLV_TAG_CAPACITY) {
        tag.size = static_cast<uint8_t>(sizeof(T) + 1);
        std::memset(tag.data, 0, tag.size);
        tag.data[tag.size - 1] = 1;
        value = 123;
        EXPECT_EQ(TLV_ERR_INVALID_TAG, convert(&tag, TLV_BYTE_ORDER_LITTLE_ENDIAN, &value));
        EXPECT_EQ(123u, value);
        check_comparison(TLV_OK, 0, compare, &tag, T(0), TLV_BYTE_ORDER_LITTLE_ENDIAN);
    }
#if TLV_TAG_CAPACITY >= 8
    tag = {{0x82, 0, 0, 0, 0, 0, 0, 0}, 8};
    ASSERT_EQ(TLV_OK, convert(&tag, TLV_BYTE_ORDER_LITTLE_ENDIAN, &value));
    EXPECT_EQ(0x82u, value);
#endif
}
}

TEST(Unit_Tag, U8ByteOrders) { check_byte_orders(tlv_tag_to_u8, tlv_tag_equal_u8); }
TEST(Unit_Tag, U16ByteOrders) { check_byte_orders(tlv_tag_to_u16, tlv_tag_equal_u16); }
TEST(Unit_Tag, U32ByteOrders) { check_byte_orders(tlv_tag_to_u32, tlv_tag_equal_u32); }
TEST(Unit_Tag, U64ByteOrders) {
    check_byte_orders(tlv_tag_to_u64, tlv_tag_equal_u64);
#if TLV_TAG_CAPACITY >= 8
    const tlv_tag_t tag = {{0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01}, 8};
    check_comparison(TLV_OK, 1, tlv_tag_equal_u64, &tag, UINT64_C(0x0123456789abcdef), TLV_BYTE_ORDER_LITTLE_ENDIAN);
#endif
}

TEST(Unit_Tag, ConstructFromBytes) {
    uint8_t bytes[TLV_TAG_CAPACITY];
    for (size_t i = 0; i < sizeof(bytes); ++i) bytes[i] = static_cast<uint8_t>(i + 1);
    tlv_tag_t tag = {{0}, 0};
    ASSERT_EQ(TLV_OK, tlv_tag_from_bytes(bytes, sizeof(bytes), &tag));
    EXPECT_EQ(sizeof(bytes), tag.size);
    EXPECT_EQ(0, std::memcmp(bytes, tag.data, sizeof(bytes)));
    const tlv_tag_t original = tag;
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_tag_from_bytes(nullptr, 1, &tag));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_tag_from_bytes(bytes, 1, nullptr));
    for (size_t size : {size_t(TLV_TAG_CAPACITY) + 1, size_t(256), size_t(257), SIZE_MAX}) {
        EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE, tlv_tag_from_bytes(bytes, size, &tag));
        EXPECT_EQ(0, std::memcmp(&original, &tag, sizeof(tag)));
        check_comparison(TLV_ERR_INVALID_TAG_SIZE, 0, tlv_tag_equal_bytes, &tag, bytes, size);
    }
    EXPECT_EQ(0, std::memcmp(&original, &tag, sizeof(tag)));
    ASSERT_EQ(TLV_OK, tlv_tag_from_bytes(tag.data, tag.size, &tag));
    EXPECT_EQ(0, std::memcmp(&original, &tag, sizeof(tag)));
#if TLV_TAG_CAPACITY > 1
    ASSERT_EQ(TLV_OK, tlv_tag_from_bytes(tag.data + 1, TLV_TAG_CAPACITY - 1, &tag));
    EXPECT_EQ(0, std::memcmp(bytes + 1, tag.data, TLV_TAG_CAPACITY - 1));
    EXPECT_EQ(0, tag.data[TLV_TAG_CAPACITY - 1]);
#endif
    ASSERT_EQ(TLV_OK, tlv_tag_from_bytes(nullptr, 0, &tag));
    EXPECT_EQ(0, tag.size);
    for (auto byte : tag.data) EXPECT_EQ(0, byte);
}

namespace {
template<typename T>
void check_constructor(tlv_result_t (*construct)(T, size_t, tlv_byte_order_t, tlv_tag_t*),
                       tlv_result_t (*convert)(const tlv_tag_t*, tlv_byte_order_t, T*)) {
    tlv_tag_t tag;
    std::memset(&tag, 0x55, sizeof(tag));
    const tlv_tag_t original = tag;
    EXPECT_EQ(TLV_ERR_NULL_ARG, construct(T(0), 1, TLV_BYTE_ORDER_BIG_ENDIAN, nullptr));
    for (size_t size : {size_t(0), size_t(9), size_t(TLV_TAG_CAPACITY) + 1, SIZE_MAX}) {
        EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE, construct(T(0), size, TLV_BYTE_ORDER_BIG_ENDIAN, &tag));
        EXPECT_EQ(0, std::memcmp(&original, &tag, sizeof(tag)));
    }
    EXPECT_EQ(TLV_ERR_INVALID_BYTE_ORDER, construct(T(0), 1, TLV_BYTE_ORDER_UNKNOWN, &tag));
    EXPECT_EQ(0, std::memcmp(&original, &tag, sizeof(tag)));
    if (sizeof(T) > 1) {
        EXPECT_EQ(TLV_ERR_INVALID_TAG, construct(static_cast<T>(0x100), 1, TLV_BYTE_ORDER_BIG_ENDIAN, &tag));
        EXPECT_EQ(0, std::memcmp(&original, &tag, sizeof(tag)));
    }
    for (auto order : {TLV_BYTE_ORDER_BIG_ENDIAN, TLV_BYTE_ORDER_LITTLE_ENDIAN}) {
        for (size_t size = 1; size <= sizeof(uint64_t) && size <= TLV_TAG_CAPACITY; ++size) {
            ASSERT_EQ(TLV_OK, construct(T(0x82), size, order, &tag));
            EXPECT_EQ(size, tag.size);
            for (size_t i = 0; i < TLV_TAG_CAPACITY; ++i)
                EXPECT_EQ(i == (order == TLV_BYTE_ORDER_BIG_ENDIAN ? size - 1 : 0) ? 0x82 : 0, tag.data[i]);
            T value = 0;
            ASSERT_EQ(TLV_OK, convert(&tag, order, &value));
            EXPECT_EQ(T(0x82), value);
        }
        if (sizeof(T) <= TLV_TAG_CAPACITY) {
            const T maximum = static_cast<T>(~T(0));
            ASSERT_EQ(TLV_OK, construct(maximum, sizeof(T), order, &tag));
            for (size_t i = 0; i < sizeof(T); ++i) EXPECT_EQ(0xff, tag.data[i]);
            T value = 0;
            ASSERT_EQ(TLV_OK, convert(&tag, order, &value));
            EXPECT_EQ(maximum, value);
        }
        ASSERT_EQ(TLV_OK, construct(T(0), 1, order, &tag));
        EXPECT_EQ(1, tag.size);
        for (auto byte : tag.data) EXPECT_EQ(0, byte);
    }
}
}

TEST(Unit_Tag, ConstructU8) { check_constructor(tlv_tag_from_u8, tlv_tag_to_u8); }
TEST(Unit_Tag, ConstructU16) { check_constructor(tlv_tag_from_u16, tlv_tag_to_u16); }
TEST(Unit_Tag, ConstructU32) { check_constructor(tlv_tag_from_u32, tlv_tag_to_u32); }
TEST(Unit_Tag, ConstructU64) { check_constructor(tlv_tag_from_u64, tlv_tag_to_u64); }

TEST(Unit_Tag, IrregularNumericLengths) {
    const uint8_t big[] = {1, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd};
    const uint64_t expected[] = {UINT64_C(0x012345), UINT64_C(0x0123456789), UINT64_C(0x0123456789abcd)};
    size_t fixture = 0;
    for (size_t size : {size_t(3), size_t(5), size_t(7)}) {
        const uint64_t value = expected[fixture++];
        if (size > TLV_TAG_CAPACITY) continue;
        for (auto order : {TLV_BYTE_ORDER_BIG_ENDIAN, TLV_BYTE_ORDER_LITTLE_ENDIAN}) {
            tlv_tag_t tag = {{0}, static_cast<uint8_t>(size)};
            for (size_t i = 0; i < size; ++i)
                tag.data[i] = big[order == TLV_BYTE_ORDER_BIG_ENDIAN ? i : size - 1 - i];
            uint64_t decoded = 0;
            ASSERT_EQ(TLV_OK, tlv_tag_to_u64(&tag, order, &decoded));
            EXPECT_EQ(value, decoded);
            tlv_tag_t encoded = {{0}, 0};
            ASSERT_EQ(TLV_OK, tlv_tag_from_u64(value, size, order, &encoded));
            check_comparison(TLV_OK, 1, tlv_tag_equal, &tag, &encoded);
        }
    }
}

TEST(Unit_Tag, MultipleInvalidInputsKeepValidationOrder) {
    tlv_tag_t tag = {{0x82}, 1};
    const tlv_tag_t before = tag;
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_tag_from_bytes(nullptr, SIZE_MAX, &tag));
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              tlv_tag_from_u64(0, 0, TLV_BYTE_ORDER_UNKNOWN, nullptr));
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE,
              tlv_tag_from_u64(UINT64_MAX, 0, TLV_BYTE_ORDER_UNKNOWN, &tag));
    EXPECT_EQ(TLV_ERR_INVALID_BYTE_ORDER,
              tlv_tag_from_u64(UINT64_MAX, 1, TLV_BYTE_ORDER_UNKNOWN, &tag));
    EXPECT_EQ(0, std::memcmp(&before, &tag, sizeof(tag)));
    tag.size = 0;
    uint64_t value = 42;
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_tag_to_u64(&tag, TLV_BYTE_ORDER_UNKNOWN, nullptr));
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE, tlv_tag_to_u64(&tag, TLV_BYTE_ORDER_UNKNOWN, &value));
    EXPECT_EQ(42u, value);
}

TEST(Unit_Tag, ComparisonNullOutputsAndValidationOrder) {
    tlv_tag_t tag = {{0}, 0};
    int equal = 42;
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_tag_equal(&tag, &tag, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_tag_equal_bytes(&tag, nullptr, 0, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_tag_equal_bytes(&tag, nullptr, SIZE_MAX, &equal));
    EXPECT_EQ(42, equal);
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              tlv_tag_equal_u64(&tag, 0, TLV_BYTE_ORDER_UNKNOWN, nullptr));
    check_comparison(TLV_ERR_INVALID_TAG_SIZE, 0, tlv_tag_equal_u64,
                     &tag, UINT64_MAX, TLV_BYTE_ORDER_UNKNOWN);
    tag.size = 1;
    check_comparison(TLV_ERR_INVALID_BYTE_ORDER, 0, tlv_tag_equal_u64,
                     &tag, UINT64_MAX, TLV_BYTE_ORDER_UNKNOWN);
}
