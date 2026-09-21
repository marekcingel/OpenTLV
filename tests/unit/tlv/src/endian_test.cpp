#include "tlv/endian.h"
#include "tlv/tlv.h"

#include <gtest/gtest.h>
#include <cstring>
#include "tlv/tag.h"

extern "C" int tlv_test_c_endian(void);

TEST(Unit_TLVEndian, PublicCContract) {
    EXPECT_EQ(1, tlv_test_c_endian());
    EXPECT_EQ(13, TLV_ERR_OVERFLOW);
    EXPECT_STREQ("numeric overflow", tlv_strerror(TLV_ERR_OVERFLOW));
}

namespace {
struct EndianCase {
    uint32_t value;
    uint8_t  be[4];
    uint8_t  le[4];
};

const EndianCase cases[] = {
    {0x00000000u, {0x00, 0x00, 0x00, 0x00}, {0x00, 0x00, 0x00, 0x00}},
    {0x00000001u, {0x00, 0x00, 0x00, 0x01}, {0x01, 0x00, 0x00, 0x00}},
    {0x12345678u, {0x12, 0x34, 0x56, 0x78}, {0x78, 0x56, 0x34, 0x12}},
    {0x80FF8000u, {0x80, 0xFF, 0x80, 0x00}, {0x00, 0x80, 0xFF, 0x80}},
    {0xFFFFFFFFu, {0xFF, 0xFF, 0xFF, 0xFF}, {0xFF, 0xFF, 0xFF, 0xFF}},
};
} // namespace

TEST(Unit_TLVEndian, read_u16_be_from_exact_bytes) {
    for (const auto& test : cases) {
        SCOPED_TRACE(test.value);
        alignas(uint32_t) uint8_t storage[3] = {};
        for (size_t i = 0; i < 2; ++i) {
            storage[i + 1] = test.be[i + 2];
        }
        EXPECT_EQ(static_cast<uint16_t>(test.value), tlv_read_u16_be(storage + 1));
    }
}

TEST(Unit_TLVEndian, write_u16_be_produces_exact_bytes) {
    for (const auto& test : cases) {
        SCOPED_TRACE(test.value);
        alignas(uint32_t) uint8_t storage[4];
        for (auto& byte : storage) {
            byte = 0xA5;
        }
        tlv_write_u16_be(storage + 1, static_cast<uint16_t>(test.value));
        EXPECT_EQ(0xA5, storage[0]);
        EXPECT_EQ(0xA5, storage[3]);
        for (size_t i = 0; i < 2; ++i) {
            EXPECT_EQ(test.be[i + 2], storage[i + 1]) << "byte " << i;
        }
    }
}

TEST(Unit_TLVEndian, read_u16_le_from_exact_bytes) {
    for (const auto& test : cases) {
        SCOPED_TRACE(test.value);
        alignas(uint32_t) uint8_t storage[3] = {};
        for (size_t i = 0; i < 2; ++i) {
            storage[i + 1] = test.le[i + 0];
        }
        EXPECT_EQ(static_cast<uint16_t>(test.value), tlv_read_u16_le(storage + 1));
    }
}

TEST(Unit_TLVEndian, write_u16_le_produces_exact_bytes) {
    for (const auto& test : cases) {
        SCOPED_TRACE(test.value);
        alignas(uint32_t) uint8_t storage[4];
        for (auto& byte : storage) {
            byte = 0xA5;
        }
        tlv_write_u16_le(storage + 1, static_cast<uint16_t>(test.value));
        EXPECT_EQ(0xA5, storage[0]);
        EXPECT_EQ(0xA5, storage[3]);
        for (size_t i = 0; i < 2; ++i) {
            EXPECT_EQ(test.le[i + 0], storage[i + 1]) << "byte " << i;
        }
    }
}

TEST(Unit_TLVEndian, read_u32_be_from_exact_bytes) {
    for (const auto& test : cases) {
        SCOPED_TRACE(test.value);
        alignas(uint32_t) uint8_t storage[5] = {};
        for (size_t i = 0; i < 4; ++i) {
            storage[i + 1] = test.be[i + 0];
        }
        EXPECT_EQ(static_cast<uint32_t>(test.value), tlv_read_u32_be(storage + 1));
    }
}

TEST(Unit_TLVEndian, write_u32_be_produces_exact_bytes) {
    for (const auto& test : cases) {
        SCOPED_TRACE(test.value);
        alignas(uint32_t) uint8_t storage[6];
        for (auto& byte : storage) {
            byte = 0xA5;
        }
        tlv_write_u32_be(storage + 1, static_cast<uint32_t>(test.value));
        EXPECT_EQ(0xA5, storage[0]);
        EXPECT_EQ(0xA5, storage[5]);
        for (size_t i = 0; i < 4; ++i) {
            EXPECT_EQ(test.be[i + 0], storage[i + 1]) << "byte " << i;
        }
    }
}

TEST(Unit_TLVEndian, read_u32_le_from_exact_bytes) {
    for (const auto& test : cases) {
        SCOPED_TRACE(test.value);
        alignas(uint32_t) uint8_t storage[5] = {};
        for (size_t i = 0; i < 4; ++i) {
            storage[i + 1] = test.le[i + 0];
        }
        EXPECT_EQ(static_cast<uint32_t>(test.value), tlv_read_u32_le(storage + 1));
    }
}

TEST(Unit_TLVEndian, write_u32_le_produces_exact_bytes) {
    for (const auto& test : cases) {
        SCOPED_TRACE(test.value);
        alignas(uint32_t) uint8_t storage[6];
        for (auto& byte : storage) {
            byte = 0xA5;
        }
        tlv_write_u32_le(storage + 1, static_cast<uint32_t>(test.value));
        EXPECT_EQ(0xA5, storage[0]);
        EXPECT_EQ(0xA5, storage[5]);
        for (size_t i = 0; i < 4; ++i) {
            EXPECT_EQ(test.le[i + 0], storage[i + 1]) << "byte " << i;
        }
    }
}

TEST(Unit_TLVEndian, NativeOrderMatchesIntegerStorage) {
    const uint32_t original = UINT32_C(0x12345678);
    uint8_t        bytes[4];
    std::memcpy(bytes, &original, sizeof(bytes));
    const tlv_byte_order_t order = tlv_endian_native();
    const uint8_t          big[] = {0x12, 0x34, 0x56, 0x78};
    const uint8_t          little[] = {0x78, 0x56, 0x34, 0x12};
    if (std::memcmp(bytes, big, sizeof(bytes)) == 0)
        EXPECT_EQ(TLV_BYTE_ORDER_BIG_ENDIAN, order);
    else if (std::memcmp(bytes, little, sizeof(bytes)) == 0)
        EXPECT_EQ(TLV_BYTE_ORDER_LITTLE_ENDIAN, order);
    else
        EXPECT_EQ(TLV_BYTE_ORDER_UNKNOWN, order);
    if (order != TLV_BYTE_ORDER_UNKNOWN) {
        uint64_t result = 0;
        ASSERT_EQ(TLV_OK, tlv_read_uint(bytes, sizeof(bytes), order, &result));
        EXPECT_EQ(original, result);
    }
}

TEST(Unit_TLVEndian, CheckedWidthsExactBytesAndPadding) {
    const uint64_t values[] = {0x01,
                               0x0102,
                               0x010203,
                               0x01020304,
                               UINT64_C(0x0102030405),
                               UINT64_C(0x010203040506),
                               UINT64_C(0x01020304050607),
                               UINT64_C(0x0102030405060708)};
    for (size_t width = 1; width <= sizeof(uint64_t); ++width) {
        for (auto order : {TLV_BYTE_ORDER_BIG_ENDIAN, TLV_BYTE_ORDER_LITTLE_ENDIAN}) {
            alignas(uint64_t) uint8_t bytes[10];
            uint8_t                   expected[8];
            for (size_t i = 0; i < width; ++i)
                expected[i] =
                    static_cast<uint8_t>(order == TLV_BYTE_ORDER_BIG_ENDIAN ? i + 1 : width - i);
            std::memset(bytes, 0xA5, sizeof(bytes));
            ASSERT_EQ(TLV_OK, tlv_write_uint(bytes + 1, width, order, values[width - 1]));
            EXPECT_EQ(0, std::memcmp(expected, bytes + 1, width));
            EXPECT_EQ(0xA5, bytes[0]);
            EXPECT_EQ(0xA5, bytes[width + 1]);
            std::memcpy(bytes + 1, expected, width);
            uint64_t value = 99;
            ASSERT_EQ(TLV_OK, tlv_read_uint(bytes + 1, width, order, &value));
            EXPECT_EQ(values[width - 1], value);
            for (uint64_t small : {UINT64_C(0), UINT64_C(1)}) {
                ASSERT_EQ(TLV_OK, tlv_write_uint(bytes + 1, width, order, small));
                for (size_t i = 0; i < width; ++i)
                    EXPECT_EQ(i == (order == TLV_BYTE_ORDER_BIG_ENDIAN ? width - 1 : 0) ? small : 0,
                              bytes[i + 1]);
                ASSERT_EQ(TLV_OK, tlv_read_uint(bytes + 1, width, order, &value));
                EXPECT_EQ(small, value);
            }
            const uint64_t maximum = UINT64_MAX >> ((sizeof(uint64_t) - width) * 8);
            ASSERT_EQ(TLV_OK, tlv_write_uint(bytes + 1, width, order, maximum));
            for (size_t i = 1; i <= width; ++i) EXPECT_EQ(255, bytes[i]);
            ASSERT_EQ(TLV_OK, tlv_read_uint(bytes + 1, width, order, &value));
            EXPECT_EQ(maximum, value);
            if (width < sizeof(uint64_t)) {
                EXPECT_EQ(TLV_ERR_OVERFLOW, tlv_write_uint(bytes + 1, width, order, maximum + 1));
                for (size_t i = 1; i <= width; ++i) EXPECT_EQ(255, bytes[i]);
            }
            EXPECT_EQ(0xA5, bytes[0]);
            for (size_t i = width + 1; i < sizeof(bytes); ++i) EXPECT_EQ(0xA5, bytes[i]);
        }
    }
}

TEST(Unit_TLVEndian, CheckedFailuresPreserveOutputs) {
    uint8_t bytes[8];
    std::memset(bytes, 0xA5, sizeof(bytes));
    uint64_t value = 42;
    for (size_t width : {size_t(0), size_t(9), SIZE_MAX}) {
        EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
                  tlv_read_uint(bytes, width, TLV_BYTE_ORDER_BIG_ENDIAN, &value));
        EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
                  tlv_write_uint(bytes, width, TLV_BYTE_ORDER_BIG_ENDIAN, 0));
    }
    for (auto order : {TLV_BYTE_ORDER_UNKNOWN, static_cast<tlv_byte_order_t>(99)}) {
        EXPECT_EQ(TLV_ERR_INVALID_BYTE_ORDER, tlv_read_uint(bytes, 8, order, &value));
        EXPECT_EQ(TLV_ERR_INVALID_BYTE_ORDER, tlv_write_uint(bytes, 8, order, 0));
    }
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_read_uint(nullptr, 8, TLV_BYTE_ORDER_BIG_ENDIAN, &value));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_read_uint(bytes, 8, TLV_BYTE_ORDER_BIG_ENDIAN, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_write_uint(nullptr, 8, TLV_BYTE_ORDER_BIG_ENDIAN, 0));
    EXPECT_EQ(42u, value);
    for (auto byte : bytes) EXPECT_EQ(0xA5, byte);
}

TEST(Unit_TLVEndian, ValidationOrderAndBothOrdersPreserveOutputs) {
    for (auto order : {TLV_BYTE_ORDER_BIG_ENDIAN, TLV_BYTE_ORDER_LITTLE_ENDIAN,
                       TLV_BYTE_ORDER_UNKNOWN, static_cast<tlv_byte_order_t>(99)}) {
        alignas(uint64_t) uint8_t storage[10];
        std::memset(storage, 0xA5, sizeof(storage));
        uint64_t value = 42;
        for (size_t width : {size_t(0), size_t(9), SIZE_MAX}) {
            EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_read_uint(nullptr, width, order, &value));
            EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_read_uint(storage + 1, width, order, nullptr));
            EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_write_uint(nullptr, width, order, UINT64_MAX));
            EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_read_uint(storage + 1, width, order, &value));
            EXPECT_EQ(42u, value);
            EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
                      tlv_write_uint(storage + 1, width, order, UINT64_MAX));
            for (auto byte : storage) EXPECT_EQ(0xA5, byte);
        }
        if (order == TLV_BYTE_ORDER_UNKNOWN || static_cast<int>(order) == 99) {
            EXPECT_EQ(TLV_ERR_INVALID_BYTE_ORDER,
                      tlv_write_uint(storage + 1, 1, order, UINT64_MAX));
            for (auto byte : storage) EXPECT_EQ(0xA5, byte);
        }
    }
}

TEST(Unit_TLVEndian, FixedU64ExactBytesUnaligned) {
    const uint64_t values[] = {0, 1, UINT64_C(0x0123456789ABCDEF), UINT64_MAX};
    const uint8_t  expected[][8] = {{0},
                                    {0, 0, 0, 0, 0, 0, 0, 1},
                                    {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
                                    {255, 255, 255, 255, 255, 255, 255, 255}};
    for (size_t n = 0; n < 4; ++n) {
        alignas(uint64_t) uint8_t bytes[10];
        std::memset(bytes, 0xA5, sizeof(bytes));
        tlv_write_u64_be(bytes + 1, values[n]);
        EXPECT_EQ(0, std::memcmp(bytes + 1, expected[n], 8));
        std::memcpy(bytes + 1, expected[n], 8);
        EXPECT_EQ(values[n], tlv_read_u64_be(bytes + 1));
        tlv_write_u64_le(bytes + 1, values[n]);
        for (size_t i = 0; i < 8; ++i) EXPECT_EQ(expected[n][7 - i], bytes[i + 1]);
        for (size_t i = 0; i < 8; ++i) bytes[i + 1] = expected[n][7 - i];
        EXPECT_EQ(values[n], tlv_read_u64_le(bytes + 1));
        EXPECT_EQ(0xA5, bytes[0]);
        EXPECT_EQ(0xA5, bytes[9]);
    }
}
