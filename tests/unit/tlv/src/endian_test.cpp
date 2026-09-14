#include "tlv/endian.h"
#include "tlv/tlv.h"

#include <gtest/gtest.h>
#include <cstring>
#include "tlv/tag.h"

namespace {
struct EndianCase {
    uint32_t value;
    uint8_t be[4];
    uint8_t le[4];
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
        EXPECT_EQ(static_cast<uint16_t>(test.value),
                  tlv_read_u16_be(storage + 1));
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
        EXPECT_EQ(static_cast<uint16_t>(test.value),
                  tlv_read_u16_le(storage + 1));
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
        EXPECT_EQ(static_cast<uint32_t>(test.value),
                  tlv_read_u32_be(storage + 1));
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
        EXPECT_EQ(static_cast<uint32_t>(test.value),
                  tlv_read_u32_le(storage + 1));
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
    uint8_t bytes[4];
    std::memcpy(bytes, &original, sizeof(bytes));
    const tlv_byte_order_t order = tlv_endian_native();
    const uint8_t big[] = {0x12, 0x34, 0x56, 0x78};
    const uint8_t little[] = {0x78, 0x56, 0x34, 0x12};
    if (std::memcmp(bytes, big, sizeof(bytes)) == 0)
        EXPECT_EQ(TLV_BYTE_ORDER_BIG_ENDIAN, order);
    else if (std::memcmp(bytes, little, sizeof(bytes)) == 0)
        EXPECT_EQ(TLV_BYTE_ORDER_LITTLE_ENDIAN, order);
    else
        EXPECT_EQ(TLV_BYTE_ORDER_UNKNOWN, order);
#if TLV_TAG_MAX_SIZE >= 4
    if (order != TLV_BYTE_ORDER_UNKNOWN) {
        tlv_tag_t tag = {{0}, 4};
        std::memcpy(tag.data, bytes, sizeof(bytes));
        uint32_t result = 0;
        ASSERT_EQ(TLV_OK, tlv_tag_to_u32(&tag, order, &result));
        EXPECT_EQ(original, result);
    }
#endif
}
