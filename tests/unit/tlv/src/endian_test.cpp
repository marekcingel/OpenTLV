#include "tlv/endian.h"
#include "tlv/tlv.h"

#include <gtest/gtest.h>

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
