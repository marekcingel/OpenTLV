#include "controlled_format.h"
#include "tlv++/tlv.hpp"

#include <gtest/gtest.h>

#include <array>
#include <string>
#include <type_traits>

#if __cplusplus >= 201703L
static_assert(std::is_same<tlv::byte, std::byte>::value, "C++17 must use std::byte");
static_assert(std::is_same<tlv::any, std::any>::value, "C++17 must use std::any");
#endif
#if __cplusplus >= 202002L
static_assert(std::is_same<tlv::span<int>, std::span<int>>::value, "C++20 must use std::span");
#endif
#if defined(__cpp_lib_expected) && __cpp_lib_expected >= 202202L
static_assert(std::is_same<tlv::expected<int, int>, std::expected<int, int>>::value,
              "C++23 must use std::expected");
#endif

namespace {

tlv::bytes to_bytes(const std::string& s) {
    return tlv::bytes(reinterpret_cast<const tlv::byte*>(s.data()), s.size());
}

TEST(Unit_Tlvpp, WriterReportsBufferTooShort) {
    std::array<tlv::byte, 2> buf{};
    tlv::writer              w(buf.data(), buf.size(), controlled::writer);

    auto r = w.write(TLV_TAG(0x01), to_bytes("abcd"));
    ASSERT_FALSE(r.has_value());
    EXPECT_TRUE(r.error().code == TLV_ERR_BUFFER_TOO_SHORT);
}

TEST(Unit_Tlvpp, ReaderReportsEndOfBuffer) {
    std::array<tlv::byte, 2> buf{{static_cast<tlv::byte>(0x01), static_cast<tlv::byte>(0x00)}};
    tlv::reader              reader(tlv::bytes(buf.data(), buf.size()), controlled::reader);

    auto e1 = reader.next();
    ASSERT_TRUE(e1.has_value());
    EXPECT_TRUE(e1->value.empty());

    EXPECT_TRUE(reader.at_end());
    auto e2 = reader.next();
    ASSERT_FALSE(e2.has_value());
    EXPECT_TRUE(e2.error().code == TLV_ERR_END_OF_BUFFER);
}

TEST(Unit_Tlvpp, WriterWriteDiagReportsRequiredExceedingAvailableCapacity) {
    std::array<tlv::byte, 1> buf{};
    tlv::writer              w(buf.data(), buf.size(), controlled::writer);

    tlv::writer_diagnostic diagnostic{};
    auto                   e = w.write(TLV_TAG(0x01), to_bytes("ab"), diagnostic);
    ASSERT_FALSE(e.has_value());
    EXPECT_TRUE(e.error().code == TLV_ERR_BUFFER_TOO_SHORT);
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, diagnostic.diagnostic.code);
    EXPECT_EQ(TLV_WRITER_OP_VALUE, diagnostic.operation);
    ASSERT_TRUE(diagnostic.has_required);
    EXPECT_EQ(4u, diagnostic.required);
    ASSERT_TRUE(diagnostic.has_available);
    EXPECT_EQ(1u, diagnostic.available);
}

TEST(Unit_Tlvpp, ReaderNextDiagReportsValueExceedingAvailableBytes) {
    std::array<tlv::byte, 2> buf{{static_cast<tlv::byte>(0xAB), static_cast<tlv::byte>(6)}};
    tlv::reader              reader(tlv::bytes(buf.data(), buf.size()), controlled::reader);

    tlv::reader_diagnostic diagnostic{};
    auto                   e = reader.next(diagnostic);
    ASSERT_FALSE(e.has_value());
    EXPECT_TRUE(e.error().code == TLV_ERR_BUFFER_TOO_SHORT);
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, diagnostic.diagnostic.code);
    EXPECT_EQ(TLV_READER_OP_VALUE, diagnostic.operation);
    ASSERT_TRUE(diagnostic.has_declared_length);
    EXPECT_EQ(6u, diagnostic.declared_length);
    ASSERT_TRUE(diagnostic.has_available);
    EXPECT_EQ(0u, diagnostic.available);
}

// --- Codec concept test ---

struct greeting {
    static const tlv::tag_t tag;
    std::string             text;

    void encode(std::vector<tlv::byte>& out) const {
        out.resize(text.size());
        for (size_t i = 0; i < text.size(); ++i) {
            out[i] = static_cast<tlv::byte>(text[i]);
        }
    }

    static tlv::expected<greeting, tlv::error> decode(tlv::bytes data) {
        std::string s(reinterpret_cast<const char*>(data.data()), data.size());
        return greeting{s};
    }
};

const tlv::tag_t greeting::tag = TLV_TAG(0x10);

static_assert(tlv::is_tlv_codec<greeting>::value, "greeting must satisfy TLV codec interface");

TEST(Unit_Tlvpp, RegistryComparesValidTagBytesAndSize) {
    tlv::codec_registry registry;
    tlv::tag_t          first = TLV_TAG(0x10);
    registry.register_decoder(
        first, [](tlv::bytes) -> tlv::expected<tlv::any, tlv::error> { return tlv::any(42); });
    // The same bytes in different memory are the same tag.
    const std::uint8_t same_bytes[] = {0x10};
    tlv::tag_t         same = tlv_tag(same_bytes, sizeof(same_bytes));
    EXPECT_TRUE(registry.has_decoder(same));
    tlv::tag_t other = TLV_TAG(0x11);
    EXPECT_FALSE(registry.has_decoder(other));
    tlv::tag_t longer = TLV_TAG(0x10, 0x00);
    EXPECT_FALSE(registry.has_decoder(longer));
    registry.register_decoder(
        longer, [](tlv::bytes) -> tlv::expected<tlv::any, tlv::error> { return tlv::any(84); });
    auto decoded = registry.decode(longer, tlv::bytes{});
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(84, tlv::any_cast<int>(*decoded));
    auto decoded_first = registry.decode(first, tlv::bytes{});
    ASSERT_TRUE(decoded_first.has_value());
    EXPECT_EQ(42, tlv::any_cast<int>(*decoded_first));
}

} // namespace
