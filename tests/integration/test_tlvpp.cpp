// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv++/builtins/asn1/ber.hpp"
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

TEST(Integration_Tlvpp, WriterReaderRoundtrip) {
    std::array<tlv::byte, 64> buf{};
    tlv::writer<>             w(buf.data(), buf.size(), tlv::ber::format{});

    auto r1 = w.write(tlv::tag_bytes<0x01>(), to_bytes("hi"));
    ASSERT_TRUE(r1.has_value());
    auto r2 = w.write(tlv::tag_bytes<0x02>(), to_bytes("x"));
    ASSERT_TRUE(r2.has_value());

    tlv::reader<> reader(tlv::bytes(buf.data(), w.size()), tlv::ber::format{});

    auto e1 = reader.next();
    ASSERT_TRUE(e1.has_value());
    EXPECT_TRUE(e1->tag() == tlv::tag_bytes<0x01>());
    EXPECT_TRUE(e1->value().size() == 2);

    auto e2 = reader.next();
    ASSERT_TRUE(e2.has_value());
    EXPECT_TRUE(e2->tag() == tlv::tag_bytes<0x02>());
    EXPECT_TRUE(e2->value().size() == 1);

    EXPECT_TRUE(reader.at_end());
}

TEST(Integration_Tlvpp, RegistryDynamicDecode) {
    const tlv::tag      greeting = tlv::tag_bytes<0x10>();
    tlv::codec_registry registry;
    registry.register_decoder(greeting, [](tlv::bytes data) -> tlv::expected<tlv::any, tlv::error> {
        return tlv::any(std::string(reinterpret_cast<const char*>(data.data()), data.size()));
    });
    EXPECT_TRUE(registry.has_decoder(greeting));

    std::array<tlv::byte, 64> buf{};
    tlv::writer<>             w(buf.data(), buf.size(), tlv::ber::format{});
    ASSERT_TRUE(w.write(greeting, to_bytes("cau")).has_value());

    tlv::reader<> reader(tlv::bytes(buf.data(), w.size()), tlv::ber::format{});
    auto          element = reader.next();
    ASSERT_TRUE(element.has_value());

    auto decoded = registry.decode(element->tag(), element->value().as_bytes());
    ASSERT_TRUE(decoded.has_value());
    EXPECT_TRUE(tlv::any_cast<std::string>(*decoded) == "cau");

    auto unregistered = registry.decode(tlv::tag_bytes<0x11>(), tlv::bytes{});
    ASSERT_FALSE(unregistered.has_value());
    EXPECT_EQ(tlv::errc::unsupported, unregistered.error().status());
}

} // namespace
