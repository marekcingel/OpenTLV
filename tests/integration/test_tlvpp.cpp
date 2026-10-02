// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/builtins/asn1/ber.h"
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
    tlv::writer<>             w(buf.data(), buf.size(), tlv_format_ber);

    auto r1 = w.write(tlv::tag_bytes<0x01>(), to_bytes("hi"));
    ASSERT_TRUE(r1.has_value());
    auto r2 = w.write(tlv::tag_bytes<0x02>(), to_bytes("x"));
    ASSERT_TRUE(r2.has_value());

    tlv::reader<> reader(tlv::bytes(buf.data(), w.size()), tlv_format_ber);

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

// --- Codec concept test ---

struct greeting {
    static const tlv::tag tag;
    std::string           text;

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

const tlv::tag greeting::tag = tlv::tag_bytes<0x10>();

static_assert(tlv::is_tlv_codec<greeting>::value, "greeting must satisfy TLV codec interface");

TEST(Integration_Tlvpp, CodecWriteViaWriter) {
    std::array<tlv::byte, 64> buf{};
    tlv::writer<>             w(buf.data(), buf.size(), tlv_format_ber);

    greeting g{"ahoj"};
    auto     r = tlv::write_value(w, g);
    ASSERT_TRUE(r.has_value());

    tlv::reader<> reader(tlv::bytes(buf.data(), w.size()), tlv_format_ber);
    auto          element = reader.next();
    ASSERT_TRUE(element.has_value());
    EXPECT_TRUE(element->tag() == greeting::tag);

    auto value = element->value().as_bytes();
    auto decoded = greeting::decode(value);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_TRUE(decoded->text == "ahoj");
}

TEST(Integration_Tlvpp, RegistryDynamicDecode) {
    tlv::codec_registry registry;
    registry.register_type<greeting>();

    EXPECT_TRUE(registry.has_decoder(greeting::tag));

    std::array<tlv::byte, 64> buf{};
    tlv::writer<>             w(buf.data(), buf.size(), tlv_format_ber);
    greeting                  g{"cau"};
    auto                      write_result = tlv::write_value(w, g);
    ASSERT_TRUE(write_result.has_value());

    tlv::reader<> reader(tlv::bytes(buf.data(), w.size()), tlv_format_ber);
    auto          element = reader.next();
    ASSERT_TRUE(element.has_value());

    auto value = element->value().as_bytes();
    auto decoded = registry.decode(element->tag(), value);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_TRUE(tlv::any_cast<greeting>(*decoded).text == "cau");
}

} // namespace
