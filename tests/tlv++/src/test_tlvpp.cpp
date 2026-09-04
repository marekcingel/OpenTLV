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
static_assert(std::is_same<tlv::span<int>, std::span<int>>::value,
              "C++20 must use std::span");
#endif
#if defined(__cpp_lib_expected) && __cpp_lib_expected >= 202202L
static_assert(std::is_same<tlv::expected<int, int>, std::expected<int, int>>::value,
              "C++23 must use std::expected");
#endif

namespace {

tlv::bytes to_bytes(const std::string &s) {
  return tlv::bytes(reinterpret_cast<const tlv::byte *>(s.data()), s.size());
}

TEST(TLV_CPP, test_writer_reader_roundtrip) {
  std::array<tlv::byte, 64> buf{};
  tlv::writer w(buf.data(), buf.size());

  auto r1 = w.write(0x01, to_bytes("hi"));
  ASSERT_TRUE(r1.has_value());
  auto r2 = w.write(0x02, to_bytes("x"));
  ASSERT_TRUE(r2.has_value());

  tlv::reader reader(tlv::bytes(buf.data(), w.size()));

  auto e1 = reader.next();
  ASSERT_TRUE(e1.has_value());
  EXPECT_TRUE(e1->tag == 0x01);
  EXPECT_TRUE(e1->value.size() == 2);

  auto e2 = reader.next();
  ASSERT_TRUE(e2.has_value());
  EXPECT_TRUE(e2->tag == 0x02);
  EXPECT_TRUE(e2->value.size() == 1);

  EXPECT_TRUE(reader.at_end());
}

TEST(TLV_CPP, test_writer_reports_buffer_too_short) {
  std::array<tlv::byte, 2> buf{};
  tlv::writer w(buf.data(), buf.size());

  auto r = w.write(0x01, to_bytes("abcd"));
  ASSERT_FALSE(r.has_value());
  EXPECT_TRUE(r.error().code == TLV_ERR_BUFFER_TOO_SHORT);
}

TEST(TLV_CPP, test_reader_reports_end_of_buffer) {
  std::array<tlv::byte, 2> buf{{static_cast<tlv::byte>(0x01), static_cast<tlv::byte>(0x00)}};
  tlv::reader reader(tlv::bytes(buf.data(), buf.size()));

  auto e1 = reader.next();
  ASSERT_TRUE(e1.has_value());
  EXPECT_TRUE(e1->value.empty());

  EXPECT_TRUE(reader.at_end());
  auto e2 = reader.next();
  ASSERT_FALSE(e2.has_value());
  EXPECT_TRUE(e2.error().code == TLV_ERR_END_OF_BUFFER);
}

// --- Codec concept test ---

struct greeting {
  static constexpr tlv::tag_t tag = 0x10;
  std::string text;

  void encode(std::vector<tlv::byte> &out) const {
    out.resize(text.size());
    for (size_t i = 0; i < text.size(); ++i) {
      out[i] = static_cast<tlv::byte>(text[i]);
    }
  }

  static tlv::expected<greeting, tlv::error> decode(tlv::bytes data) {
    std::string s(reinterpret_cast<const char *>(data.data()), data.size());
    return greeting{s};
  }
};

static_assert(tlv::is_tlv_codec<greeting>::value, "greeting must satisfy TLV codec interface");

TEST(TLV_CPP, test_codec_write_via_writer) {
  std::array<tlv::byte, 64> buf{};
  tlv::writer w(buf.data(), buf.size());

  greeting g{"ahoj"};
  auto r = w.write(g);
  ASSERT_TRUE(r.has_value());

  tlv::reader reader(tlv::bytes(buf.data(), w.size()));
  auto entry = reader.next();
  ASSERT_TRUE(entry.has_value());
  EXPECT_TRUE(entry->tag == greeting::tag);

  auto decoded = greeting::decode(entry->value);
  ASSERT_TRUE(decoded.has_value());
  EXPECT_TRUE(decoded->text == "ahoj");
}

TEST(TLV_CPP, test_registry_dynamic_decode) {
  tlv::codec_registry registry;
  registry.register_type<greeting>();

  EXPECT_TRUE(registry.has_decoder(greeting::tag));

  std::array<tlv::byte, 64> buf{};
  tlv::writer w(buf.data(), buf.size());
  greeting g{"cau"};
  auto write_result = w.write(g);
  ASSERT_TRUE(write_result.has_value());

  tlv::reader reader(tlv::bytes(buf.data(), w.size()));
  auto entry = reader.next();
  ASSERT_TRUE(entry.has_value());

  auto decoded = registry.decode(entry->tag, entry->value);
  ASSERT_TRUE(decoded.has_value());
  EXPECT_TRUE(tlv::any_cast<greeting>(*decoded).text == "cau");
}

} // namespace
