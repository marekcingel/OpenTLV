#include <array>
#include <cassert>
#include <iostream>
#include <string_view>

#include "tlv++/tlv.hpp"

namespace {

int g_failed = 0;

#define CHECK(cond) do { \
    if (!(cond)) { \
        std::cerr << "FAIL: " << #cond << " (" << __FILE__ << ":" << __LINE__ << ")\n"; \
        ++g_failed; \
    } \
} while (0)

tlv::bytes to_bytes(std::string_view s) {
    return tlv::bytes(reinterpret_cast<const std::byte*>(s.data()), s.size());
}

void test_writer_reader_roundtrip() {
    std::array<std::byte, 64> buf{};
    tlv::writer w(buf.data(), buf.size());

    auto r1 = w.write(0x01, to_bytes("hi"));
    CHECK(r1.has_value());
    auto r2 = w.write(0x02, to_bytes("x"));
    CHECK(r2.has_value());

    tlv::reader reader(std::span(buf.data(), w.size()));

    auto e1 = reader.next();
    CHECK(e1.has_value());
    CHECK(e1->tag == 0x01);
    CHECK(e1->value.size() == 2);

    auto e2 = reader.next();
    CHECK(e2.has_value());
    CHECK(e2->tag == 0x02);
    CHECK(e2->value.size() == 1);

    CHECK(reader.at_end());
}

void test_writer_reports_buffer_too_short() {
    std::array<std::byte, 2> buf{};
    tlv::writer w(buf.data(), buf.size());

    auto r = w.write(0x01, to_bytes("abcd"));
    CHECK(!r.has_value());
    CHECK(r.error().code == TLV_ERR_BUFFER_TOO_SHORT);
}

void test_reader_reports_end_of_buffer() {
    std::array<std::byte, 2> buf{ std::byte{0x01}, std::byte{0x00} };
    tlv::reader reader(std::span(buf.data(), buf.size()));

    auto e1 = reader.next();
    CHECK(e1.has_value());
    CHECK(e1->value.empty());

    CHECK(reader.at_end());
    auto e2 = reader.next();
    CHECK(!e2.has_value());
    CHECK(e2.error().code == TLV_ERR_END_OF_BUFFER);
}

// --- Codec concept test ---

struct greeting {
    static constexpr tlv::tag_t tag = 0x10;
    std::string text;

    void encode(std::vector<std::byte>& out) const {
        out.resize(text.size());
        for (size_t i = 0; i < text.size(); ++i) {
            out[i] = static_cast<std::byte>(text[i]);
        }
    }

    static std::expected<greeting, tlv::error> decode(tlv::bytes data) {
        std::string s(reinterpret_cast<const char*>(data.data()), data.size());
        return greeting{s};
    }
};

static_assert(tlv::TlvCodec<greeting>, "greeting must satisfy TlvCodec");

void test_codec_write_via_writer() {
    std::array<std::byte, 64> buf{};
    tlv::writer w(buf.data(), buf.size());

    greeting g{"ahoj"};
    auto r = w.write(g);
    CHECK(r.has_value());

    tlv::reader reader(std::span(buf.data(), w.size()));
    auto entry = reader.next();
    CHECK(entry.has_value());
    CHECK(entry->tag == greeting::tag);

    auto decoded = greeting::decode(entry->value);
    CHECK(decoded.has_value());
    CHECK(decoded->text == "ahoj");
}

void test_registry_dynamic_decode() {
    tlv::codec_registry registry;
    registry.register_type<greeting>();

    CHECK(registry.has_decoder(greeting::tag));

    std::array<std::byte, 64> buf{};
    tlv::writer w(buf.data(), buf.size());
    greeting g{"cau"};
    auto write_result = w.write(g);
    CHECK(write_result.has_value());

    tlv::reader reader(std::span(buf.data(), w.size()));
    auto entry = reader.next();
    CHECK(entry.has_value());

    auto decoded = registry.decode(entry->tag, entry->value);
    CHECK(decoded.has_value());
    CHECK(std::any_cast<greeting>(*decoded).text == "cau");
}

} // namespace

int main() {
    std::cout << "OpenTLV tlv++ tests\n";

    test_writer_reader_roundtrip();
    test_writer_reports_buffer_too_short();
    test_reader_reports_end_of_buffer();
    test_codec_write_via_writer();
    test_registry_dynamic_decode();

    if (g_failed == 0) {
        std::cout << "All tests passed\n";
    } else {
        std::cout << g_failed << " test(s) failed\n";
    }
    return g_failed == 0 ? 0 : 1;
}
