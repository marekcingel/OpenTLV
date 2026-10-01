#include "tlv++/native.hpp"
#include "tlv++/format.hpp"
#include "controlled_format.h"
#include "tlv++/tlv.hpp"
#include "tlv/config.h"
#if OPENTLV_LLDP
#include "tlv++/builtins/lldp/lldp.hpp"
#endif

#include <gtest/gtest.h>

#include <array>
#include <string>
#include <type_traits>

TEST(Unit_Tlvpp, TreeWriterBorrowsStorageAndReportsInitializationErrors) {
    tlv_format_t format = controlled::format;
    format.is_constructed = [](const void*, const tlv_tag_t* tag) {
        return tag->size == 1 && tag->data[0] == 0xE1 ? 1 : 0;
    };
    std::array<tlv::byte, 8> output{}, scratch{};
    tlv::tree_writer_frame   frame{};
    tlv::tree_writer         writer(output.data(), output.size(), format, &frame, 1, scratch.data(),
                                    scratch.size());
    const tlv::element_view  leaf = {tlv::tag_bytes<1>(), tlv::value_view{}};
    ASSERT_TRUE(writer.begin(tlv::tag_bytes<0xE1>()).has_value());
    ASSERT_TRUE(writer.write(leaf).has_value());
    EXPECT_EQ(0u, writer.size());
    EXPECT_FALSE(writer.finish().has_value());
    ASSERT_TRUE(writer.end().has_value());
    EXPECT_EQ(4u, writer.size());
    EXPECT_TRUE(writer.finish().has_value());
    EXPECT_EQ(tlv::byte{0xE1}, output[0]);
    EXPECT_EQ(tlv::byte{2}, output[1]);
    const tlv_format_t invalid{};
    tlv::tree_writer   bad(output.data(), output.size(), invalid, &frame, 1, nullptr, 0);
    EXPECT_FALSE(bad.begin(tlv::tag_bytes<0xE1>()).has_value());
    EXPECT_FALSE(bad.write(leaf).has_value());
    EXPECT_FALSE(bad.end().has_value());
    EXPECT_FALSE(bad.finish().has_value());
    EXPECT_EQ(0u, bad.size());
}

TEST(Unit_Tlvpp, CanonicalWriterMeasuresPreservesAndCopiesIntoCallerStorage) {
    const uint8_t original[] = {0xFF, 1, 0xAB};
    auto          parsed =
        tlv::decode(controlled::format,
                    tlv::bytes(reinterpret_cast<const tlv::byte*>(original), sizeof(original)));
    ASSERT_TRUE(parsed);
    const auto decoded = *parsed;
    auto       required = tlv::encoded_size(decoded.element, controlled::format);
    ASSERT_TRUE(required.has_value());
    EXPECT_EQ(3u, *required);
    std::array<tlv::byte, 9> output{};
    tlv::writer<>            writer(output.data(), output.size(), controlled::format);
    ASSERT_TRUE(writer.write(decoded.element).has_value());
    ASSERT_TRUE(writer.preserve(decoded.source, decoded.element).has_value());
    ASSERT_TRUE(writer.copy_encoded(tlv::bytes(output.data(), 3)).has_value());
    EXPECT_EQ(0u, writer.remaining());
    tlv::writer_diagnostic diagnostic{};
    EXPECT_FALSE(writer.write(decoded.element, &diagnostic).has_value());
    EXPECT_EQ(9u, writer.size());
    EXPECT_EQ(3u, diagnostic.required);
    EXPECT_EQ(9u, diagnostic.diagnostic.offset);
}

#if OPENTLV_LLDP
TEST(Unit_Tlvpp, LldpPresetUsesSharedDescriptor) {
    EXPECT_EQ(&tlv_format_lldp, &tlv::lldp_format());
    const std::array<tlv::byte, 4> wire = {tlv::byte{6}, tlv::byte{2}, tlv::byte{0},
                                           tlv::byte{120}};
    auto result = tlv::decode(tlv::lldp_format(), tlv::bytes(wire.data(), wire.size()));
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE((tlv::tag_bytes<3>() == result->element.tag()));
    EXPECT_EQ(2u, result->element.value().size());
}
#endif

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

static_assert(!std::is_convertible<tlv_element_t, tlv::element_view>::value,
              "C++ semantic imports must be explicit");

TEST(Unit_Tlvpp, AsBytesValidatesAndBorrowsValue) {
    const uint8_t data[] = {0xAA, 0xBB};
    auto          result = tlv::native::borrow_value(tlv_value_t{data, sizeof(data)});
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(reinterpret_cast<const tlv::byte*>(data), result->data());
    EXPECT_EQ(sizeof(data), result->size());
    auto empty = tlv::native::borrow_value(tlv_value_t{nullptr, 0});
    ASSERT_TRUE(empty.has_value());
    EXPECT_TRUE(empty->empty());
    auto invalid = tlv::native::borrow_value(tlv_value_t{nullptr, 1});
    ASSERT_FALSE(invalid.has_value());
    EXPECT_EQ(TLV_ERR_NULL_ARG, invalid.error().code);
#if SIZE_MAX < UINT64_MAX
    auto oversized =
        tlv::native::borrow_value(tlv_value_t{data, static_cast<tlv_size_t>(SIZE_MAX) + 1});
    ASSERT_FALSE(oversized.has_value());
    EXPECT_EQ(TLV_ERR_NATIVE_SIZE, oversized.error().code);
#endif
}

namespace {

tlv::bytes to_bytes(const std::string& s) {
    return tlv::bytes(reinterpret_cast<const tlv::byte*>(s.data()), s.size());
}

TEST(Unit_Tlvpp, WriterReportsBufferTooShort) {
    std::array<tlv::byte, 2> buf{};
    tlv::writer<>            w(buf.data(), buf.size(), controlled::format);

    auto r = w.write(tlv::tag_bytes<0x01>(), to_bytes("abcd"));
    ASSERT_FALSE(r.has_value());
    EXPECT_TRUE(r.error().code == TLV_ERR_BUFFER_TOO_SHORT);
}

TEST(Unit_Tlvpp, ReaderReportsEndOfBuffer) {
    std::array<tlv::byte, 2> buf{{static_cast<tlv::byte>(0x01), static_cast<tlv::byte>(0x00)}};
    tlv::reader<>            reader(tlv::bytes(buf.data(), buf.size()), controlled::format);

    auto e1 = reader.next();
    ASSERT_TRUE(e1.has_value());
    EXPECT_TRUE(e1->value().size() == 0);
    auto decoded = tlv::decode(controlled::format, tlv::bytes(buf.data(), buf.size()));
    ASSERT_TRUE(decoded);
    EXPECT_EQ(1u, decoded->source.length.offset);
    EXPECT_EQ(1u, decoded->source.length.size);
    EXPECT_EQ(0u, decoded->source.data[decoded->source.length.offset]);

    EXPECT_TRUE(reader.at_end());
    auto e2 = reader.next();
    ASSERT_FALSE(e2.has_value());
    EXPECT_TRUE(e2.error().code == TLV_ERR_END_OF_BUFFER);
}

TEST(Unit_Tlvpp, WriterWriteDiagReportsRequiredExceedingAvailableCapacity) {
    std::array<tlv::byte, 1> buf{};
    tlv::writer<>            w(buf.data(), buf.size(), controlled::format);

    tlv::writer_diagnostic diagnostic{};
    auto                   e = w.write(tlv::tag_bytes<0x01>(), to_bytes("ab"), diagnostic);
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
    tlv::reader<>            reader(tlv::bytes(buf.data(), buf.size()), controlled::format);

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

TEST(Unit_Tlvpp, RegistryComparesValidTagBytesAndSize) {
    tlv::codec_registry registry;
    tlv::tag            first = tlv::tag_bytes<0x10>();
    registry.register_decoder(
        first, [](tlv::bytes) -> tlv::expected<tlv::any, tlv::error> { return tlv::any(42); });
    // The same bytes in different memory are the same tag.
    const std::uint8_t same_bytes[] = {0x10};
    tlv::tag           same =
        tlv::tag(tlv::bytes(reinterpret_cast<const tlv::byte*>(same_bytes), sizeof(same_bytes)));
    EXPECT_TRUE(registry.has_decoder(same));
    tlv::tag other = tlv::tag_bytes<0x11>();
    EXPECT_FALSE(registry.has_decoder(other));
    tlv::tag longer = tlv::tag_bytes<0x10, 0x00>();
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
