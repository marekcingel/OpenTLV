// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv++/native.hpp"
#include "tlv++/format.hpp"
#include "tlv++/formats/fixed_format.hpp"
#include "tlv++/tlv.hpp"

#include <gtest/gtest.h>
#include <tlv++/formats/runtime_fixed.hpp>

#include "tlv/formats/fixed.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

TEST(TlvppRuntimeFixed, CopyRebindsConfigurationAndPreservesLtvSemantics) {
    const tlv::runtime_fixed_format copied([] {
        tlv::runtime_fixed_format original(1, 1, tlv::byte_order::big_endian,
                                           tlv::element_order::ltv,
                                           tlv::length_scope::tag_and_value);
        return tlv::runtime_fixed_format(original);
    }());
    auto                            selected = copied.view();
    ASSERT_TRUE(selected);
    const tlv::byte wire[] = {tlv::byte(2), tlv::byte(9), tlv::byte(0x41)};
    auto            decoded = tlv::decode(*selected, {wire, sizeof wire});
    ASSERT_TRUE(decoded);
    EXPECT_EQ(tlv::tag_bytes<9>(), decoded->element.tag());
    EXPECT_EQ(1u, decoded->element.value().size());
    tlv::byte output[3]{};
    auto      written = tlv::encode(*selected, decoded->element, output, sizeof output);
    ASSERT_TRUE(written);
    EXPECT_EQ(sizeof wire, *written);
    EXPECT_EQ(0, std::memcmp(wire, output, sizeof wire));
}

TEST(TlvppRuntimeFixed, RejectsInvalidConfigurationThroughResult) {
    const tlv::runtime_fixed_format invalid(0, 1);
    auto                            selected = invalid.view();
    ASSERT_FALSE(selected);
    EXPECT_EQ(tlv::errc::invalid_argument, selected.error().status());
    const tlv::runtime_fixed_format invalid_order(1, 1, static_cast<tlv::byte_order>(99));
    EXPECT_EQ(tlv::errc::invalid_argument, invalid_order.view().error().status());
}

namespace {

constexpr tlv::byte_order BE = tlv::byte_order::big_endian;
constexpr tlv::byte_order LE = tlv::byte_order::little_endian;

tlv::bytes to_bytes(const std::string& s) {
    return tlv::bytes(reinterpret_cast<const tlv::byte*>(s.data()), s.size());
}

// Owns the bytes of a tag, which tlv::tag only borrows. A temporary is valid
// for the full expression it appears in; keep a named object for longer uses.
struct owned_tag {
    std::array<std::uint8_t, 16> bytes{};
    std::size_t                  size = 0;

    operator tlv::tag() const {
        return tlv::tag(tlv::bytes(reinterpret_cast<const tlv::byte*>(bytes.data()), size));
    }
};

owned_tag make_tag(std::size_t width) {
    owned_tag tag;
    tag.size = width;
    for (std::size_t i = 0; i < width; ++i) tag.bytes[i] = static_cast<std::uint8_t>(0xA1 + i);
    return tag;
}

// Encodes one element, checks the exact wire layout, then reads it back.
template <std::size_t T, std::size_t L, tlv::byte_order O> void check_layout_and_round_trip() {
    using format = tlv::fixed_format<T, L, O>;
    SCOPED_TRACE(std::to_string(T) + "/" + std::to_string(L) + (O == BE ? "/BE" : "/LE"));

    const std::string         value = "abc";
    std::array<tlv::byte, 32> buf{};
    tlv::writer<>             w(buf.data(), buf.size(), format::view());
    ASSERT_TRUE(w.write(make_tag(T), to_bytes(value)).has_value());
    ASSERT_EQ(w.size(), T + L + value.size());

    const owned_tag expected_owner = make_tag(T);
    const tlv::tag  expected_tag = expected_owner;
    for (std::size_t i = 0; i < T; ++i) {
        EXPECT_EQ(buf[i], expected_tag.data()[i]);
    }
    for (std::size_t i = 0; i < L; ++i) {
        const std::size_t  index = O == BE ? i : L - 1 - i;
        const std::uint8_t expected = i == L - 1 ? static_cast<std::uint8_t>(value.size()) : 0;
        EXPECT_EQ(static_cast<std::uint8_t>(buf[T + index]), expected);
    }

    tlv::reader<> reader(tlv::bytes(buf.data(), w.size()), format::view());
    auto          element = reader.next();
    ASSERT_TRUE(element.has_value());
    EXPECT_EQ(element->tag().size(), T);
    for (std::size_t i = 0; i < T; ++i) EXPECT_EQ(element->tag().data()[i], expected_tag.data()[i]);
    ASSERT_EQ(element->value().size(), value.size());
    // Zero-copy: the value points into the input buffer.
    EXPECT_EQ(element->value().data(), buf.data() + T + L);
    EXPECT_TRUE(reader.at_end());
}

TEST(Unit_Tlvpp_FixedFormat, SupportedConfigurationsRoundTrip) {
    check_layout_and_round_trip<1, 1, BE>();
    check_layout_and_round_trip<1, 1, LE>();
    check_layout_and_round_trip<2, 2, BE>();
    check_layout_and_round_trip<2, 2, LE>();
    check_layout_and_round_trip<1, 3, BE>();
    check_layout_and_round_trip<1, 3, LE>();
    check_layout_and_round_trip<4, 4, BE>();
    check_layout_and_round_trip<4, 4, LE>();
    check_layout_and_round_trip<3, 8, BE>();
    check_layout_and_round_trip<3, 8, LE>();
    // Tags longer than the built-in formats accept work as well.
    check_layout_and_round_trip<8, 2, BE>();
    check_layout_and_round_trip<12, 2, LE>();
}

TEST(Unit_Tlvpp_FixedFormat, LengthByteOrderDoesNotChangeTheTag) {
    // 300 = 0x012C needs two length bytes and makes the order visible.
    const std::string          value(300, 'x');
    std::array<tlv::byte, 320> be{};
    std::array<tlv::byte, 320> le{};
    using be_format = tlv::fixed_format<2, 2, BE>;
    using le_format = tlv::fixed_format<2, 2, LE>;
    tlv::writer<> wb(be.data(), be.size(), be_format::view());
    tlv::writer<> wl(le.data(), le.size(), le_format::view());
    ASSERT_TRUE(wb.write(make_tag(2), to_bytes(value)).has_value());
    ASSERT_TRUE(wl.write(make_tag(2), to_bytes(value)).has_value());

    EXPECT_EQ(static_cast<std::uint8_t>(be[0]), 0xA1);
    EXPECT_EQ(static_cast<std::uint8_t>(be[1]), 0xA2);
    EXPECT_EQ(static_cast<std::uint8_t>(le[0]), 0xA1);
    EXPECT_EQ(static_cast<std::uint8_t>(le[1]), 0xA2);
    EXPECT_EQ(static_cast<std::uint8_t>(be[2]), 0x01);
    EXPECT_EQ(static_cast<std::uint8_t>(be[3]), 0x2C);
    EXPECT_EQ(static_cast<std::uint8_t>(le[2]), 0x2C);
    EXPECT_EQ(static_cast<std::uint8_t>(le[3]), 0x01);
}

TEST(Unit_Tlvpp_FixedFormat, DescriptorHasStaticStorageAndAMatchingContext) {
    using format = tlv::fixed_format<1, 2, BE>;
    EXPECT_EQ(&tlv::native::descriptor(format::view()), &tlv::native::descriptor(format::view()));
    ASSERT_NE(tlv::native::descriptor(format::view()).context, nullptr);
    const auto* config =
        static_cast<const tlv_fixed_format_t*>(tlv::native::descriptor(format::view()).context);
    EXPECT_EQ(config->identifier.size, 1u);
    EXPECT_EQ(config->length.size, 2u);
    EXPECT_EQ(config->length.byte_order, static_cast<tlv_byte_order_t>(BE));
    EXPECT_NE(tlv::native::descriptor(format::view()).decode, nullptr);
    EXPECT_NE(tlv::native::descriptor(format::view()).encode, nullptr);
    EXPECT_NE(
        static_cast<const void*>(&tlv::native::descriptor(format::view())),
        static_cast<const void*>(&tlv::native::descriptor(tlv::fixed_format<1, 2, LE>::view())));
}

// Proves the C++ template reuses the C implementation's callbacks directly
// (identical function pointers), rather than an independent C++
// implementation that merely produces equivalent wire bytes.
TEST(Unit_Tlvpp_FixedFormat, DelegatesToTheSameCImplementationAsARuntimeConfig) {
    using format = tlv::fixed_format<2, 3, LE>;
    const tlv_fixed_format_t c_config = {
        {2}, {3, static_cast<tlv_byte_order_t>(LE)}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
    tlv_format_t c_format{};
    ASSERT_EQ(TLV_OK, tlv_fixed_format_init(&c_format, &c_config));

    const tlv_format_t& cpp_format = tlv::native::descriptor(format::view());
    EXPECT_EQ(cpp_format.decode, c_format.decode);
    EXPECT_EQ(cpp_format.measure, c_format.measure);
    EXPECT_EQ(cpp_format.encode, c_format.encode);
}

TEST(Unit_Tlvpp_FixedFormat, LengthRangeBoundaries) {
    std::size_t size = 0;

    const tlv_format_t& w1 = tlv::native::descriptor(tlv::fixed_format<1, 1, BE>::view());
    EXPECT_EQ(tlv_encoded_size(TLV_TAG(1), 0, &w1, &size), TLV_OK);
    EXPECT_EQ(size, 2u);
    EXPECT_EQ(tlv_encoded_size(TLV_TAG(1), 255, &w1, &size), TLV_OK);
    EXPECT_EQ(tlv_encoded_size(TLV_TAG(1), 256, &w1, &size), TLV_ERR_INVALID_LENGTH);

    const tlv_format_t& w2 = tlv::native::descriptor(tlv::fixed_format<1, 2, LE>::view());
    EXPECT_EQ(tlv_encoded_size(TLV_TAG(1), 65535, &w2, &size), TLV_OK);
    EXPECT_EQ(size, 65538u);
    EXPECT_EQ(tlv_encoded_size(TLV_TAG(1), 65536, &w2, &size), TLV_ERR_INVALID_LENGTH);

    const tlv_format_t& w3 = tlv::native::descriptor(tlv::fixed_format<1, 3, BE>::view());
    EXPECT_EQ(tlv_encoded_size(TLV_TAG(1), 0xFFFFFF, &w3, &size), TLV_OK);
    EXPECT_EQ(tlv_encoded_size(TLV_TAG(1), 0x1000000, &w3, &size), TLV_ERR_INVALID_LENGTH);

    using width1 = tlv::fixed_format<1, 1, BE>;
    using width4 = tlv::fixed_format<1, 4, BE>;
    using width8 = tlv::fixed_format<1, 8, BE>;
    EXPECT_EQ(width1::max_length, 0xFFu);
    EXPECT_EQ(width4::max_length, 0xFFFFFFFFu);
    EXPECT_EQ(width8::max_length, ~static_cast<std::uint64_t>(0));

#if SIZE_MAX > 0xFFFFFFFFu
    const tlv_format_t& w4 = tlv::native::descriptor(tlv::fixed_format<1, 4, BE>::view());
    EXPECT_EQ(tlv_encoded_size(TLV_TAG(1), 0xFFFFFFFFu, &w4, &size), TLV_OK);
    EXPECT_EQ(tlv_encoded_size(TLV_TAG(1), static_cast<std::size_t>(0xFFFFFFFFu) + 1, &w4, &size),
              TLV_ERR_INVALID_LENGTH);
#endif
}

TEST(Unit_Tlvpp_FixedFormat, MaximumEncodableLengthRoundTrips) {
    // One-byte length: 255 is the largest value; 256 must be rejected by the writer.
    std::vector<tlv::byte> buf(2 + 255);
    tlv::writer<>          w(buf.data(), buf.size(), tlv::fixed_format<1, 1, BE>::view());
    const std::string      max_value(255, 'm');
    ASSERT_TRUE(w.write(make_tag(1), to_bytes(max_value)).has_value());
    EXPECT_EQ(static_cast<std::uint8_t>(buf[1]), 255);

    tlv::reader<> reader(tlv::bytes(buf.data(), w.size()), tlv::fixed_format<1, 1, BE>::view());
    auto          element = reader.next();
    ASSERT_TRUE(element.has_value());
    EXPECT_EQ(element->value().size(), 255u);

    std::vector<tlv::byte> too_big(2 + 256);
    tlv::writer<>          w2(too_big.data(), too_big.size(), tlv::fixed_format<1, 1, BE>::view());
    auto                   r = w2.write(make_tag(1), to_bytes(std::string(256, 'x')));
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().status(), tlv::errc::invalid_length);
    EXPECT_EQ(w2.size(), 0u);
}

TEST(Unit_Tlvpp_FixedFormat, EmptyValueRoundTrips) {
    std::array<tlv::byte, 8> buf{};
    tlv::writer<>            w(buf.data(), buf.size(), tlv::fixed_format<2, 2, LE>::view());
    ASSERT_TRUE(w.write(make_tag(2), tlv::bytes()).has_value());
    EXPECT_EQ(w.size(), 4u);

    tlv::reader<> reader(tlv::bytes(buf.data(), w.size()), tlv::fixed_format<2, 2, LE>::view());
    auto          element = reader.next();
    ASSERT_TRUE(element.has_value());
    EXPECT_EQ(element->value().size(), 0u);
}

TEST(Unit_Tlvpp_FixedFormat, TruncatedInputIsRejected) {
    using format = tlv::fixed_format<2, 2, BE>;
    // tag(2) length(2)=3 value(3)
    const std::array<std::uint8_t, 7> full = {0x01, 0x02, 0x00, 0x03, 'a', 'b', 'c'};
    for (std::size_t size = 1; size < full.size(); ++size) {
        SCOPED_TRACE(size);
        tlv::reader<> reader(tlv::bytes(reinterpret_cast<const tlv::byte*>(full.data()), size),
                             format::view());
        auto          element = reader.next();
        ASSERT_FALSE(element.has_value());
        EXPECT_EQ(element.error().status(), tlv::errc::truncated);
    }
}

TEST(Unit_Tlvpp_FixedFormat, DecodeReportsTheTruncatedField) {
    using format = tlv::fixed_format<2, 3, LE>;
    const uint8_t      data[] = {1, 2, 1, 2, 3};
    tlv_decoded_t      decoded{};
    tlv_format_error_t error{};
    EXPECT_EQ(TLV_ERR_TRUNCATED, tlv_format_decode(&tlv::native::descriptor(format::view()), data,
                                                   1, &decoded, &error));
    EXPECT_EQ(TLV_REGION_TAG, error.region);
    EXPECT_EQ(TLV_ERR_TRUNCATED, tlv_format_decode(&tlv::native::descriptor(format::view()), data,
                                                   4, &decoded, &error));
    EXPECT_EQ(TLV_REGION_LENGTH, error.region);
    EXPECT_EQ(2u, error.offset);
    EXPECT_EQ(TLV_ERR_TRUNCATED, tlv_format_decode(&tlv::native::descriptor(format::view()), data,
                                                   5, &decoded, &error));
    EXPECT_EQ(TLV_REGION_VALUE, error.region);
    EXPECT_EQ(0x030201u, error.required);
}

TEST(Unit_Tlvpp_FixedFormat, InsufficientOutputCapacityIsReported) {
    using format = tlv::fixed_format<2, 2, BE>;
    // The element needs 2 + 2 + 3 = 7 bytes.
    for (std::size_t capacity = 0; capacity < 7; ++capacity) {
        SCOPED_TRACE(capacity);
        std::array<tlv::byte, 8> buf{};
        tlv::writer<>            w(buf.data(), capacity, format::view());
        auto                     r = w.write(make_tag(2), to_bytes("abc"));
        ASSERT_FALSE(r.has_value());
        EXPECT_EQ(r.error().status(), tlv::errc::buffer_too_short);
        EXPECT_EQ(w.size(), 0u);
    }
}

TEST(Unit_Tlvpp_FixedFormat, LogicalMeasureAndEncodingUseTheSameFraming) {
    using format = tlv::fixed_format<2, 2, BE>;
    const uint8_t       value[] = {1, 2, 3};
    const tlv_element_t element = {TLV_TAG(1, 2), {value, sizeof(value)}};
    tlv_encoding_t      sizes{};
    ASSERT_EQ(TLV_OK, tlv_format_measure(&tlv::native::descriptor(format::view()), &element, &sizes,
                                         nullptr));
    EXPECT_EQ(4u, sizes.header);
    EXPECT_EQ(3u, sizes.value);
    EXPECT_EQ(7u, sizes.total);
    uint8_t output[7] = {};
    size_t  written = 99;
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_format_encode(&tlv::native::descriptor(format::view()),
                                                          &element, output, 6, &written, nullptr));
    EXPECT_EQ(7u, written);
    EXPECT_EQ(TLV_OK, tlv_format_encode(&tlv::native::descriptor(format::view()), &element, output,
                                        7, &written, nullptr));
}

TEST(Unit_Tlvpp_FixedFormat, TagSizeMustMatchTheConfiguredWidth) {
    using format = tlv::fixed_format<2, 1, BE>;
    std::array<tlv::byte, 16> buf{};
    tlv::writer<>             w(buf.data(), buf.size(), format::view());

    for (std::size_t width : {std::size_t(1), std::size_t(3)}) {
        auto r = w.write(make_tag(width), to_bytes("a"));
        ASSERT_FALSE(r.has_value());
        EXPECT_EQ(r.error().status(), tlv::errc::invalid_tag_size);
    }
    EXPECT_EQ(w.size(), 0u);
}

TEST(Unit_Tlvpp_FixedFormat, MultipleElementsInSequence) {
    using format = tlv::fixed_format<1, 2, LE>;
    std::array<tlv::byte, 32> buf{};
    tlv::writer<>             w(buf.data(), buf.size(), format::view());
    ASSERT_TRUE(w.write(make_tag(1), to_bytes("ab")).has_value());
    ASSERT_TRUE(w.write(make_tag(1), to_bytes("cde")).has_value());
    EXPECT_EQ(w.size(), (1u + 2 + 2) + (1 + 2 + 3));

    tlv::reader<> reader(tlv::bytes(buf.data(), w.size()), format::view());
    auto          first = reader.next();
    auto          second = reader.next();
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(first->value().size(), 2u);
    EXPECT_EQ(second->value().size(), 3u);
    EXPECT_TRUE(reader.at_end());
}

TEST(Unit_Tlvpp_FixedFormat, WorksWithTheCApi) {
    using format = tlv::fixed_format<1, 2, BE>;
    std::uint8_t       buf[16] = {};
    const std::uint8_t value[2] = {0xDE, 0xAD};
    const tlv_tag_t    tag = TLV_TAG(0x10);
    size_t             written = 0;
    ASSERT_EQ(tlv_write(buf, sizeof(buf), &tlv::native::descriptor(format::view()), tag, value,
                        sizeof(value), &written),
              TLV_OK);
    const std::uint8_t expected[] = {0x10, 0x00, 0x02, 0xDE, 0xAD};
    ASSERT_EQ(written, sizeof(expected));
    EXPECT_EQ(std::vector<std::uint8_t>(buf, buf + written),
              std::vector<std::uint8_t>(expected, expected + sizeof(expected)));

    tlv_element_t element;
    size_t        consumed = 0;
    ASSERT_EQ(tlv_read(buf, written, &tlv::native::descriptor(format::view()), &element, &consumed),
              TLV_OK);
    EXPECT_EQ(consumed, written);
    EXPECT_EQ(element.value.data, buf + 3);
}

TEST(Unit_Tlvpp_FixedFormat, OneByteConfigurationMatchesTheCApi) {
    using format = tlv::fixed_format<1, 1, BE>;
    const tlv_fixed_format_t c_config = {
        {1}, {1, TLV_BYTE_ORDER_BIG_ENDIAN}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
    tlv_format_t c_writer{};
    ASSERT_EQ(TLV_OK, tlv_fixed_format_init(&c_writer, &c_config));
    for (std::size_t length : {std::size_t(0), std::size_t(1), std::size_t(255)}) {
        SCOPED_TRACE(length);
        std::vector<std::uint8_t> value(length, 0x5A);
        std::uint8_t              expected[300] = {};
        std::uint8_t              actual[300] = {};
        const tlv_tag_t           tag = TLV_TAG(0x7F);
        size_t                    expected_size = 0, actual_size = 0;

        ASSERT_EQ(tlv_write(expected, sizeof(expected), &c_writer, tag, value.data(), value.size(),
                            &expected_size),
                  TLV_OK);
        ASSERT_EQ(tlv_write(actual, sizeof(actual), &tlv::native::descriptor(format::view()), tag,
                            value.data(), value.size(), &actual_size),
                  TLV_OK);
        ASSERT_EQ(actual_size, expected_size);
        EXPECT_EQ(std::vector<std::uint8_t>(actual, actual + actual_size),
                  std::vector<std::uint8_t>(expected, expected + expected_size));
    }
    std::size_t size = 0;
    EXPECT_EQ(tlv_encoded_size(TLV_TAG(1), 256, &tlv::native::descriptor(format::view()), &size),
              tlv_encoded_size(TLV_TAG(1), 256, &c_writer, &size));
}

// Unlike the compile-time tlv::fixed_format<>, a runtime-configurable
// tlv_fixed_format_t needs no tlv++ wrapper: tlv::writer<>/tlv::reader<> already
// accept a plain `const tlv_format_t&`. See
// docs/guides/memory.md#format-context-ownership-and-lifetime.
TEST(Unit_Tlvpp_FixedFormat, ReaderAndWriterAcceptARuntimeCDescriptor) {
    const tlv_fixed_format_t config = {
        {2}, {1, TLV_BYTE_ORDER_BIG_ENDIAN}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
    tlv_format_t format{};
    ASSERT_EQ(TLV_OK, tlv_fixed_format_init(&format, &config));

    std::array<tlv::byte, 16> buf{};
    tlv::writer<>             writer(buf.data(), buf.size(), tlv::native::borrow_format(format));
    const std::array<tlv::byte, 3> value = {tlv::byte(0xAA), tlv::byte(0xBB), tlv::byte(0xCC)};
    ASSERT_TRUE(writer.write(tlv::tag_bytes<0x12, 0x34>(), tlv::bytes(value.data(), value.size())));

    tlv::reader<> reader(tlv::bytes(buf.data(), writer.size()), tlv::native::borrow_format(format));
    auto          element = reader.next();
    ASSERT_TRUE(element.has_value());
    EXPECT_EQ(element->tag().size(), 2u);
    EXPECT_EQ(element->value().size(), value.size());
    EXPECT_TRUE(reader.at_end());
}

#if SIZE_MAX < UINT64_MAX
TEST(Unit_Tlvpp_FixedFormat, LogicalSizingExceedsNativeAddressSpace) {
    using format = tlv::fixed_format<1, 8, BE>;
    const tlv_element_t element = {TLV_TAG(1), {nullptr, UINT64_C(0x0100000000000000)}};
    tlv_encoding_t      encoding{};
    ASSERT_EQ(TLV_OK, tlv_format_measure(&tlv::native::descriptor(format::view()), &element,
                                         &encoding, nullptr));
    EXPECT_EQ(element.value.size + 9, encoding.total);
}
#endif

} // namespace

TEST(Unit_Tlvpp_FormatContract, SourceAndSemanticOperationsAreDistinct) {
    const uint8_t wire[] = {1, 1, 42};
    const auto&   format =
        tlv::native::descriptor(tlv::fixed_format<1, 1, tlv::byte_order::big_endian>::view());
    auto decoded = tlv::decode(tlv::native::borrow_format(format),
                               tlv::bytes(reinterpret_cast<const tlv::byte*>(wire), sizeof(wire)));
    ASSERT_TRUE(decoded);
    auto sizes = tlv::measure(tlv::native::borrow_format(format), decoded->element);
    ASSERT_TRUE(sizes);
    EXPECT_EQ(sizeof(wire), sizes->total);
    tlv::byte output[3]{};
    auto      copied = tlv::preserve(decoded->source, decoded->element, output, sizeof(output));
    ASSERT_TRUE(copied);
    EXPECT_EQ(sizeof(wire), *copied);
    const uint8_t changed = 7;
    decoded->element = tlv::element_view(
        decoded->element.tag(),
        tlv::value_view(tlv::bytes(reinterpret_cast<const tlv::byte*>(&changed), 1)));
    EXPECT_FALSE(tlv::preserve(decoded->source, decoded->element, output, sizeof(output)));
    EXPECT_TRUE(
        tlv::encode(tlv::native::borrow_format(format), decoded->element, output, sizeof(output)));
}
