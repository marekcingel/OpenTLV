#include "tlv++/builtins/fixed/fixed_format.hpp"
#include "tlv++/tlv.hpp"

#include <gtest/gtest.h>

#if OPENTLV_FORMAT_FIXED_1BYTE
#include "tlv/builtins/fixed/fixed_1byte.h"
#endif

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace {

constexpr tlv_byte_order_t BE = TLV_BYTE_ORDER_BIG_ENDIAN;
constexpr tlv_byte_order_t LE = TLV_BYTE_ORDER_LITTLE_ENDIAN;

tlv::bytes to_bytes(const std::string& s) {
    return tlv::bytes(reinterpret_cast<const tlv::byte*>(s.data()), s.size());
}

// Owns the bytes of a tag, which tlv::tag_t only borrows. A temporary is valid
// for the full expression it appears in; keep a named object for longer uses.
struct owned_tag {
    std::array<std::uint8_t, 16> bytes{};
    std::size_t                  size = 0;

    operator tlv::tag_t() const {
        return tlv_tag(bytes.data(), size);
    }
};

owned_tag make_tag(std::size_t width) {
    owned_tag tag;
    tag.size = width;
    for (std::size_t i = 0; i < width; ++i) tag.bytes[i] = static_cast<std::uint8_t>(0xA1 + i);
    return tag;
}

// Encodes one element, checks the exact wire layout, then reads it back.
template <std::size_t T, std::size_t L, tlv_byte_order_t O> void check_layout_and_round_trip() {
    using format = tlv::fixed_format<T, L, O>;
    SCOPED_TRACE(std::to_string(T) + "/" + std::to_string(L) + (O == BE ? "/BE" : "/LE"));

    const std::string         value = "abc";
    std::array<tlv::byte, 32> buf{};
    tlv::writer               w(buf.data(), buf.size(), format::writer());
    ASSERT_TRUE(w.write(make_tag(T), to_bytes(value)).has_value());
    ASSERT_EQ(w.size(), T + L + value.size());

    const owned_tag  expected_owner = make_tag(T);
    const tlv::tag_t expected_tag = expected_owner;
    for (std::size_t i = 0; i < T; ++i) {
        EXPECT_EQ(static_cast<std::uint8_t>(buf[i]), expected_tag.data[i]);
    }
    for (std::size_t i = 0; i < L; ++i) {
        const std::size_t  index = O == BE ? i : L - 1 - i;
        const std::uint8_t expected = i == L - 1 ? static_cast<std::uint8_t>(value.size()) : 0;
        EXPECT_EQ(static_cast<std::uint8_t>(buf[T + index]), expected);
    }

    tlv::reader reader(tlv::bytes(buf.data(), w.size()), format::reader());
    auto        entry = reader.next();
    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(entry->tag.size, T);
    for (std::size_t i = 0; i < T; ++i) EXPECT_EQ(entry->tag.data[i], expected_tag.data[i]);
    ASSERT_EQ(entry->value.size(), value.size());
    // Zero-copy: the value points into the input buffer.
    EXPECT_EQ(entry->value.data(), buf.data() + T + L);
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
    tlv::writer wb(be.data(), be.size(), be_format::writer());
    tlv::writer wl(le.data(), le.size(), le_format::writer());
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

TEST(Unit_Tlvpp_FixedFormat, DescriptorsHaveStaticStorageAndNoContext) {
    using format = tlv::fixed_format<1, 2, BE>;
    EXPECT_EQ(&format::reader(), &format::reader());
    EXPECT_EQ(&format::writer(), &format::writer());
    EXPECT_EQ(format::reader().context, nullptr);
    EXPECT_EQ(format::writer().context, nullptr);
    EXPECT_EQ(format::reader().read_element, nullptr);
    EXPECT_EQ(format::writer().write_header, nullptr);
    EXPECT_NE(static_cast<const void*>(&format::reader()),
              static_cast<const void*>(&tlv::fixed_format<1, 2, LE>::reader()));
}

TEST(Unit_Tlvpp_FixedFormat, LengthRangeBoundaries) {
    std::size_t size = 0;

    const tlv_writer_format_t& w1 = tlv::fixed_format<1, 1, BE>::writer();
    EXPECT_EQ(w1.length_size(nullptr, 0, &size), TLV_OK);
    EXPECT_EQ(size, 1u);
    EXPECT_EQ(w1.length_size(nullptr, 255, &size), TLV_OK);
    EXPECT_EQ(w1.length_size(nullptr, 256, &size), TLV_ERR_INVALID_LENGTH);

    const tlv_writer_format_t& w2 = tlv::fixed_format<1, 2, LE>::writer();
    EXPECT_EQ(w2.length_size(nullptr, 65535, &size), TLV_OK);
    EXPECT_EQ(size, 2u);
    EXPECT_EQ(w2.length_size(nullptr, 65536, &size), TLV_ERR_INVALID_LENGTH);

    const tlv_writer_format_t& w3 = tlv::fixed_format<1, 3, BE>::writer();
    EXPECT_EQ(w3.length_size(nullptr, 0xFFFFFF, &size), TLV_OK);
    EXPECT_EQ(w3.length_size(nullptr, 0x1000000, &size), TLV_ERR_INVALID_LENGTH);

    using width1 = tlv::fixed_format<1, 1, BE>;
    using width4 = tlv::fixed_format<1, 4, BE>;
    using width8 = tlv::fixed_format<1, 8, BE>;
    EXPECT_EQ(width1::max_length, 0xFFu);
    EXPECT_EQ(width4::max_length, 0xFFFFFFFFu);
    EXPECT_EQ(width8::max_length, ~static_cast<std::uint64_t>(0));

#if SIZE_MAX > 0xFFFFFFFFu
    const tlv_writer_format_t& w4 = tlv::fixed_format<1, 4, BE>::writer();
    EXPECT_EQ(w4.length_size(nullptr, 0xFFFFFFFFu, &size), TLV_OK);
    EXPECT_EQ(w4.length_size(nullptr, static_cast<std::size_t>(0xFFFFFFFFu) + 1, &size),
              TLV_ERR_INVALID_LENGTH);
#endif
}

TEST(Unit_Tlvpp_FixedFormat, MaximumEncodableLengthRoundTrips) {
    // One-byte length: 255 is the largest value; 256 must be rejected by the writer.
    std::vector<tlv::byte> buf(2 + 255);
    tlv::writer            w(buf.data(), buf.size(), tlv::fixed_format<1, 1, BE>::writer());
    const std::string      max_value(255, 'm');
    ASSERT_TRUE(w.write(make_tag(1), to_bytes(max_value)).has_value());
    EXPECT_EQ(static_cast<std::uint8_t>(buf[1]), 255);

    tlv::reader reader(tlv::bytes(buf.data(), w.size()), tlv::fixed_format<1, 1, BE>::reader());
    auto        entry = reader.next();
    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(entry->value.size(), 255u);

    std::vector<tlv::byte> too_big(2 + 256);
    tlv::writer w2(too_big.data(), too_big.size(), tlv::fixed_format<1, 1, BE>::writer());
    auto        r = w2.write(make_tag(1), to_bytes(std::string(256, 'x')));
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, TLV_ERR_INVALID_LENGTH);
    EXPECT_EQ(w2.size(), 0u);
}

TEST(Unit_Tlvpp_FixedFormat, EmptyValueRoundTrips) {
    std::array<tlv::byte, 8> buf{};
    tlv::writer              w(buf.data(), buf.size(), tlv::fixed_format<2, 2, LE>::writer());
    ASSERT_TRUE(w.write(make_tag(2), tlv::bytes()).has_value());
    EXPECT_EQ(w.size(), 4u);

    tlv::reader reader(tlv::bytes(buf.data(), w.size()), tlv::fixed_format<2, 2, LE>::reader());
    auto        entry = reader.next();
    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(entry->value.size(), 0u);
}

TEST(Unit_Tlvpp_FixedFormat, TruncatedInputIsRejected) {
    using format = tlv::fixed_format<2, 2, BE>;
    // tag(2) length(2)=3 value(3)
    const std::array<std::uint8_t, 7> full = {0x01, 0x02, 0x00, 0x03, 'a', 'b', 'c'};
    for (std::size_t size = 1; size < full.size(); ++size) {
        SCOPED_TRACE(size);
        tlv::reader reader(tlv::bytes(reinterpret_cast<const tlv::byte*>(full.data()), size),
                           format::reader());
        auto        entry = reader.next();
        ASSERT_FALSE(entry.has_value());
        EXPECT_EQ(entry.error().code, TLV_ERR_BUFFER_TOO_SHORT);
    }
}

TEST(Unit_Tlvpp_FixedFormat, ReaderCallbacksReportShortFields) {
    using format = tlv::fixed_format<2, 3, LE>;
    const std::uint8_t data[3] = {1, 2, 3};
    tlv_tag_t          tag;
    std::size_t        length = 0, consumed = 0;

    EXPECT_EQ(format::reader().read_tag(nullptr, data, 1, &tag, &consumed),
              TLV_ERR_BUFFER_TOO_SHORT);
    EXPECT_EQ(format::reader().read_tag(nullptr, data, 2, &tag, &consumed), TLV_OK);
    EXPECT_EQ(consumed, 2u);
    EXPECT_EQ(format::reader().read_length(nullptr, data, 2, &length, &consumed),
              TLV_ERR_BUFFER_TOO_SHORT);
    EXPECT_EQ(format::reader().read_length(nullptr, data, 3, &length, &consumed), TLV_OK);
    EXPECT_EQ(consumed, 3u);
    EXPECT_EQ(length, 0x030201u);
}

TEST(Unit_Tlvpp_FixedFormat, InsufficientOutputCapacityIsReported) {
    using format = tlv::fixed_format<2, 2, BE>;
    // The element needs 2 + 2 + 3 = 7 bytes.
    for (std::size_t capacity = 0; capacity < 7; ++capacity) {
        SCOPED_TRACE(capacity);
        std::array<tlv::byte, 8> buf{};
        tlv::writer              w(buf.data(), capacity, format::writer());
        auto                     r = w.write(make_tag(2), to_bytes("abc"));
        ASSERT_FALSE(r.has_value());
        EXPECT_EQ(r.error().code, TLV_ERR_BUFFER_TOO_SHORT);
        EXPECT_EQ(w.size(), 0u);
    }
}

TEST(Unit_Tlvpp_FixedFormat, WriterCallbacksReportShortCapacity) {
    using format = tlv::fixed_format<2, 2, BE>;
    std::uint8_t    buf[4] = {};
    std::size_t     written = 0;
    const owned_tag tag_owner = make_tag(2);
    tlv::tag_t      tag = tag_owner;

    EXPECT_EQ(format::writer().write_tag(nullptr, buf, 1, &tag, &written),
              TLV_ERR_BUFFER_TOO_SHORT);
    EXPECT_EQ(format::writer().write_length(nullptr, buf, 1, 3, &written),
              TLV_ERR_BUFFER_TOO_SHORT);
    // A size query with no destination succeeds and reports the width.
    EXPECT_EQ(format::writer().write_tag(nullptr, nullptr, 0, &tag, &written), TLV_OK);
    EXPECT_EQ(written, 2u);
    EXPECT_EQ(format::writer().write_length(nullptr, nullptr, 0, 3, &written), TLV_OK);
    EXPECT_EQ(written, 2u);
}

TEST(Unit_Tlvpp_FixedFormat, TagSizeMustMatchTheConfiguredWidth) {
    using format = tlv::fixed_format<2, 1, BE>;
    std::array<tlv::byte, 16> buf{};
    tlv::writer               w(buf.data(), buf.size(), format::writer());

    for (std::size_t width : {std::size_t(1), std::size_t(3)}) {
        auto r = w.write(make_tag(width), to_bytes("a"));
        ASSERT_FALSE(r.has_value());
        EXPECT_EQ(r.error().code, TLV_ERR_INVALID_TAG_SIZE);
    }
    EXPECT_EQ(w.size(), 0u);
}

TEST(Unit_Tlvpp_FixedFormat, MultipleElementsInSequence) {
    using format = tlv::fixed_format<1, 2, LE>;
    std::array<tlv::byte, 32> buf{};
    tlv::writer               w(buf.data(), buf.size(), format::writer());
    ASSERT_TRUE(w.write(make_tag(1), to_bytes("ab")).has_value());
    ASSERT_TRUE(w.write(make_tag(1), to_bytes("cde")).has_value());
    EXPECT_EQ(w.size(), (1u + 2 + 2) + (1 + 2 + 3));

    tlv::reader reader(tlv::bytes(buf.data(), w.size()), format::reader());
    auto        first = reader.next();
    auto        second = reader.next();
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(first->value.size(), 2u);
    EXPECT_EQ(second->value.size(), 3u);
    EXPECT_TRUE(reader.at_end());
}

TEST(Unit_Tlvpp_FixedFormat, WorksWithTheCApi) {
    using format = tlv::fixed_format<1, 2, BE>;
    std::uint8_t       buf[16] = {};
    const std::uint8_t value[2] = {0xDE, 0xAD};
    const tlv_tag_t    tag = TLV_TAG(0x10);
    size_t             written = 0;
    ASSERT_EQ(tlv_write(buf, sizeof(buf), &format::writer(), tag, value, sizeof(value), &written),
              TLV_OK);
    const std::uint8_t expected[] = {0x10, 0x00, 0x02, 0xDE, 0xAD};
    ASSERT_EQ(written, sizeof(expected));
    EXPECT_EQ(std::vector<std::uint8_t>(buf, buf + written),
              std::vector<std::uint8_t>(expected, expected + sizeof(expected)));

    tlv_view_t view;
    size_t     consumed = 0;
    ASSERT_EQ(tlv_read(buf, written, &format::reader(), &view, &consumed), TLV_OK);
    EXPECT_EQ(consumed, written);
    EXPECT_EQ(view.value.data, buf + 3);
}

#if OPENTLV_FORMAT_FIXED_1BYTE
TEST(Unit_Tlvpp_FixedFormat, OneByteConfigurationMatchesTheBuiltinFormat) {
    using format = tlv::fixed_format<1, 1, BE>;
    for (std::size_t length : {std::size_t(0), std::size_t(1), std::size_t(255)}) {
        SCOPED_TRACE(length);
        std::vector<std::uint8_t> value(length, 0x5A);
        std::uint8_t              expected[300] = {};
        std::uint8_t              actual[300] = {};
        const tlv_tag_t           tag = TLV_TAG(0x7F);
        size_t                    expected_size = 0, actual_size = 0;

        ASSERT_EQ(tlv_write(expected, sizeof(expected), &tlv_writer_format_fixed_1byte, tag,
                            value.data(), value.size(), &expected_size),
                  TLV_OK);
        ASSERT_EQ(tlv_write(actual, sizeof(actual), &format::writer(), tag, value.data(),
                            value.size(), &actual_size),
                  TLV_OK);
        ASSERT_EQ(actual_size, expected_size);
        EXPECT_EQ(std::vector<std::uint8_t>(actual, actual + actual_size),
                  std::vector<std::uint8_t>(expected, expected + expected_size));
    }
    std::size_t size = 0;
    EXPECT_EQ(format::writer().length_size(nullptr, 256, &size),
              tlv_writer_format_fixed_1byte.length_size(nullptr, 256, &size));
}
#endif

#if SIZE_MAX < UINT64_MAX
TEST(Unit_Tlvpp_FixedFormat, LengthWiderThanSizeTIsRejected) {
    using format = tlv::fixed_format<1, 8, BE>;
    const std::uint8_t data[8] = {0x01, 0, 0, 0, 0, 0, 0, 0};
    std::size_t        length = 0, consumed = 0;
    EXPECT_EQ(format::reader().read_length(nullptr, data, sizeof(data), &length, &consumed),
              TLV_ERR_INVALID_LENGTH);
}
#endif

} // namespace
