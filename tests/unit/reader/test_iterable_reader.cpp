// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv++/tlv.hpp"
#include "tlv++/native.hpp"
#include "custom_cpp_format.hpp"
#include <gtest/gtest.h>
#include <algorithm>
#include <iterator>
#include <type_traits>

namespace {
tlv::bytes input(const uint8_t* data, size_t size) {
    return {reinterpret_cast<const tlv::byte*>(data), size};
}
using fixed = tlv::fixed_format<1, 1, tlv::byte_order::big_endian>;
const uint8_t wire[] = {1, 1, 42, 2, 0, 3, 2, 43, 44};

struct move_only_format : custom_cpp_format {
    move_only_format() {
        trailer = 0xEE;
    }
    move_only_format(move_only_format&& other) : custom_cpp_format(other) {
        other.trailer = 0;
    }
    move_only_format(const move_only_format&) = delete;
};

struct end_error_format {
    tlv::expected<tlv::decoded, tlv::format_failure> decode(tlv::bytes) const noexcept {
        return tlv::unexpected<tlv::format_failure>(tlv::format_failure(TLV_ERR_END_OF_BUFFER));
    }
};

struct counted_error_format {
    size_t*                                          calls;
    tlv::expected<tlv::decoded, tlv::format_failure> decode(tlv::bytes) const noexcept {
        ++*calls; // An observation sink; immutable configuration and outcomes are unchanged.
        return tlv::unexpected<tlv::format_failure>(
            tlv::format_failure(tlv::errc::buffer_too_short).at(tlv::wire_region::value, 1, 2));
    }
};

auto make_custom_range(tlv::bytes data) -> decltype(tlv::parse(data, move_only_format{})) {
    auto range = tlv::parse(data, move_only_format{});
    return range;
}

template <typename Range> void expect_single(Range&& range, tlv::tag tag, tlv::bytes value) {
    size_t count = 0;
    for (auto element : range) {
        EXPECT_EQ(tag, element.tag());
        EXPECT_EQ(value.data(), element.value().data());
        EXPECT_EQ(value.size(), element.value().size());
        ++count;
    }
    EXPECT_EQ(1u, count);
}
} // namespace

TEST(Unit_Tlvpp_IterableReader, ElementsBorrowIndependentWireValues) {
    tlv::reader<fixed> reader(input(wire, sizeof(wire)));
    const uint8_t      tags[] = {1, 2, 3};
    const size_t       sizes[] = {1, 0, 2};
    const size_t       values[] = {2, 5, 7};
    tlv::element_view  retained;
    size_t             count = 0;
    for (auto element : reader) {
        ASSERT_LT(count, 3u);
        EXPECT_EQ(tags[count], static_cast<uint8_t>(element.tag()[0]));
        EXPECT_EQ(sizes[count], element.value().size());
        EXPECT_EQ(reinterpret_cast<const tlv::byte*>(wire + values[count]), element.value().data());
        if (count == 0) retained = element;
        ++count;
    }
    EXPECT_EQ(3u, count);
    EXPECT_EQ(42u, static_cast<unsigned char>(retained.value()[0]));
    EXPECT_EQ(sizeof(wire), reader.consumed());
    EXPECT_EQ(reader.begin(), reader.end());
}

TEST(Unit_Tlvpp_IterableReader, EmptyFinalInputIsAnEmptyRange) {
    tlv::reader<fixed> reader(tlv::bytes{});
    EXPECT_EQ(reader.begin(), reader.end());
    auto range = tlv::parse<fixed>(tlv::bytes{});
    EXPECT_EQ(range.begin(), range.end());
}

TEST(Unit_Tlvpp_IterableReader, CursorInteroperabilityBreakAndRepeatedBegin) {
    tlv::reader<fixed> reader(input(wire, sizeof(wire)));
    ASSERT_TRUE(reader.next());
    for (auto element : reader) {
        EXPECT_EQ(tlv::tag_bytes<2>(), element.tag());
        break;
    }
    EXPECT_EQ(5u, reader.offset());
    auto third = reader.next_source();
    ASSERT_TRUE(third);
    EXPECT_EQ(tlv::tag_bytes<3>(), third->element.tag());

    tlv::reader<fixed> repeated(input(wire, sizeof(wire)));
    EXPECT_EQ(tlv::tag_bytes<1>(), repeated.begin()->tag());
    EXPECT_EQ(tlv::tag_bytes<2>(), repeated.begin()->tag());
    EXPECT_EQ(5u, repeated.consumed());
}

TEST(Unit_Tlvpp_IterableReader, InputIteratorTraitsPostincrementAndAlgorithms) {
    using iterator = tlv::reader<fixed>::iterator;
    static_assert(std::is_same<std::iterator_traits<iterator>::iterator_category,
                               std::input_iterator_tag>::value,
                  "single-pass iterator");
    static_assert(
        std::is_same<std::iterator_traits<iterator>::value_type, tlv::element_view>::value,
        "semantic views");
    EXPECT_EQ(iterator{}, iterator{});
    tlv::reader<fixed> reader(input(wire, sizeof(wire)));
    auto               current = reader.begin();
    auto               copy = current;
    EXPECT_EQ(current, copy);
    EXPECT_EQ(tlv::tag_bytes<1>(), (current++)->tag());
    EXPECT_EQ(tlv::tag_bytes<2>(), current->tag());
    EXPECT_EQ(2, std::distance(current, reader.end()));
    auto range = tlv::parse<fixed>(input(wire, sizeof(wire)));
    EXPECT_EQ(1, std::count_if(range.begin(), range.end(),
                               [](tlv::element_view element) { return element.value().empty(); }));
}

TEST(Unit_Tlvpp_IterableReader, FirstFailureThrowsWithCanonicalDiagnosticAndNoConsumption) {
    const uint8_t          malformed[] = {1, 2, 42};
    tlv::reader<fixed>     reader(input(malformed, sizeof(malformed)));
    tlv::reader_diagnostic expected{};
    auto                   result = reader.next(expected);
    ASSERT_FALSE(result);
    try {
        (void)reader.begin();
        FAIL() << "must report a truncated first element";
    } catch (const tlv::parse_error& failure) {
        EXPECT_EQ(result.error().code, failure.code());
        EXPECT_EQ(0u, failure.offset());
        EXPECT_EQ(expected.diagnostic.offset, failure.diagnostic().diagnostic.offset);
        EXPECT_EQ(expected.operation, failure.diagnostic().operation);
        EXPECT_EQ(expected.declared_length, failure.diagnostic().declared_length);
    }
    EXPECT_EQ(0u, reader.consumed());
    EXPECT_THROW((void)reader.begin(), tlv::parse_error);
}

TEST(Unit_Tlvpp_IterableReader, LaterFailureThrowsAfterValidPrefixAndCanRetryExplicitly) {
    const uint8_t      malformed[] = {1, 1, 42, 2};
    tlv::reader<fixed> reader(input(malformed, sizeof(malformed)));
    size_t             count = 0;
    try {
        for (auto element : reader) {
            EXPECT_EQ(tlv::tag_bytes<1>(), element.tag());
            ++count;
        }
        FAIL() << "must report the truncated second header";
    } catch (const tlv::parse_error& failure) {
        EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, failure.code());
        EXPECT_EQ(3u, failure.offset());
        EXPECT_EQ(4u, failure.diagnostic().diagnostic.offset);
    }
    EXPECT_EQ(1u, count);
    EXPECT_EQ(3u, reader.consumed());
    auto result = reader.next();
    ASSERT_FALSE(result);
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, result.error().code);
}

TEST(Unit_Tlvpp_IterableReader, InvalidInitializationAndCallbackEndAreNotEmptyRanges) {
    tlv_format_t  missing{};
    tlv::reader<> reader(tlv::bytes{}, tlv::native::borrow_format(missing));
    try {
        (void)reader.begin();
        FAIL() << "invalid initialization must report an initialized failure";
    } catch (const tlv::parse_error& failure) {
        const auto error = failure.failure();
        EXPECT_EQ(tlv::errc::null_argument, error.status());
        EXPECT_EQ(tlv::operation::reader, error.stage());
        EXPECT_EQ(tlv::severity::error, error.severity());
        ASSERT_TRUE(error.has_offset());
        EXPECT_EQ(0u, error.offset());
        EXPECT_FALSE(error.has_tag());
        EXPECT_EQ(0u, error.depth());
        EXPECT_EQ(nullptr, error.expected());
        EXPECT_EQ(nullptr, error.actual());
    }
    const uint8_t                 data[] = {1};
    tlv::reader<end_error_format> custom(input(data, sizeof(data)));
    try {
        (void)custom.begin();
        FAIL() << "callback END_OF_BUFFER inside input is not final EOF";
    } catch (const tlv::parse_error& failure) {
        EXPECT_EQ(TLV_ERR_END_OF_BUFFER, failure.code());
        EXPECT_FALSE(failure.failure().has_offset());
        EXPECT_FALSE(failure.failure().has_tag());
        EXPECT_EQ(0u, failure.failure().depth());
    }
    EXPECT_EQ(0u, custom.consumed());
    auto invalid_range = tlv::parse(tlv::bytes{}, tlv::native::borrow_format(missing));
    EXPECT_THROW((void)invalid_range.begin(), tlv::parse_error);
}

TEST(Unit_Tlvpp_IterableReader, FailureAndPauseDecodeOnceAndEmptyBoundariesDoNotDecode) {
    const uint8_t data[] = {1};
    for (auto mode : {tlv::input_mode::final, tlv::input_mode::incremental}) {
        size_t                            calls = 0;
        tlv::reader<counted_error_format> reader(input(data, sizeof data),
                                                 counted_error_format{&calls}, mode);
        try {
            (void)reader.begin();
            FAIL() << "the callback must report incomplete input";
        } catch (const tlv::parse_error& failure) {
            EXPECT_EQ(1u, calls);
            const auto error = failure.failure();
            EXPECT_EQ(mode == tlv::input_mode::final ? tlv::errc::buffer_too_short
                                                     : tlv::errc::need_more_data,
                      error.status());
            ASSERT_TRUE(error.has_offset());
            EXPECT_EQ(1u, error.offset());
            EXPECT_FALSE(error.has_tag());
            EXPECT_EQ(0u, error.depth());
        }
        EXPECT_EQ(0u, reader.consumed());

        calls = 0;
        tlv::reader<counted_error_format> empty({}, counted_error_format{&calls}, mode);
        if (mode == tlv::input_mode::final) {
            EXPECT_EQ(empty.begin(), empty.end());
        } else {
            try {
                (void)empty.begin();
                FAIL() << "empty incremental input must remain resumable";
            } catch (const tlv::parse_error& failure) {
                const auto error = failure.failure();
                EXPECT_EQ(tlv::errc::need_more_data, error.status());
                EXPECT_EQ(tlv::severity::info, error.severity());
                ASSERT_TRUE(error.has_offset());
                EXPECT_EQ(0u, error.offset());
                EXPECT_FALSE(error.has_tag());
                EXPECT_EQ(0u, error.depth());
            }
        }
        EXPECT_EQ(0u, calls);
    }
}

TEST(Unit_Tlvpp_IterableReader, IncrementalShortageExhaustionAndAbsoluteOffsets) {
    tlv::reader<fixed> reader(input(wire, 4), tlv::input_mode::incremental);
    auto               first = reader.begin();
    EXPECT_EQ(tlv::tag_bytes<1>(), first->tag());
    EXPECT_THROW(++first, tlv::parse_error);
    EXPECT_EQ(3u, reader.offset());
    ASSERT_TRUE(reader.set_input(input(wire + 3, 2), 3, tlv::input_mode::incremental));
    EXPECT_EQ(tlv::tag_bytes<2>(), reader.begin()->tag());
    try {
        (void)reader.begin();
        FAIL() << "exhausted non-final input must request more data";
    } catch (const tlv::parse_error& failure) {
        EXPECT_EQ(TLV_NEED_MORE_DATA, failure.code());
        EXPECT_EQ(5u, failure.offset());
        EXPECT_EQ(5u, failure.diagnostic().diagnostic.offset);
    }
    ASSERT_TRUE(reader.set_input(input(wire + 3, sizeof(wire) - 3), 0, tlv::input_mode::final));
    EXPECT_EQ(tlv::tag_bytes<3>(), reader.begin()->tag());
    EXPECT_EQ(reader.begin(), reader.end());
    tlv::reader<fixed> empty(tlv::bytes{}, tlv::input_mode::incremental);
    EXPECT_THROW((void)empty.begin(), tlv::parse_error);
}

TEST(Unit_Tlvpp_IterableReader, GenericRuntimeAndTemporaryCustomRanges) {
    size_t count = 0;
    for (auto element : tlv::parse(input(wire, sizeof(wire)), fixed::view())) {
        EXPECT_EQ(++count, static_cast<unsigned char>(element.tag()[0]));
    }
    EXPECT_EQ(3u, count);
    auto borrowed = tlv::parse(input(wire, sizeof(wire)), fixed::view());
    EXPECT_EQ(3, std::distance(borrowed.begin(), borrowed.end()));
    const uint8_t custom_wire[] = {9, 1, 42, 0xEE, 10, 0, 0xEE};
    count = 0;
    for (auto element : make_custom_range(input(custom_wire, sizeof(custom_wire)))) {
        EXPECT_EQ(9u + count, static_cast<unsigned char>(element.tag()[0]));
        EXPECT_EQ(count == 0 ? 1u : 0u, element.value().size());
        ++count;
    }
    EXPECT_EQ(2u, count);
}

TEST(Unit_Tlvpp_IterableReader, MovingRangeRebindsFormatAndPreservesPosition) {
    const uint8_t data[] = {1, 0, 0xEE, 2, 0, 0xEE};
    auto          original = make_custom_range(input(data, sizeof(data)));
    EXPECT_EQ(tlv::tag_bytes<1>(), original.begin()->tag());
    auto moved = std::move(original);
    EXPECT_EQ(tlv::tag_bytes<2>(), moved.begin()->tag());
    EXPECT_EQ(moved.begin(), moved.end());
}

#if OPENTLV_FORMAT_BER
TEST(Unit_Tlvpp_IterableReader, BuiltinBerRangeIsFlatAndBorrowed) {
    const uint8_t data[] = {0x30, 3, 2, 1, 42, 4, 0};
    size_t        count = 0;
    for (auto element : tlv::ber::parse(input(data, sizeof(data)))) {
        EXPECT_EQ(count == 0 ? tlv::tag_bytes<0x30>() : tlv::tag_bytes<4>(), element.tag());
        EXPECT_EQ(count == 0 ? 3u : 0u, element.value().size());
        ++count;
    }
    EXPECT_EQ(2u, count);
}
#endif

TEST(Unit_Tlvpp_IterableReader, AvailableBuiltinHelpersUseTheirWireFraming) {
    const uint8_t binary[] = {4, 1, 42};
    (void)binary;
#if OPENTLV_FORMAT_DER
    expect_single(tlv::der::parse(input(binary, sizeof(binary))), tlv::tag_bytes<4>(),
                  input(binary + 2, 1));
#endif
#if OPENTLV_FORMAT_CER
    expect_single(tlv::cer::parse(input(binary, sizeof(binary))), tlv::tag_bytes<4>(),
                  input(binary + 2, 1));
#endif
#if OPENTLV_EMV
    const uint8_t emv[] = {0x5A, 1, 42};
    expect_single(tlv::emv::parse(input(emv, sizeof(emv))), tlv::tag_bytes<0x5A>(),
                  input(emv + 2, 1));
#endif
#if OPENTLV_BLUETOOTH
    const uint8_t ltv[] = {2, 1, 42};
    expect_single(tlv::bluetooth::parse(input(ltv, sizeof(ltv))), tlv::tag_bytes<1>(),
                  input(ltv + 2, 1));
#endif
#if OPENTLV_LLDP
    const uint8_t lldp[] = {6, 2, 0, 120};
    expect_single(tlv::lldp::parse(input(lldp, sizeof(lldp))), tlv::tag_bytes<3>(),
                  input(lldp + 2, 2));
#endif
#if OPENTLV_DHCP
    const uint8_t dhcp[] = {53, 1, 1, 255, 0};
    const uint8_t tags[] = {53, 255, 0};
    size_t        count = 0;
    for (auto element : tlv::dhcp::parse(input(dhcp, sizeof(dhcp)))) {
        ASSERT_LT(count, 3u);
        EXPECT_EQ(tags[count], static_cast<unsigned char>(element.tag()[0]));
        EXPECT_EQ(count == 0 ? 1u : 0u, element.value().size());
        ++count;
    }
    EXPECT_EQ(3u, count); // Framing continues after End; container policy stays explicit.
#endif
#if OPENTLV_NFC
    const uint8_t nfc[] = {0, 3, 1, 42, 0xFE, 0};
    const uint8_t nfc_tags[] = {0, 3, 0xFE, 0};
    size_t        nfc_count = 0;
    for (auto element : tlv::nfc::parse(input(nfc, sizeof(nfc)))) {
        ASSERT_LT(nfc_count, 4u);
        EXPECT_EQ(nfc_tags[nfc_count], static_cast<unsigned char>(element.tag()[0]));
        EXPECT_EQ(nfc_count == 1 ? 1u : 0u, element.value().size());
        ++nfc_count;
    }
    EXPECT_EQ(4u, nfc_count);
#endif
}
