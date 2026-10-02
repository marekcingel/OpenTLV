// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv++/native.hpp"
#include "tlv++/reader/reader.hpp"
#include "tlv++/writer/writer.hpp"
#include "controlled_format.h"
#include <gtest/gtest.h>
#include <cstring>
#include <type_traits>
#include <vector>

static_assert(std::is_trivially_copyable<tlv::tag>::value, "Tags copy descriptors only");
static_assert(std::is_trivially_copyable<tlv::value_view>::value, "Values copy descriptors only");
static_assert(std::is_trivially_copyable<tlv::element_view>::value,
              "Elements copy descriptors only");
static_assert(!std::is_convertible<tlv_tag_t, tlv::tag>::value, "Native imports are explicit");
static_assert(!std::is_convertible<tlv::tag, tlv_tag_t>::value, "Native exports are explicit");
static_assert(!std::is_convertible<tlv_value_t, tlv::value_view>::value,
              "Value imports are checked");
static_assert(!std::is_convertible<tlv::value_view, tlv_value_t>::value,
              "Value exports are explicit");
static_assert(!std::is_convertible<tlv_element_t, tlv::element_view>::value,
              "Element imports are checked");
static_assert(!std::is_convertible<tlv::element_view, tlv_element_t>::value,
              "Element exports are explicit");

namespace {
tlv::bytes bytes(const uint8_t* data, size_t size) {
    return {reinterpret_cast<const tlv::byte*>(data), size};
}
} // namespace

TEST(Unit_Tlvpp_Semantics, IdentifiersHaveByteIdentityAndStableLiteralStorage) {
    const uint8_t  storage[] = {0x9F, 0x02};
    const tlv::tag identifier(bytes(storage, sizeof(storage)));
    const auto     literal = tlv::tag_bytes<0x9F, 0x02>();
    EXPECT_TRUE((identifier == literal));
    EXPECT_FALSE((identifier != literal));
    EXPECT_TRUE((identifier < tlv::tag_bytes<0x9F, 0x03>()));
    EXPECT_TRUE((identifier > tlv::tag_bytes<0x9F>()));
    EXPECT_TRUE((identifier <= literal));
    EXPECT_TRUE((identifier >= literal));
    EXPECT_EQ(identifier.data(), identifier.as_bytes().data());
    EXPECT_EQ(literal.data(), (tlv::tag_bytes<0x9F, 0x02>().data()));
    EXPECT_EQ((std::vector<tlv::byte>{tlv::byte{0x9F}, tlv::byte{0x02}}),
              std::vector<tlv::byte>(identifier.begin(), identifier.end()));
    EXPECT_EQ(tlv::byte{0x02}, identifier.at(1));
    EXPECT_THROW(identifier.at(2), std::out_of_range);
    EXPECT_THROW(tlv::tag{}.at(0), std::out_of_range);
    const tlv::tag absent;
    const tlv::tag empty(bytes(storage, 0));
    EXPECT_TRUE((absent == empty));
    EXPECT_FALSE((absent.present()));
    EXPECT_TRUE((empty.present()));
    EXPECT_EQ(absent.begin(), absent.end());
    EXPECT_EQ(empty.begin(), empty.end());
    EXPECT_EQ(nullptr, tlv::native::descriptor(absent).data);
    EXPECT_EQ(storage, tlv::native::descriptor(empty).data);
}

TEST(Unit_Tlvpp_Semantics, NativeImportsRejectInvalidRepresentationBeforeByteAccess) {
    const uint8_t storage[] = {42};
    auto          bad_tag = tlv::native::borrow_tag({nullptr, 1});
    ASSERT_FALSE(bad_tag);
    EXPECT_EQ(TLV_ERR_NULL_ARG, bad_tag.error().code);
    auto bad_value = tlv::native::borrow_value({nullptr, 1});
    ASSERT_FALSE(bad_value);
    EXPECT_EQ(TLV_ERR_NULL_ARG, bad_value.error().code);
    auto bad_element = tlv::native::borrow_element({{storage, 1}, {nullptr, 1}});
    ASSERT_FALSE(bad_element);
    EXPECT_EQ(TLV_ERR_NULL_ARG, bad_element.error().code);
#if SIZE_MAX < UINT64_MAX
    const tlv_value_t oversized{storage, static_cast<tlv_size_t>(SIZE_MAX) + 1};
    auto              rejected = tlv::native::borrow_value(oversized);
    ASSERT_FALSE(rejected);
    EXPECT_EQ(TLV_ERR_NATIVE_SIZE, rejected.error().code);
    EXPECT_FALSE((tlv::native::borrow_element({{storage, 1}, oversized})));
#endif
    auto valid = tlv::native::borrow_element({{storage, 1}, {storage, 1}});
    ASSERT_TRUE(valid);
    const auto raw = tlv::native::descriptor(*valid);
    EXPECT_EQ(storage, raw.tag.data);
    EXPECT_EQ(storage, raw.value.data);
    EXPECT_EQ(1u, raw.value.size);
}

TEST(Unit_Tlvpp_Semantics, ValuesAndElementsCompareContentsAndBorrowStableInput) {
    const uint8_t input[] = {1, 2, 42, 43, 2, 0};
    const uint8_t copy[] = {42, 43};
    tlv::reader<> reader(bytes(input, sizeof(input)), controlled::format);
    auto          decoded = reader.next_source();
    ASSERT_TRUE(decoded);
    const auto element = decoded->element;
    EXPECT_TRUE((element.tag() == tlv::tag_bytes<1>()));
    EXPECT_EQ(reinterpret_cast<const tlv::byte*>(input), element.tag().data());
    EXPECT_EQ(reinterpret_cast<const tlv::byte*>(input + 2), element.value().data());
    EXPECT_EQ(2u, element.value().size());
    const tlv::value_view value(bytes(copy, sizeof(copy)));
    EXPECT_TRUE((value == element.value()));
    EXPECT_EQ(0, value.compare(element.value()));
    EXPECT_TRUE((element == tlv::element_view(tlv::tag_bytes<1>(), value)));
    EXPECT_TRUE((element != tlv::element_view(tlv::tag_bytes<2>(), value)));
    EXPECT_EQ((std::vector<tlv::byte>{tlv::byte{42}, tlv::byte{43}}),
              std::vector<tlv::byte>(value.begin(), value.end()));
    EXPECT_EQ(tlv::byte{43}, value.at(1));
    EXPECT_THROW(value.at(2), std::out_of_range);
    const tlv::value_view empty;
    EXPECT_EQ(empty.begin(), empty.end());
    EXPECT_THROW(empty.at(0), std::out_of_range);
    ASSERT_TRUE(reader.next());
    EXPECT_EQ(tlv::byte{42}, element.value()[0]);
    tlv::byte     output[sizeof(input)]{};
    tlv::writer<> writer(output, sizeof(output), controlled::format);
    ASSERT_TRUE(writer.write(element.tag(), element.value()));
    ASSERT_EQ(4u, writer.size());
    EXPECT_EQ(0, std::memcmp(input, output, writer.size()));
    auto preserved = tlv::preserve(decoded->source, element, output, sizeof(output));
    ASSERT_TRUE(preserved);
    EXPECT_EQ(4u, *preserved);
    EXPECT_EQ(0, std::memcmp(input, output, *preserved));
}

TEST(Unit_Tlvpp_Semantics, PreservationDistinguishesAbsentAndExplicitlyEmptyIdentifiers) {
    const uint8_t wire = 42, other = 0;
    for (bool present : {false, true}) {
        tlv_format_t format{};
        format.context = &present;
        format.decode = [](const void* context, const uint8_t* data, size_t, tlv_decoded_t* result,
                           tlv_format_error_t*) {
            const bool has_tag = *static_cast<const bool*>(context);
            result->element = {{has_tag ? data : nullptr, 0}, {data, 1}};
            result->source.header = {0, 0, 1};
            result->source.tag = {0, 0, has_tag ? 1 : 0};
            result->source.value = {0, 1, 1};
            result->source.trailer = {1, 0, 1};
            result->source.size = 1;
            return TLV_OK;
        };
        auto result = tlv::decode(format, bytes(&wire, 1));
        ASSERT_TRUE(result);
        EXPECT_EQ(present, result->element.tag().present());
        const tlv::tag same(bytes(present ? &other : nullptr, 0));
        const tlv::tag changed(bytes(present ? nullptr : &other, 0));
        tlv::byte      output{};
        ASSERT_TRUE(tlv::preserve(result->source, {same, result->element.value()}, &output, 1));
        EXPECT_EQ(tlv::byte{42}, output);
        auto rejected =
            tlv::preserve(result->source, {changed, result->element.value()}, &output, 1);
        ASSERT_FALSE(rejected);
        EXPECT_EQ(TLV_ERR_INVALID_ARG, rejected.error().code);
    }
}
