#include "tlv++/tlv.hpp"
#include "controlled_format.h"
#include <gtest/gtest.h>
#include <array>

namespace application {
struct count {
    uint8_t value;
};
} // namespace application
namespace tlv {
template <> struct codec<application::count> {
    using value_type = application::count;
    static expected<value_type, tlv_codec_result_t> decode(bytes input) {
        auto result = uint8_codec::decode(input);
        if (!result) return unexpected<tlv_codec_result_t>(result.error());
        if (*result > 10) return unexpected<tlv_codec_result_t>(TLV_CODEC_ERR_INVALID_VALUE);
        return value_type{*result};
    }
    static expected<size_t, tlv_codec_result_t> encode(const value_type& value, byte* output,
                                                       size_t capacity) {
        if (value.value > 10) return unexpected<tlv_codec_result_t>(TLV_CODEC_ERR_INVALID_VALUE);
        return uint8_codec::encode(value.value, output, capacity);
    }
};
} // namespace tlv
namespace {
using Label = tlv::field<tlv::tag_constant<0x50>, std::string>;
using Count = tlv::field<tlv::tag_constant<0x51>, application::count>;
using Big = tlv::field<tlv::tag_constant<0x9F, 0x36>, uint16_t, tlv::uint16_be_codec>;
using Little = tlv::field<tlv::tag_constant<0x9F, 0x36>, uint16_t, tlv::uint16_le_codec>;
using Borrowed = tlv::field<tlv::tag_constant<0x50>, tlv::value_view>;
using EmptyTag = tlv::field<tlv::tag_constant<>, std::string>;

TEST(Unit_Tlvpp_TypedFields, IndependentBytesAndExplicitEndianness) {
    const tlv::byte   input[] = {static_cast<tlv::byte>(0x12), static_cast<tlv::byte>(0x34)};
    tlv::element_view element(Big::tag(), tlv::value_view(tlv::bytes(input, 2)));
    auto              big = element.decode<Big>();
    auto              little = element.decode<Little>();
    ASSERT_TRUE(big);
    ASSERT_TRUE(little);
    EXPECT_EQ(0x1234, *big);
    EXPECT_EQ(0x3412, *little);
    tlv::byte                                                       output[8]{};
    tlv::writer<tlv::fixed_format<2, 1, TLV_BYTE_ORDER_BIG_ENDIAN>> writer(output, 8);
    ASSERT_TRUE(writer.write<Big>(*big));
    const tlv::byte expected[] = {static_cast<tlv::byte>(0x9F), static_cast<tlv::byte>(0x36),
                                  static_cast<tlv::byte>(2), static_cast<tlv::byte>(0x12),
                                  static_cast<tlv::byte>(0x34)};
    EXPECT_EQ(5u, writer.size());
    EXPECT_TRUE(std::equal(expected, expected + 5, output));
}

TEST(Unit_Tlvpp_TypedFields, StringsPreserveNulsAndBorrowedValuesRetainInput) {
    const tlv::byte   input[] = {static_cast<tlv::byte>('A'), static_cast<tlv::byte>(0),
                                 static_cast<tlv::byte>('B')};
    tlv::element_view element(Label::tag(), tlv::value_view(tlv::bytes(input, 3)));
    auto              text = element.decode<Label>();
    auto              borrowed = element.decode<Borrowed>();
    ASSERT_TRUE(text);
    ASSERT_TRUE(borrowed);
    EXPECT_EQ(std::string("A\0B", 3), *text);
    EXPECT_EQ(input, borrowed->as_bytes().data());
    tlv::byte     output[8]{};
    tlv::byte     scratch[3]{};
    tlv::writer<> writer(output, 8, controlled::format);
    ASSERT_TRUE(writer.write<Label>(*text, {scratch, 3}));
    const tlv::byte expected[] = {static_cast<tlv::byte>(0x50), static_cast<tlv::byte>(3),
                                  static_cast<tlv::byte>('A'), static_cast<tlv::byte>(0),
                                  static_cast<tlv::byte>('B')};
    EXPECT_TRUE(std::equal(expected, expected + 5, output));
    EXPECT_TRUE(tlv::element_view(Label::tag(), {}).decode<Label>()->empty());
    EXPECT_TRUE(tlv::element_view({}, {}).decode<EmptyTag>()->empty());
    ASSERT_TRUE(writer.write<Label>(std::string{}));
    EXPECT_EQ(7u, writer.size());
    EXPECT_EQ(static_cast<tlv::byte>(0x50), output[5]);
    EXPECT_EQ(static_cast<tlv::byte>(0), output[6]);
}

TEST(Unit_Tlvpp_TypedFields, ErrorDomainsAndCursorPreservation) {
    const tlv::byte input[] = {static_cast<tlv::byte>(1)};
    auto wrong = tlv::element_view(Label::tag(), tlv::value_view({input, 1})).decode<Big>();
    ASSERT_FALSE(wrong);
    EXPECT_EQ(tlv::typed_errc::tag_mismatch, wrong.error().kind);
    auto invalid = tlv::element_view(Big::tag(), tlv::value_view({input, 1})).decode<Big>();
    ASSERT_FALSE(invalid);
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE, invalid.error().codec_code);
    tlv::byte     output[3]{};
    tlv::byte     scratch[1]{};
    tlv::writer<> writer(output, 3, controlled::format);
    auto          too_small = writer.write<Label>("AB", {scratch, 1});
    ASSERT_FALSE(too_small);
    EXPECT_EQ(TLV_CODEC_ERR_BUFFER_TOO_SHORT, too_small.error().codec_code);
    auto framing = writer.write<Label>("AB");
    ASSERT_FALSE(framing);
    EXPECT_EQ(tlv::typed_errc::framing, framing.error().kind);
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, framing.error().framing_code);
    EXPECT_EQ(0u, writer.size());
    EXPECT_FALSE(writer.write<Count>(application::count{11}));
    EXPECT_EQ(0u, writer.size());
    ASSERT_TRUE(writer.write<Count>(application::count{7}, {scratch, 1}));
    EXPECT_EQ(static_cast<tlv::byte>(0x51), output[0]);
    EXPECT_EQ(static_cast<tlv::byte>(1), output[1]);
    EXPECT_EQ(static_cast<tlv::byte>(7), output[2]);
    auto count = tlv::element_view(Count::tag(), tlv::value_view({output + 2, 1})).decode<Count>();
    ASSERT_TRUE(count);
    EXPECT_EQ(7, count->value);
}

#if OPENTLV_DOCUMENT
int constructed(const void*, const tlv_tag_t* tag) {
    return tag->size == 1 && tag->data[0] == 0x6F;
}
TEST(Unit_Tlvpp_TypedFields, DocumentScopeDuplicatesAndInvalidatedNodes) {
    auto format = controlled::format;
    format.is_constructed = constructed;
    const tlv::byte input[] = {
        static_cast<tlv::byte>(0x6F), static_cast<tlv::byte>(3),   static_cast<tlv::byte>(0x50),
        static_cast<tlv::byte>(1),    static_cast<tlv::byte>('N'), static_cast<tlv::byte>(0x50),
        static_cast<tlv::byte>(1),    static_cast<tlv::byte>('T'), static_cast<tlv::byte>(0x50),
        static_cast<tlv::byte>(1),    static_cast<tlv::byte>('D')};
    auto doc = tlv::document::parse({input, 11}, tlv::document_format(format));
    ASSERT_TRUE(doc);
    auto top = doc->get<Label>();
    ASSERT_TRUE(top);
    EXPECT_EQ("T", *top);
    auto root = doc->find(tlv::tag_bytes<0x6F>());
    auto nested = root.get<Label>();
    ASSERT_TRUE(nested);
    EXPECT_EQ("N", *nested);
    auto missing = root.get<Count>();
    ASSERT_FALSE(missing);
    EXPECT_EQ(tlv::typed_errc::missing_field, missing.error().kind);
    auto absent = doc->get<Count>();
    ASSERT_FALSE(absent);
    EXPECT_EQ(tlv::typed_errc::missing_field, absent.error().kind);
    using Root = tlv::field<tlv::tag_constant<0x6F>, std::string>;
    auto complex = root.decode<Root>();
    ASSERT_FALSE(complex);
    EXPECT_EQ(tlv::typed_errc::constructed_value, complex.error().kind);
    auto child = root.first_child();
    child.erase();
    auto stale = child.decode<Label>();
    ASSERT_FALSE(stale);
    EXPECT_EQ(tlv::typed_errc::invalid_node, stale.error().kind);
    EXPECT_EQ(tlv::typed_errc::invalid_node, child.get<Label>().error().kind);
    auto bytes = doc->encode();
    ASSERT_TRUE(bytes);
    const tlv::byte expected[] = {static_cast<tlv::byte>(0x6F), static_cast<tlv::byte>(0),
                                  static_cast<tlv::byte>(0x50), static_cast<tlv::byte>(1),
                                  static_cast<tlv::byte>('T'),  static_cast<tlv::byte>(0x50),
                                  static_cast<tlv::byte>(1),    static_cast<tlv::byte>('D')};
    EXPECT_EQ(std::vector<tlv::byte>(expected, expected + 8), *bytes);
}
#endif
} // namespace
