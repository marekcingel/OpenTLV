// Keep this translation unit separate: low-level headers must not import codecs.
#include "tlv++/reader.hpp"
#include "tlv++/writer.hpp"
#include "tlv++/walker.hpp"
#include "tlv++/schema.hpp"
#include "tlv++/query.hpp"
#if defined(OPENTLV_TLVPP_CODEC_HPP) || defined(OPENTLV_CODEC_H)
#error Low-level APIs must not depend on the codec layer
#endif
#include "tlv/builtins/fixed/default.h"
#include "tlv++/structure.hpp"
#include <gtest/gtest.h>
#include "tlv/config.h"
#if OPENTLV_FORMAT_BER
#include "tlv++/ber.hpp"

TEST(Integration_TLV_CPP, BerIndefiniteRoundTripAndTraversal) {
    tlv::byte        buffer[8]{};
    const uint8_t    children[] = {4, 2, 0, 0};
    const tlv::bytes value(reinterpret_cast<const tlv::byte*>(children), sizeof(children));
    auto written = tlv::ber_write_indefinite(buffer, sizeof(buffer), TLV_TAG(0x30), value);
    ASSERT_TRUE(written);
    EXPECT_EQ(8u, *written);
    tlv::reader reader(tlv::bytes(buffer, *written), tlv_reader_format_ber);
    auto        item = reader.next();
    ASSERT_TRUE(item);
    EXPECT_EQ(buffer + 2, item->value.data());
    EXPECT_EQ(4u, item->value.size());
    EXPECT_TRUE(reader.at_end());
    size_t visits = 0;
    EXPECT_TRUE(tlv::walk_tree(tlv::bytes(buffer, *written), tlv_reader_format_ber,
                               tlv_ber_is_constructed, 1, 2,
                               [&visits](const tlv::entry&, size_t depth, size_t offset) {
                                   EXPECT_EQ(visits, depth);
                                   EXPECT_EQ(visits * 2, offset);
                                   ++visits;
                                   return TLV_VISIT_CONTINUE;
                               }));
    EXPECT_EQ(2u, visits);
    EXPECT_FALSE(tlv::ber_write_indefinite(buffer, 7, TLV_TAG(0x30), value));
    EXPECT_FALSE(tlv::ber_write_indefinite(buffer, sizeof(buffer), TLV_TAG(4), value));
}

TEST(Integration_TLV_CPP, BerPathQuery) {
    // 6F { 84, A5 { 50 "AB" } }, then a top-level 50.
    const uint8_t    wire[] = {0x6F, 0x0A, 0x84, 0x02, 0xAA, 0xBB, 0xA5, 0x04,
                               0x50, 0x02, 0x41, 0x42, 0x50, 0x01, 0xFF};
    const tlv::bytes input(reinterpret_cast<const tlv::byte*>(wire), sizeof(wire));

    size_t offset = 99;
    EXPECT_FALSE(tlv::query::parse("6F//50", &offset));
    EXPECT_EQ(3u, offset);

    auto path = tlv::query::parse("6F/A5/50");
    ASSERT_TRUE(path);
    EXPECT_EQ(3u, path->size());
    EXPECT_EQ(3u, path->c_query().count);
    size_t visits = 0;
    EXPECT_TRUE(path->walk(input, tlv_reader_format_ber, tlv_ber_is_constructed, 8, 100,
                           [&](const tlv::entry& item, size_t depth, size_t at) {
                               EXPECT_EQ(2u, depth);
                               EXPECT_EQ(8u, at);
                               EXPECT_EQ(2u, item.value.size());
                               EXPECT_EQ(0x41, static_cast<int>(item.value[0]));
                               ++visits;
                               return TLV_VISIT_CONTINUE;
                           }));
    EXPECT_EQ(1u, visits);

    auto missing = tlv::query::parse("6F/A5/51");
    ASSERT_TRUE(missing);
    EXPECT_TRUE(missing->walk(input, tlv_reader_format_ber, tlv_ber_is_constructed, 8, 100,
                              [](const tlv::entry&, size_t, size_t) {
                                  ADD_FAILURE();
                                  return TLV_VISIT_CONTINUE;
                              }));
    size_t failed_at = 0;
    auto   limited = path->walk(
        input, tlv_reader_format_ber, tlv_ber_is_constructed, 1, 100,
        [](const tlv::entry&, size_t, size_t) { return TLV_VISIT_CONTINUE; }, &failed_at);
    ASSERT_FALSE(limited);
    EXPECT_EQ(TLV_ERR_LIMIT, limited.error().code);
}
#endif

TEST(Integration_TLV_CPP, LayeredTraversalAndSchema) {
    const uint8_t data[] = {1, 1, 42, 2, 0};
    tlv::bytes    bytes(reinterpret_cast<const tlv::byte*>(data), sizeof(data));
    size_t        visits = 0;
    auto result = tlv::walk_tree(bytes, tlv_reader_format_default, nullptr, 0, 2,
                                 [&visits](const tlv::entry& item, size_t depth, size_t offset) {
                                     EXPECT_EQ(0u, depth);
                                     EXPECT_EQ(visits ? 3u : 0u, offset);
                                     EXPECT_EQ(visits ? 2 : 1, item.tag.data[0]);
                                     ++visits;
                                     return TLV_VISIT_CONTINUE;
                                 });
    ASSERT_TRUE(result);
    EXPECT_EQ(2u, visits);
    const tlv_structure_rule_t rule = {
        {TLV_TAG(1), 1, 1, 0, nullptr}, 1, 1, TLV_SCHEMA_PRIMITIVE, nullptr};
    const tlv_structure_schema_t schema = {&rule, 1, 1};
    EXPECT_TRUE(tlv::validate(bytes, tlv_reader_format_default, nullptr, schema, 0, 2));
}

TEST(Integration_TLV_CPP, ValidateAllCountsViolationsAndReportsTagPaths) {
    const uint8_t              data[] = {2, 0};
    const tlv::bytes           bytes(reinterpret_cast<const tlv::byte*>(data), sizeof(data));
    const tlv_structure_rule_t rule = {
        {TLV_TAG(1), 1, 1, 0, "one"}, 1, 1, TLV_SCHEMA_PRIMITIVE, nullptr};
    const tlv_structure_schema_t schema = {&rule, 1, 0};
    tlv_schema_issue_t           issues[4];
    auto                         count =
        tlv::validate_all(bytes, tlv_reader_format_default, nullptr, schema, 0, 2, issues, 4);
    ASSERT_TRUE(count);
    ASSERT_EQ(2u, *count); // Tag 1 is missing and tag 2 is unexpected.
    char path[8];
    ASSERT_EQ(TLV_OK, tlv_schema_issue_path_string(&issues[0], path, sizeof(path), nullptr));
    EXPECT_STREQ("01", path);

    auto conforming = tlv::validate_all(tlv::bytes(), tlv_reader_format_default, nullptr,
                                        tlv_structure_schema_t{nullptr, 0, 0}, 0, 2, nullptr, 0);
    ASSERT_TRUE(conforming);
    EXPECT_EQ(0u, *conforming);
}

TEST(Integration_TLV_CPP, ValidateAllDiagReportsFieldNamesAndPaths) {
    const uint8_t              data[] = {2, 0};
    const tlv::bytes           bytes(reinterpret_cast<const tlv::byte*>(data), sizeof(data));
    const tlv_structure_rule_t rule = {
        {TLV_TAG(1), 1, 1, 0, "one"}, 1, 1, TLV_SCHEMA_PRIMITIVE, nullptr};
    const tlv_structure_schema_t schema = {&rule, 1, 0};
    tlv_schema_diagnostic_t      diagnostics[4];
    auto count = tlv::validate_all_diag(bytes, tlv_reader_format_default, nullptr, schema, 0, 2,
                                        diagnostics, 4);
    ASSERT_TRUE(count);
    ASSERT_EQ(2u, *count); // Tag 1 is missing and tag 2 is unexpected.
    EXPECT_EQ(TLV_SCHEMA_ISSUE_MISSING, diagnostics[0].kind);
    EXPECT_STREQ("one", diagnostics[0].field);
    EXPECT_EQ(TLV_SCHEMA_ISSUE_UNEXPECTED, diagnostics[1].kind);
    EXPECT_EQ(nullptr, diagnostics[1].field);

    auto conforming =
        tlv::validate_all_diag(tlv::bytes(), tlv_reader_format_default, nullptr,
                               tlv_structure_schema_t{nullptr, 0, 0}, 0, 2, nullptr, 0);
    ASSERT_TRUE(conforming);
    EXPECT_EQ(0u, *conforming);
}

namespace {
struct pair_value {
    uint8_t first, second;
};
tlv_codec_result_t decode_pair(const void*, const tlv_reader_format_t* format, const uint8_t* data,
                               size_t size, void* out, size_t capacity) {
    if (capacity < sizeof(pair_value)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    tlv_view_t a{}, b{};
    size_t     used = 0, second_used = 0;
    if (tlv_read(data, size, format, &a, &used) != TLV_OK ||
        tlv_read(data + used, size - used, format, &b, &second_used) != TLV_OK ||
        a.value.length != 1 || b.value.length != 1 || a.tag.data[0] != 1 || b.tag.data[0] != 2 ||
        used + second_used != size)
        return TLV_CODEC_ERR_INVALID_VALUE;
    *static_cast<pair_value*>(out) = pair_value{a.value.data[0], b.value.data[0]};
    return TLV_CODEC_OK;
}
tlv_codec_result_t encode_pair(const void*, const tlv_writer_format_t* format, const void* value,
                               size_t size, uint8_t* data, size_t capacity, size_t* written) {
    if (size != sizeof(pair_value)) return TLV_CODEC_ERR_INVALID_VALUE;
    const auto& pair = *static_cast<const pair_value*>(value);
    if (!data) {
        *written = 6;
        return TLV_CODEC_OK;
    }
    size_t first = 0, second = 0;
    if (tlv_write(data, capacity, format, TLV_TAG(1), &pair.first, 1, &first) != TLV_OK ||
        tlv_write(data + first, capacity - first, format, TLV_TAG(2), &pair.second, 1, &second) !=
            TLV_OK)
        return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    *written = first + second;
    return TLV_CODEC_OK;
}
} // namespace

TEST(Integration_TLV_CPP, StructureCodecUsesCallerOwnedStorage) {
    const tlv_structure_codec_t codec = {nullptr,
                                         &tlv_reader_format_default,
                                         &tlv_writer_format_default,
                                         nullptr,
                                         nullptr,
                                         0,
                                         2,
                                         decode_pair,
                                         encode_pair};
    const pair_value            value{42, 7};
    tlv::byte                   data[6]{};
    auto                        size = tlv::encode_structure(codec, value, nullptr, 0);
    ASSERT_TRUE(size);
    EXPECT_EQ(6u, *size);
    auto written = tlv::encode_structure(codec, value, data, sizeof(data));
    ASSERT_TRUE(written);
    auto result = tlv::decode_structure<pair_value>(codec, tlv::bytes(data, *written));
    ASSERT_TRUE(result);
    EXPECT_EQ(42, result->first);
    EXPECT_EQ(7, result->second);
    auto failed = tlv::decode_structure<pair_value>(codec, tlv::bytes(data, *written - 1));
    ASSERT_FALSE(failed);
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_STRUCTURE, failed.error());
}
