// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv++/tlv.hpp"
#include <gtest/gtest.h>
#include <type_traits>

namespace {
struct bounded_byte_codec {
    using value_type = uint8_t;
    explicit bounded_byte_codec(uint8_t maximum) : maximum(maximum) {}
    tlv::expected<uint8_t, tlv::codec_errc> decode(tlv::bytes input) const noexcept {
        if (input.size() != 1 || static_cast<unsigned>(input[0]) > maximum)
            return tlv::unexpected<tlv::codec_errc>(tlv::codec_errc::invalid_value);
        return static_cast<uint8_t>(input[0]);
    }
    tlv::expected<size_t, tlv::codec_errc> encode(const uint8_t& value, tlv::byte* output,
                                                  size_t capacity) const noexcept {
        if (value > maximum)
            return tlv::unexpected<tlv::codec_errc>(tlv::codec_errc::invalid_value);
        if (!output && !capacity) return size_t(1);
        if (capacity < 1)
            return tlv::unexpected<tlv::codec_errc>(tlv::codec_errc::buffer_too_short);
        output[0] = static_cast<tlv::byte>(value);
        return size_t(1);
    }
    uint8_t maximum;
};

struct permissive_byte_codec : bounded_byte_codec {
    template <typename... Args>
    explicit permissive_byte_codec(Args&&...) : bounded_byte_codec(uint8_t(sizeof...(Args))) {}
};

using stationary_codec = tlv::codec_owner<permissive_byte_codec>;
static_assert(!std::is_constructible<stationary_codec, stationary_codec&>::value,
              "Mutable owners must not enter the forwarding constructor");
static_assert(!std::is_constructible<stationary_codec, const stationary_codec&>::value,
              "Const owners cannot be copied");
static_assert(!std::is_constructible<stationary_codec, volatile stationary_codec&>::value,
              "Volatile owners must not enter the forwarding constructor");
static_assert(!std::is_constructible<stationary_codec, const volatile stationary_codec&>::value,
              "Const volatile owners must not enter the forwarding constructor");
static_assert(!std::is_constructible<stationary_codec, stationary_codec&&>::value,
              "Owners cannot be moved");
static_assert(!std::is_constructible<stationary_codec, const stationary_codec&&>::value,
              "Const temporary owners must not enter the forwarding constructor");
static_assert(!std::is_constructible<stationary_codec, volatile stationary_codec&&>::value,
              "Volatile temporary owners must not enter the forwarding constructor");
static_assert(!std::is_constructible<stationary_codec, const volatile stationary_codec&&>::value,
              "Const volatile temporary owners must not enter the forwarding constructor");
} // namespace

TEST(Unit_Tlvpp, RuntimeCodecAcceptsDefaultAndMultipleConstructorArguments) {
    stationary_codec default_owner;
    stationary_codec multiple_owner(1, 2);
    const tlv::byte  zero[] = {tlv::byte(0)}, two[] = {tlv::byte(2)};
    EXPECT_EQ(0u, *default_owner.view().decode<uint8_t>({zero, 1}));
    EXPECT_EQ(tlv::codec_errc::invalid_value,
              default_owner.view().decode<uint8_t>({two, 1}).error());
    EXPECT_EQ(2u, *multiple_owner.view().decode<uint8_t>({two, 1}));
}

TEST(Unit_Tlvpp, RuntimeCodecOwnsNonDefaultStateAndPreservesStatus) {
    tlv::codec_owner<bounded_byte_codec> owner(uint8_t(7));
    const auto                           codec = owner.view();
    const tlv::byte                      valid[] = {tlv::byte(6)}, invalid[] = {tlv::byte(8)};
    EXPECT_EQ(6u, *codec.decode<uint8_t>({valid, 1}));
    EXPECT_EQ(tlv::codec_errc::invalid_value, codec.decode<uint8_t>({invalid, 1}).error());
    const auto failure = tlv::to_error(codec.decode<uint8_t>({invalid, 1}).error());
    EXPECT_EQ(tlv::operation::codec, failure.stage());
    EXPECT_EQ(tlv::errc::invalid_value, failure.status());
    EXPECT_EQ(1u, *codec.encode(uint8_t(7)));
    tlv::byte output[1]{};
    EXPECT_EQ(1u, *codec.encode(uint8_t(5), {output, 1}));
    EXPECT_EQ(tlv::byte(5), output[0]);
    static_assert(!std::is_copy_constructible<decltype(owner)>::value,
                  "Codec owners remain stationary");
}

TEST(Unit_Tlvpp, CodecStructureFailureDoesNotImplySchemaValidation) {
    const auto codec_status = tlv::codec_errc::invalid_structure;
    const auto failure = tlv::to_error(codec_status);
    EXPECT_EQ(tlv::errc::invalid_value, failure.status());
    EXPECT_EQ(tlv::operation::codec, failure.stage());
    EXPECT_STREQ(tlv::message(codec_status), failure.message());
}

TEST(Unit_Tlvpp, PublicSchemaReportsMissingFieldAndBoundedViolations) {
    const tlv::schema_storage<2>  schema({{tlv::tag_bytes<1>(),
                                           tlv::bounds::exactly(1),
                                           tlv::bounds::exactly(1),
                                           tlv::schema_kind::primitive,
                                           {},
                                           "first"},
                                          {tlv::tag_bytes<2>(),
                                           tlv::bounds::exactly(2),
                                           tlv::bounds::exactly(1),
                                           tlv::schema_kind::primitive,
                                           {},
                                           "second"}});
    const tlv::fixed_format<1, 1> format;
    const tlv::byte               input[] = {tlv::byte(1), tlv::byte(1), tlv::byte(0x41)};
    auto result = tlv::validate({input, sizeof input}, format, schema.view());
    ASSERT_FALSE(result);
    EXPECT_EQ(tlv::errc::missing_field, result.error().status());
    EXPECT_TRUE(result.error().has_offset());
    EXPECT_EQ(sizeof input, result.error().offset());
    EXPECT_EQ(tlv::operation::schema, result.error().stage());
    tlv::validation_report<1> report;
    auto                      missing = report.validate({}, format, schema.view());
    ASSERT_TRUE(missing);
    EXPECT_EQ(2u, *missing);
    EXPECT_EQ(1u, report.size());
    EXPECT_TRUE(report.truncated());
    auto issue = report.at(0);
    EXPECT_EQ(tlv::schema_issue::missing, issue.kind());
    EXPECT_EQ(0u, issue.occurrences());
    EXPECT_STREQ("first", issue.field());
    EXPECT_THROW(report.at(1), std::out_of_range);
    tlv::validation_report<0> count_only;
    EXPECT_EQ(2u, *count_only.validate({}, format, schema.view()));
}

TEST(Unit_Tlvpp, ErrorCopiesPreserveLocationWithoutOwningText) {
    static_assert(std::is_trivially_copyable<tlv::error>::value,
                  "Errors must not own heap storage");
    const tlv::byte                      input[] = {tlv::byte(1), tlv::byte(4), tlv::byte(0x41)};
    tlv::reader<tlv::fixed_format<1, 1>> reader({input, sizeof input});
    auto                                 result = reader.next();
    ASSERT_FALSE(result);
    EXPECT_EQ(tlv::errc::buffer_too_short, result.error().status());
    EXPECT_TRUE(result.error().has_offset());
    EXPECT_EQ(2u, result.error().offset());
    EXPECT_EQ(tlv::operation::reader, result.error().stage());
    EXPECT_TRUE(result.error().has_tag());
    EXPECT_EQ(tlv::tag_bytes<1>(), result.error().tag());
    EXPECT_EQ(tlv::severity::error, result.error().severity());
    EXPECT_NE(nullptr, result.error().message());
    tlv::reader<tlv::fixed_format<1, 1>> invalid({static_cast<const tlv::byte*>(nullptr), 1});
    EXPECT_FALSE(invalid.at_end());
    EXPECT_EQ(tlv::errc::null_argument, invalid.next().error().status());
    tlv::reader<tlv::fixed_format<1, 1>> incremental({}, tlv::input_mode::incremental);
    EXPECT_FALSE(incremental.at_end());
    EXPECT_EQ(tlv::errc::need_more_data, incremental.next().error().status());
}

TEST(Unit_Tlvpp, WriterFailurePreservesTagAndPosition) {
    tlv::byte                            output[2]{};
    tlv::writer<tlv::fixed_format<1, 1>> writer(output, sizeof output);
    const tlv::byte                      value[] = {tlv::byte(7)};
    const auto written = writer.write(tlv::tag_bytes<3>(), tlv::bytes(value, 1));
    ASSERT_FALSE(written);
    EXPECT_EQ(tlv::errc::buffer_too_short, written.error().status());
    EXPECT_EQ(tlv::operation::writer, written.error().stage());
    ASSERT_TRUE(written.error().has_tag());
    EXPECT_EQ(tlv::tag_bytes<3>(), written.error().tag());
    EXPECT_EQ(0u, writer.size());
}

TEST(Unit_Tlvpp, TreeReaderInitializationFailureIsNotEof) {
    tlv::tree_frame  frames[2]{};
    tlv::tree_reader reader({static_cast<const tlv::byte*>(nullptr), 1}, tlv::fixed_format<1, 1>{},
                            {frames, 2}, 2, 10);
    EXPECT_FALSE(reader.at_end());
    EXPECT_EQ(tlv::errc::null_argument, reader.next().error().status());
}

TEST(Unit_Tlvpp, SchemaIssueCopiesPathBeyondReportLifetime) {
    const tlv::schema_storage<1> child({{tlv::tag_bytes<2>(), tlv::bounds::exactly(1)}});
    const tlv::schema_storage<1> root(
        {{tlv::tag_bytes<0x30>(), {}, {}, tlv::schema_kind::constructed, child.view()}});
    const tlv::byte       input[] = {tlv::byte(0x30), tlv::byte(2), tlv::byte(2), tlv::byte(0)};
    tlv::validation_issue copied;
    {
        tlv::validation_report<1> report;
        ASSERT_TRUE(report.validate({input, sizeof input}, tlv::ber::format{}, root.view()));
        ASSERT_EQ(1u, report.size());
        copied = report.at(0);
    }
    const auto error = copied.error();
    EXPECT_EQ(1u, error.depth());
    EXPECT_EQ(tlv::tag_bytes<0x30>(), error.ancestor(0));
    EXPECT_EQ(tlv::tag_bytes<2>(), error.tag());
    EXPECT_EQ(1u, copied.expected_length().minimum);
    EXPECT_EQ(0u, copied.length());
}

TEST(Unit_Tlvpp, SchemaAlternativeGroupsAndCapacityAreExplicit) {
    tlv::schema_rule first(tlv::tag_bytes<1>()), second(tlv::tag_bytes<2>());
    first.group = second.group = 1;
    const tlv::schema_storage<2, 1> schema({first, second}, tlv::schema_order::any, false,
                                           {{1, tlv::bounds::exactly(1), "choice"}});
    tlv::validation_report<1>       report;
    ASSERT_TRUE(report.validate({}, tlv::fixed_format<1, 1>{}, schema.view()));
    ASSERT_EQ(1u, report.size());
    EXPECT_TRUE(report.at(0).is_group());
    EXPECT_STREQ("choice", report.at(0).field());
    EXPECT_THROW((tlv::schema_storage<1>({first, second})), std::length_error);
}

TEST(Unit_Tlvpp, SchemaRulesComposeLengthAndGroupConstraintsInInitializerLists) {
    const tlv::schema_rule          base(tlv::tag_bytes<1>(), {2, 8});
    const tlv::schema_storage<2, 1> schema(
        {base.with_length_multiple(2).in_group(1),
         tlv::schema_rule(tlv::tag_bytes<2>(), {2, 8}).with_endpoints_only().in_group(1)},
        tlv::schema_order::any, false, {{1, tlv::bounds::exactly(1), "choice"}});
    EXPECT_EQ(0u, base.length_multiple);
    EXPECT_EQ(0u, base.group);
    EXPECT_FALSE(base.endpoints_only);
    EXPECT_FALSE(base.with_endpoints_only().with_endpoints_only(false).endpoints_only);

    const tlv::fixed_format<1, 1> format;
    const tlv::byte               valid_multiple[] = {tlv::byte(1), tlv::byte(4), tlv::byte(0),
                                                      tlv::byte(0), tlv::byte(0), tlv::byte(0)};
    const tlv::byte valid_endpoint[] = {tlv::byte(2), tlv::byte(2), tlv::byte(0), tlv::byte(0)};
    EXPECT_TRUE(tlv::validate({valid_multiple, sizeof valid_multiple}, format, schema.view()));
    EXPECT_TRUE(tlv::validate({valid_endpoint, sizeof valid_endpoint}, format, schema.view()));

    tlv::validation_report<1> report;
    const tlv::byte invalid_multiple[] = {tlv::byte(1), tlv::byte(3), tlv::byte(0), tlv::byte(0),
                                          tlv::byte(0)};
    ASSERT_TRUE(
        report.validate({invalid_multiple, sizeof invalid_multiple}, format, schema.view()));
    ASSERT_EQ(1u, report.size());
    EXPECT_EQ(tlv::schema_issue::length, report.at(0).kind());
    EXPECT_EQ(2u, report.at(0).length_multiple());
    const tlv::byte invalid_endpoint[] = {tlv::byte(2), tlv::byte(4), tlv::byte(0),
                                          tlv::byte(0), tlv::byte(0), tlv::byte(0)};
    ASSERT_TRUE(
        report.validate({invalid_endpoint, sizeof invalid_endpoint}, format, schema.view()));
    ASSERT_EQ(1u, report.size());
    EXPECT_EQ(tlv::schema_issue::length, report.at(0).kind());
    EXPECT_TRUE(report.at(0).length_endpoints_only());
    ASSERT_TRUE(report.validate({}, format, schema.view()));
    ASSERT_EQ(1u, report.size());
    EXPECT_TRUE(report.at(0).is_group());
}

TEST(Unit_Tlvpp, PublicQueryConfigurationBindsTypedVariables) {
    const tlv::fixed_format<1, 1> format;
    tlv::query_environment        environment(format);
    tlv::query_options            options(&environment);
    options.declare("minimum", tlv::query_type::integer);
    auto program = tlv::query_program::compile("count(//01[@len >= $minimum])", options);
    ASSERT_TRUE(program);
    EXPECT_EQ(tlv::query_type::integer, program->result_type());
    auto execution = tlv::query_execution::create(*program, 3, 10, 10000, environment);
    ASSERT_TRUE(execution);
    ASSERT_TRUE(execution->bind("minimum", int64_t(1)));
    const tlv::byte input[] = {tlv::byte(1), tlv::byte(1), tlv::byte(7)};
    auto            document = tlv::document::parse({input, sizeof input}, format);
    ASSERT_TRUE(document);
    tlv::writer_storage<8, 3> storage;
    const auto                workspace = storage.view();
    tlv::byte                 snapshot[8]{};
    const auto evaluated = document->evaluate(*execution, {snapshot, sizeof snapshot}, &workspace);
    ASSERT_TRUE(evaluated) << evaluated.error().message();
    const auto result = execution->scalar();
    ASSERT_TRUE(result);
    EXPECT_EQ(tlv::query_type::integer, result->kind);
    EXPECT_EQ(1, result->integer);
}

#if OPENTLV_EMV
TEST(Unit_Tlvpp, RuntimeDictionaryCodecKeepsContextAndConversionErrors) {
    const tlv::emv::dictionary dictionary;
    auto                       pan = dictionary.find(tlv::tag_bytes<0x5A>());
    ASSERT_TRUE(pan);
    EXPECT_EQ(tlv::emv::value_kind::digits, pan.kind());
    EXPECT_TRUE(pan.codec().readable());
    const tlv::byte wire[] = {tlv::byte(0x12), tlv::byte(0x3F)};
    char            output[5]{};
    auto            decoded =
        pan.codec().decode_into({wire, sizeof wire}, tlv::span<char>(output, sizeof output));
    ASSERT_TRUE(decoded);
    EXPECT_STREQ("123", output);
    char small[1]{};
    auto short_buffer =
        pan.codec().decode_into({wire, sizeof wire}, tlv::span<char>(small, sizeof small));
    ASSERT_FALSE(short_buffer);
    EXPECT_EQ(tlv::codec_errc::buffer_too_short, short_buffer.error());
    EXPECT_FALSE(tlv::emv::dictionary(tlv::emv::context::bht).find(tlv::tag_bytes<0x5A>()));
    EXPECT_FALSE(dictionary.at(dictionary.size()));
    auto unsupported = tlv::dynamic_codec{}.decode<uint64_t>({});
    ASSERT_FALSE(unsupported);
    EXPECT_EQ(tlv::codec_errc::unsupported, unsupported.error());
}
#endif
