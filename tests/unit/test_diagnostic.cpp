// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv++/diagnostic.hpp"

#include <gtest/gtest.h>

TEST(Unit_Tlvpp_Diagnostic, MakeDiagnosticSetsCodeAndSeverity) {
    tlv::diagnostic diagnostic =
        tlv::make_diagnostic(tlv::errc::end_of_input, tlv::severity::warning);

    EXPECT_EQ(tlv::errc::end_of_input, tlv::status(diagnostic));
    EXPECT_EQ(tlv::severity::warning, tlv::severity_of(diagnostic));
    EXPECT_EQ(0, diagnostic.has_offset);
    EXPECT_EQ(nullptr, diagnostic.contexts);
}

TEST(Unit_Tlvpp_Diagnostic, AddContextPushesOntoTheFrontOfTheChain) {
    tlv::diagnostic diagnostic =
        tlv::make_diagnostic(tlv::errc::invalid_length, tlv::severity::error);
    tlv::diagnostic_context ber;
    tlv::diagnostic_context schema;

    tlv::add_context(diagnostic, ber, "ber", "declared_length", "6");
    tlv::add_context(diagnostic, schema, "schema", "field", "AmountAuthorised");

    EXPECT_EQ(&schema, diagnostic.contexts);
    EXPECT_STREQ("schema", diagnostic.contexts->layer);
    EXPECT_EQ(&ber, diagnostic.contexts->next);
    EXPECT_STREQ("ber", diagnostic.contexts->next->layer);
    EXPECT_EQ(nullptr, diagnostic.contexts->next->next);
}

TEST(Unit_Tlvpp_Diagnostic, MakeDiagnosticPathStartsEmpty) {
    tlv::diagnostic_path path = tlv::make_diagnostic_path();

    EXPECT_EQ(0u, path.length);
    EXPECT_EQ(0u, path.omitted);
}

TEST(Unit_Tlvpp_Diagnostic, PushPathAppendsTagsInOrder) {
    tlv::diagnostic_path path = tlv::make_diagnostic_path();

    EXPECT_TRUE(tlv::push_path(path, tlv::tag_bytes<0x6F>()).has_value());
    EXPECT_TRUE(tlv::push_path(path, tlv::tag_bytes<0xA5>()).has_value());

    ASSERT_EQ(2u, path.length);
    EXPECT_TRUE((tlv::path_tag(path, 0) == tlv::tag_bytes<0x6F>()));
    EXPECT_TRUE((tlv::path_tag(path, 1) == tlv::tag_bytes<0xA5>()));
}

TEST(Unit_Tlvpp_Diagnostic, PushPathReturnsAnErrorWhenFull) {
    tlv::diagnostic_path path = tlv::make_diagnostic_path();
    for (size_t i = 0; i < tlv::diagnostic_path_capacity; ++i)
        ASSERT_TRUE(tlv::push_path(path, tlv::tag_bytes<0x01>()).has_value());

    tlv::expected<void, tlv::error> result = tlv::push_path(path, tlv::tag_bytes<0x02>());

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(tlv::errc::limit, result.error().status());
    EXPECT_EQ(1u, path.omitted);
    tlv::pop_path(path);
    EXPECT_EQ(0u, path.omitted);
    EXPECT_EQ(tlv::diagnostic_path_capacity, path.length);
}

TEST(Unit_Tlvpp_Diagnostic, PopPathRemovesTheLastTag) {
    tlv::diagnostic_path path = tlv::make_diagnostic_path();
    tlv::push_path(path, tlv::tag_bytes<0x6F>());
    tlv::push_path(path, tlv::tag_bytes<0xA5>());

    tlv::pop_path(path);

    ASSERT_EQ(1u, path.length);
    EXPECT_TRUE((tlv::path_tag(path, 0) == tlv::tag_bytes<0x6F>()));
}

TEST(Unit_Tlvpp_Diagnostic, SetPathAttachesThePathToTheDiagnostic) {
    tlv::diagnostic diagnostic =
        tlv::make_diagnostic(tlv::errc::end_of_input, tlv::severity::error);
    tlv::diagnostic_path path = tlv::make_diagnostic_path();
    tlv::push_path(path, tlv::tag_bytes<0x6F>());

    tlv::set_path(diagnostic, path);

    ASSERT_EQ(&path, diagnostic.path);
    EXPECT_EQ(1u, diagnostic.path->length);
}
