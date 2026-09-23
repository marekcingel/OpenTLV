#include "tlv++/diagnostic.hpp"

#include <gtest/gtest.h>

TEST(Unit_Tlvpp_Diagnostic, MakeDiagnosticSetsCodeAndSeverity) {
    tlv::diagnostic diagnostic =
        tlv::make_diagnostic(TLV_ERR_END_OF_BUFFER, TLV_DIAGNOSTIC_SEVERITY_WARNING);

    EXPECT_EQ(TLV_ERR_END_OF_BUFFER, diagnostic.code);
    EXPECT_EQ(TLV_DIAGNOSTIC_SEVERITY_WARNING, diagnostic.severity);
    EXPECT_EQ(0, diagnostic.has_offset);
    EXPECT_EQ(nullptr, diagnostic.contexts);
}

TEST(Unit_Tlvpp_Diagnostic, AddContextPushesOntoTheFrontOfTheChain) {
    tlv::diagnostic diagnostic =
        tlv::make_diagnostic(TLV_ERR_INVALID_LENGTH, TLV_DIAGNOSTIC_SEVERITY_ERROR);
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
}

TEST(Unit_Tlvpp_Diagnostic, PushPathAppendsTagsInOrder) {
    tlv::diagnostic_path path = tlv::make_diagnostic_path();

    EXPECT_TRUE(tlv::push_path(path, TLV_TAG(0x6F)).has_value());
    EXPECT_TRUE(tlv::push_path(path, TLV_TAG(0xA5)).has_value());

    ASSERT_EQ(2u, path.length);
    EXPECT_TRUE(tlv_tag_equal(path.tags[0], TLV_TAG(0x6F)));
    EXPECT_TRUE(tlv_tag_equal(path.tags[1], TLV_TAG(0xA5)));
}

TEST(Unit_Tlvpp_Diagnostic, PushPathReturnsAnErrorWhenFull) {
    tlv::diagnostic_path path = tlv::make_diagnostic_path();
    for (int i = 0; i < TLV_DIAGNOSTIC_PATH_MAX; ++i)
        ASSERT_TRUE(tlv::push_path(path, TLV_TAG(0x01)).has_value());

    tlv::expected<void, tlv::error> result = tlv::push_path(path, TLV_TAG(0x02));

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(TLV_ERR_LIMIT, result.error().code);
}

TEST(Unit_Tlvpp_Diagnostic, PopPathRemovesTheLastTag) {
    tlv::diagnostic_path path = tlv::make_diagnostic_path();
    tlv::push_path(path, TLV_TAG(0x6F));
    tlv::push_path(path, TLV_TAG(0xA5));

    tlv::pop_path(path);

    ASSERT_EQ(1u, path.length);
    EXPECT_TRUE(tlv_tag_equal(path.tags[0], TLV_TAG(0x6F)));
}

TEST(Unit_Tlvpp_Diagnostic, SetPathAttachesThePathToTheDiagnostic) {
    tlv::diagnostic diagnostic =
        tlv::make_diagnostic(TLV_ERR_END_OF_BUFFER, TLV_DIAGNOSTIC_SEVERITY_ERROR);
    tlv::diagnostic_path path = tlv::make_diagnostic_path();
    tlv::push_path(path, TLV_TAG(0x6F));

    tlv::set_path(diagnostic, path);

    ASSERT_EQ(&path, diagnostic.path);
    EXPECT_EQ(1u, diagnostic.path->length);
}
