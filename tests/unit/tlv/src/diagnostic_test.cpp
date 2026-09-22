#include "tlv/diagnostic.h"
#include <gtest/gtest.h>
#include <cstring>

TEST(Unit_Diagnostic, InitSetsCodeAndSeverityAndZeroesEverythingElse) {
    tlv_diagnostic_t diagnostic;
    std::memset(&diagnostic, 0xAA, sizeof(diagnostic));

    tlv_diagnostic_init(&diagnostic, TLV_ERR_END_OF_BUFFER, TLV_DIAGNOSTIC_SEVERITY_WARNING);

    EXPECT_EQ(TLV_ERR_END_OF_BUFFER, diagnostic.code);
    EXPECT_EQ(TLV_DIAGNOSTIC_SEVERITY_WARNING, diagnostic.severity);
    EXPECT_EQ(0, diagnostic.has_offset);
    EXPECT_EQ(0u, diagnostic.offset);
    EXPECT_EQ(nullptr, diagnostic.expected);
    EXPECT_EQ(nullptr, diagnostic.actual);
    EXPECT_EQ(nullptr, diagnostic.contexts);
}

TEST(Unit_Diagnostic, InitIgnoresANullDiagnostic) {
    tlv_diagnostic_init(nullptr, TLV_OK, TLV_DIAGNOSTIC_SEVERITY_ERROR);
}

TEST(Unit_Diagnostic, SetOffsetSetsHasOffsetAndTheOffset) {
    tlv_diagnostic_t diagnostic;
    tlv_diagnostic_init(&diagnostic, TLV_ERR_END_OF_BUFFER, TLV_DIAGNOSTIC_SEVERITY_ERROR);

    tlv_diagnostic_set_offset(&diagnostic, 42);

    EXPECT_NE(0, diagnostic.has_offset);
    EXPECT_EQ(42u, diagnostic.offset);
}

TEST(Unit_Diagnostic, SetOffsetIgnoresANullDiagnostic) {
    tlv_diagnostic_set_offset(nullptr, 42);
}

TEST(Unit_Diagnostic, AddContextPushesOntoTheFrontOfTheChain) {
    tlv_diagnostic_t diagnostic;
    tlv_diagnostic_init(&diagnostic, TLV_ERR_INVALID_LENGTH, TLV_DIAGNOSTIC_SEVERITY_ERROR);

    tlv_diagnostic_context_t ber;
    tlv_diagnostic_add_context(&diagnostic, &ber, "ber", "declared_length", "6");
    EXPECT_EQ(&ber, diagnostic.contexts);
    EXPECT_STREQ("ber", diagnostic.contexts->layer);
    EXPECT_STREQ("declared_length", diagnostic.contexts->key);
    EXPECT_STREQ("6", diagnostic.contexts->value);
    EXPECT_EQ(nullptr, diagnostic.contexts->next);

    tlv_diagnostic_context_t schema;
    tlv_diagnostic_add_context(&diagnostic, &schema, "schema", "field", "AmountAuthorised");
    EXPECT_EQ(&schema, diagnostic.contexts);
    EXPECT_EQ(&ber, diagnostic.contexts->next);
    EXPECT_EQ(nullptr, diagnostic.contexts->next->next);
}

TEST(Unit_Diagnostic, AddContextIgnoresANullDiagnosticOrContext) {
    tlv_diagnostic_t diagnostic;
    tlv_diagnostic_init(&diagnostic, TLV_OK, TLV_DIAGNOSTIC_SEVERITY_INFO);
    tlv_diagnostic_context_t context;

    tlv_diagnostic_add_context(nullptr, &context, "layer", "key", "value");
    tlv_diagnostic_add_context(&diagnostic, nullptr, "layer", "key", "value");

    EXPECT_EQ(nullptr, diagnostic.contexts);
}

TEST(Unit_Diagnostic, SeverityStringNamesEachSeverity) {
    EXPECT_STREQ("error", tlv_diagnostic_severity_string(TLV_DIAGNOSTIC_SEVERITY_ERROR));
    EXPECT_STREQ("warning", tlv_diagnostic_severity_string(TLV_DIAGNOSTIC_SEVERITY_WARNING));
    EXPECT_STREQ("info", tlv_diagnostic_severity_string(TLV_DIAGNOSTIC_SEVERITY_INFO));
}

TEST(Unit_Diagnostic, SeverityStringFallsBackForAnUnrecognizedValue) {
    EXPECT_STREQ("unknown",
                 tlv_diagnostic_severity_string(static_cast<tlv_diagnostic_severity_t>(99)));
}
