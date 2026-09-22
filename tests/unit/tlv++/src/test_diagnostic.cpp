#include "tlv++/diagnostic.hpp"

#include <gtest/gtest.h>

TEST(Unit_TlvppDiagnostic, MakeDiagnosticSetsCodeAndSeverity) {
    tlv::diagnostic diagnostic =
        tlv::make_diagnostic(TLV_ERR_END_OF_BUFFER, TLV_DIAGNOSTIC_SEVERITY_WARNING);

    EXPECT_EQ(TLV_ERR_END_OF_BUFFER, diagnostic.code);
    EXPECT_EQ(TLV_DIAGNOSTIC_SEVERITY_WARNING, diagnostic.severity);
    EXPECT_EQ(0, diagnostic.has_offset);
    EXPECT_EQ(nullptr, diagnostic.contexts);
}

TEST(Unit_TlvppDiagnostic, AddContextPushesOntoTheFrontOfTheChain) {
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
