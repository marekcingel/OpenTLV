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

TEST(Unit_Diagnostic, SetPathSetsAndClearsTheField) {
    tlv_diagnostic_t diagnostic;
    tlv_diagnostic_init(&diagnostic, TLV_ERR_END_OF_BUFFER, TLV_DIAGNOSTIC_SEVERITY_ERROR);
    tlv_diagnostic_path_t path;
    tlv_diagnostic_path_init(&path);

    tlv_diagnostic_set_path(&diagnostic, &path);
    EXPECT_EQ(&path, diagnostic.path);

    tlv_diagnostic_set_path(&diagnostic, nullptr);
    EXPECT_EQ(nullptr, diagnostic.path);
}

TEST(Unit_Diagnostic, SetPathIgnoresANullDiagnostic) {
    tlv_diagnostic_path_t path;
    tlv_diagnostic_path_init(&path);
    tlv_diagnostic_set_path(nullptr, &path);
}

TEST(Unit_Diagnostic, PathInitStartsEmpty) {
    tlv_diagnostic_path_t path;
    std::memset(&path, 0xAA, sizeof(path));

    tlv_diagnostic_path_init(&path);

    EXPECT_EQ(0u, path.length);
}

TEST(Unit_Diagnostic, PathInitIgnoresANullPath) {
    tlv_diagnostic_path_init(nullptr);
}

TEST(Unit_Diagnostic, PathPushAppendsTagsInOrder) {
    tlv_diagnostic_path_t path;
    tlv_diagnostic_path_init(&path);

    EXPECT_EQ(TLV_OK, tlv_diagnostic_path_push(&path, TLV_TAG(0x6F)));
    EXPECT_EQ(TLV_OK, tlv_diagnostic_path_push(&path, TLV_TAG(0xA5)));

    ASSERT_EQ(2u, path.length);
    EXPECT_TRUE(tlv_tag_equal(path.tags[0], TLV_TAG(0x6F)));
    EXPECT_TRUE(tlv_tag_equal(path.tags[1], TLV_TAG(0xA5)));
}

TEST(Unit_Diagnostic, PathPushReturnsLimitWhenFullAndLeavesThePathUnchanged) {
    tlv_diagnostic_path_t path;
    tlv_diagnostic_path_init(&path);
    for (int i = 0; i < TLV_DIAGNOSTIC_PATH_MAX; ++i)
        ASSERT_EQ(TLV_OK, tlv_diagnostic_path_push(&path, TLV_TAG(0x01)));

    EXPECT_EQ(TLV_ERR_LIMIT, tlv_diagnostic_path_push(&path, TLV_TAG(0x02)));
    EXPECT_EQ(static_cast<size_t>(TLV_DIAGNOSTIC_PATH_MAX), path.length);
}

TEST(Unit_Diagnostic, PathPushReturnsNullArgForANullPath) {
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_diagnostic_path_push(nullptr, TLV_TAG(0x6F)));
}

TEST(Unit_Diagnostic, PathPopRemovesTheLastTag) {
    tlv_diagnostic_path_t path;
    tlv_diagnostic_path_init(&path);
    tlv_diagnostic_path_push(&path, TLV_TAG(0x6F));
    tlv_diagnostic_path_push(&path, TLV_TAG(0xA5));

    tlv_diagnostic_path_pop(&path);

    ASSERT_EQ(1u, path.length);
    EXPECT_TRUE(tlv_tag_equal(path.tags[0], TLV_TAG(0x6F)));
}

TEST(Unit_Diagnostic, PathPopIgnoresAnEmptyOrNullPath) {
    tlv_diagnostic_path_t path;
    tlv_diagnostic_path_init(&path);

    tlv_diagnostic_path_pop(&path);
    EXPECT_EQ(0u, path.length);

    tlv_diagnostic_path_pop(nullptr);
}

TEST(Unit_Diagnostic, PathStringFormatsTagsJoinedByArrow) {
    tlv_diagnostic_path_t path;
    tlv_diagnostic_path_init(&path);
    tlv_diagnostic_path_push(&path, TLV_TAG(0x6F));
    tlv_diagnostic_path_push(&path, TLV_TAG(0xA5));
    tlv_diagnostic_path_push(&path, TLV_TAG(0xBF, 0x0C));

    char   buffer[64];
    size_t length = 0;
    EXPECT_EQ(TLV_OK, tlv_diagnostic_path_string(&path, buffer, sizeof(buffer), &length));

    EXPECT_STREQ("6F > A5 > BF0C", buffer);
    EXPECT_EQ(std::strlen(buffer), length);
}

TEST(Unit_Diagnostic, PathStringFormatsAnEmptyPathAsAnEmptyString) {
    tlv_diagnostic_path_t path;
    tlv_diagnostic_path_init(&path);

    char   buffer[8];
    size_t length = 123;
    EXPECT_EQ(TLV_OK, tlv_diagnostic_path_string(&path, buffer, sizeof(buffer), &length));

    EXPECT_STREQ("", buffer);
    EXPECT_EQ(0u, length);
}

TEST(Unit_Diagnostic, PathStringReturnsBufferTooShortAndStillReportsTheLength) {
    tlv_diagnostic_path_t path;
    tlv_diagnostic_path_init(&path);
    tlv_diagnostic_path_push(&path, TLV_TAG(0x6F));
    tlv_diagnostic_path_push(&path, TLV_TAG(0xA5));

    char   buffer[4];
    size_t length = 0;
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              tlv_diagnostic_path_string(&path, buffer, sizeof(buffer), &length));

    EXPECT_EQ(std::strlen("6F > A5"), length);
}

TEST(Unit_Diagnostic, PathStringRejectsAnInvalidTagInThePath) {
    tlv_diagnostic_path_t path;
    tlv_diagnostic_path_init(&path);
    ASSERT_EQ(TLV_OK, tlv_diagnostic_path_push(&path, tlv_tag(nullptr, 0)));

    char buffer[8];
    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              tlv_diagnostic_path_string(&path, buffer, sizeof(buffer), nullptr));
}

TEST(Unit_Diagnostic, PathStringReturnsNullArgForANullPath) {
    char buffer[8];
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              tlv_diagnostic_path_string(nullptr, buffer, sizeof(buffer), nullptr));
}
