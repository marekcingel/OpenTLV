// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/diagnostic.h"
#include "../diagnostic_invariant.h"
#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <vector>

TEST(Unit_Tlv_Diagnostic, InitSetsCodeAndSeverityAndZeroesEverythingElse) {
    tlv_diagnostic_t diagnostic;
    std::memset(&diagnostic, 0xAA, sizeof(diagnostic));

    tlv_diagnostic_init(&diagnostic, TLV_ERR_END_OF_BUFFER, TLV_DIAGNOSTIC_SEVERITY_WARNING);

    EXPECT_EQ(TLV_ERR_END_OF_BUFFER, diagnostic.code);
    EXPECT_EQ(TLV_DIAGNOSTIC_SEVERITY_WARNING, diagnostic.severity);
    EXPECT_EQ(0, diagnostic.location.kind);
    EXPECT_EQ(0u, diagnostic.location.begin);
    EXPECT_EQ(nullptr, diagnostic.expected);
    EXPECT_EQ(nullptr, diagnostic.actual);
    EXPECT_EQ(nullptr, diagnostic.contexts);
}

TEST(Unit_Tlv_Diagnostic, InitIgnoresANullDiagnostic) {
    tlv_diagnostic_init(nullptr, TLV_OK, TLV_DIAGNOSTIC_SEVERITY_ERROR);
}

TEST(Unit_Tlv_Diagnostic, LocationDistinguishesUnknownZeroAndEmptyEofSpan) {
    tlv_diagnostic_t diagnostic{};
    EXPECT_EQ(TLV_LOCATION_UNKNOWN, diagnostic.location.kind);
    tlv_diagnostic_set_location(&diagnostic, TLV_LOCATION_INPUT, TLV_LOCATION_POINT, 0, 0);
    EXPECT_EQ(TLV_LOCATION_POINT, diagnostic.location.kind);
    EXPECT_EQ(TLV_LOCATION_INPUT, diagnostic.location.domain);
    tlv_diagnostic_set_location(&diagnostic, TLV_LOCATION_EXPRESSION, TLV_LOCATION_SPAN, 7, 7);
    EXPECT_EQ(TLV_LOCATION_SPAN, diagnostic.location.kind);
    EXPECT_EQ(7u, diagnostic.location.begin);
    EXPECT_EQ(7u, diagnostic.location.end);
}

TEST(Unit_Tlv_Diagnostic, InvalidOrOverflowingEnrichmentPreservesOriginalFailure) {
    tlv_diagnostic_t diagnostic{};
    tlv_diagnostic_init(&diagnostic, TLV_ERR_SCHEMA, TLV_DIAGNOSTIC_SEVERITY_ERROR);
    tlv_diagnostic_set_location(&diagnostic, TLV_LOCATION_INPUT, TLV_LOCATION_SPAN, 3, 2);
    EXPECT_EQ(TLV_LOCATION_UNKNOWN, diagnostic.location.kind);
    tlv_diagnostic_set_location(&diagnostic, TLV_LOCATION_OUTPUT, TLV_LOCATION_SPAN, SIZE_MAX - 1,
                                SIZE_MAX);
    tlv_location_translate(&diagnostic.location, 1);
    EXPECT_EQ(TLV_LOCATION_UNKNOWN, diagnostic.location.kind);
    EXPECT_EQ(TLV_ERR_SCHEMA, diagnostic.code);
    tlv_diagnostic_set_location(&diagnostic, TLV_LOCATION_INPUT, TLV_LOCATION_SCOPE_END, 2, 2);
    tlv_location_translate(&diagnostic.location, 8);
    EXPECT_EQ(TLV_LOCATION_SCOPE_END, diagnostic.location.kind);
    EXPECT_EQ(10u, diagnostic.location.begin);
    EXPECT_EQ(10u, diagnostic.location.end);
}

TEST(Unit_Tlv_Diagnostic, CopiedDiagnosticOwnsPathAndTruncationState) {
    const uint8_t         tag_bytes[] = {0x30};
    tlv_diagnostic_path_t path{};
    for (size_t i = 0; i < TLV_DIAGNOSTIC_PATH_MAX + 3; ++i)
        (void)tlv_diagnostic_path_push(&path, tlv_tag(tag_bytes, sizeof tag_bytes));
    tlv_diagnostic_t original{};
    tlv_diagnostic_set_path(&original, &path);
    tlv_diagnostic_t copy = original;
    tlv_diagnostic_path_init(&path);
    tlv_diagnostic_set_path(&original, nullptr);
    ASSERT_TRUE(copy.has_path);
    EXPECT_EQ(static_cast<size_t>(TLV_DIAGNOSTIC_PATH_MAX), copy.path.length);
    EXPECT_EQ(3u, copy.path.omitted);
    EXPECT_TRUE(tlv_tag_equal(copy.path.tags[0], tlv_tag(tag_bytes, sizeof tag_bytes)));
    EXPECT_FALSE(original.has_path);
}

TEST(Unit_Tlv_Diagnostic, SetOffsetSetsHasOffsetAndTheOffset) {
    tlv_diagnostic_t diagnostic;
    tlv_diagnostic_init(&diagnostic, TLV_ERR_END_OF_BUFFER, TLV_DIAGNOSTIC_SEVERITY_ERROR);

    tlv_diagnostic_set_location(&diagnostic, TLV_LOCATION_INPUT, TLV_LOCATION_POINT, 42, 42);

    EXPECT_NE(0, diagnostic.location.kind);
    EXPECT_EQ(42u, diagnostic.location.begin);
}

TEST(Unit_Tlv_Diagnostic, SetOffsetIgnoresANullDiagnostic) {
    tlv_diagnostic_set_location(nullptr, TLV_LOCATION_INPUT, TLV_LOCATION_POINT, 42, 42);
}

TEST(Unit_Tlv_Diagnostic, AddContextPushesOntoTheFrontOfTheChain) {
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

TEST(Unit_Tlv_Diagnostic, AddContextIgnoresANullDiagnosticOrContext) {
    tlv_diagnostic_t diagnostic;
    tlv_diagnostic_init(&diagnostic, TLV_OK, TLV_DIAGNOSTIC_SEVERITY_INFO);
    tlv_diagnostic_context_t context;

    tlv_diagnostic_add_context(nullptr, &context, "layer", "key", "value");
    tlv_diagnostic_add_context(&diagnostic, nullptr, "layer", "key", "value");

    EXPECT_EQ(nullptr, diagnostic.contexts);
}

TEST(Unit_Tlv_Diagnostic, SeverityStringNamesEachSeverity) {
    EXPECT_STREQ("error", tlv_diagnostic_severity_string(TLV_DIAGNOSTIC_SEVERITY_ERROR));
    EXPECT_STREQ("warning", tlv_diagnostic_severity_string(TLV_DIAGNOSTIC_SEVERITY_WARNING));
    EXPECT_STREQ("info", tlv_diagnostic_severity_string(TLV_DIAGNOSTIC_SEVERITY_INFO));
}

TEST(Unit_Tlv_Diagnostic, SeverityStringFallsBackForAnUnrecognizedValue) {
    EXPECT_STREQ("unknown",
                 tlv_diagnostic_severity_string(static_cast<tlv_diagnostic_severity_t>(99)));
}

TEST(Unit_Tlv_Diagnostic, SetPathSetsAndClearsTheField) {
    tlv_diagnostic_t diagnostic;
    tlv_diagnostic_init(&diagnostic, TLV_ERR_END_OF_BUFFER, TLV_DIAGNOSTIC_SEVERITY_ERROR);
    tlv_diagnostic_path_t path;
    tlv_diagnostic_path_init(&path);

    tlv_diagnostic_set_path(&diagnostic, &path);
    EXPECT_TRUE(diagnostic.has_path);
    EXPECT_EQ(path.length, diagnostic.path.length);

    tlv_diagnostic_set_path(&diagnostic, nullptr);
    EXPECT_FALSE(diagnostic.has_path);
}

TEST(Unit_Tlv_Diagnostic, SetPathIgnoresANullDiagnostic) {
    tlv_diagnostic_path_t path;
    tlv_diagnostic_path_init(&path);
    tlv_diagnostic_set_path(nullptr, &path);
}

TEST(Unit_Tlv_Diagnostic, PathInitStartsEmpty) {
    tlv_diagnostic_path_t path;
    std::memset(&path, 0xAA, sizeof(path));

    tlv_diagnostic_path_init(&path);

    EXPECT_EQ(0u, path.length);
    EXPECT_EQ(0u, path.omitted);
}

TEST(Unit_Tlv_Diagnostic, PathInitIgnoresANullPath) {
    tlv_diagnostic_path_init(nullptr);
}

TEST(Unit_Tlv_Diagnostic, PathPushAppendsTagsInOrder) {
    tlv_diagnostic_path_t path;
    tlv_diagnostic_path_init(&path);

    EXPECT_EQ(TLV_OK, tlv_diagnostic_path_push(&path, TLV_TAG(0x6F)));
    EXPECT_EQ(TLV_OK, tlv_diagnostic_path_push(&path, TLV_TAG(0xA5)));

    ASSERT_EQ(2u, path.length);
    EXPECT_TRUE(tlv_tag_equal(path.tags[0], TLV_TAG(0x6F)));
    EXPECT_TRUE(tlv_tag_equal(path.tags[1], TLV_TAG(0xA5)));
}

TEST(Unit_Tlv_Diagnostic, PathPushRetainsOutermostTagsAndCountsOmittedTags) {
    tlv_diagnostic_path_t path;
    tlv_diagnostic_path_init(&path);
    for (int i = 0; i < TLV_DIAGNOSTIC_PATH_MAX; ++i)
        ASSERT_EQ(TLV_OK, tlv_diagnostic_path_push(&path, TLV_TAG(0x01)));

    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_diagnostic_path_push(&path, TLV_TAG(0x02)));
    EXPECT_EQ(static_cast<size_t>(TLV_DIAGNOSTIC_PATH_MAX), path.length);
    EXPECT_EQ(1u, path.omitted);
    for (size_t i = 0; i < path.length; ++i)
        EXPECT_TRUE(tlv_tag_equal(path.tags[i], TLV_TAG(0x01)));
}

TEST(Unit_Tlv_Diagnostic, PathPushReturnsNullArgForANullPath) {
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_diagnostic_path_push(nullptr, TLV_TAG(0x6F)));
}

TEST(Unit_Tlv_Diagnostic, PathPopRemovesTheLastTag) {
    tlv_diagnostic_path_t path;
    tlv_diagnostic_path_init(&path);
    tlv_diagnostic_path_push(&path, TLV_TAG(0x6F));
    tlv_diagnostic_path_push(&path, TLV_TAG(0xA5));

    tlv_diagnostic_path_pop(&path);

    ASSERT_EQ(1u, path.length);
    EXPECT_TRUE(tlv_tag_equal(path.tags[0], TLV_TAG(0x6F)));
}

TEST(Unit_Tlv_Diagnostic, PathPopIgnoresAnEmptyOrNullPath) {
    tlv_diagnostic_path_t path;
    tlv_diagnostic_path_init(&path);

    tlv_diagnostic_path_pop(&path);
    EXPECT_EQ(0u, path.length);

    tlv_diagnostic_path_pop(nullptr);
}

TEST(Unit_Tlv_Diagnostic, PathStringFormatsTagsJoinedByArrow) {
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

TEST(Unit_Tlv_Diagnostic, PathStringFormatsAnEmptyPathAsAnEmptyString) {
    tlv_diagnostic_path_t path;
    tlv_diagnostic_path_init(&path);

    char   buffer[8];
    size_t length = 123;
    EXPECT_EQ(TLV_OK, tlv_diagnostic_path_string(&path, buffer, sizeof(buffer), &length));

    EXPECT_STREQ("", buffer);
    EXPECT_EQ(0u, length);
}

TEST(Unit_Tlv_Diagnostic, PathStringReturnsBufferTooShortAndStillReportsTheLength) {
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

TEST(Unit_Tlv_Diagnostic, PathStringRejectsAnInvalidTagInThePath) {
    tlv_diagnostic_path_t path;
    tlv_diagnostic_path_init(&path);
    ASSERT_EQ(TLV_OK, tlv_diagnostic_path_push(&path, tlv_tag(nullptr, 0)));

    char buffer[8];
    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              tlv_diagnostic_path_string(&path, buffer, sizeof(buffer), nullptr));
}

TEST(Unit_Tlv_Diagnostic, PathStringReturnsNullArgForANullPath) {
    char buffer[8];
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              tlv_diagnostic_path_string(nullptr, buffer, sizeof(buffer), nullptr));
}

TEST(Unit_Tlv_Diagnostic, InvariantHelperRejectsEmptyAndMismatchedFailureDetail) {
    tlv_diagnostic_t base{};
    EXPECT_FALSE(test_diagnostic_matches(TLV_ERR_VISITOR, &base));
    base.code = TLV_ERR_INVALID_ARG;
    EXPECT_FALSE(test_diagnostic_matches(TLV_ERR_VISITOR, &base));
    base.code = TLV_ERR_VISITOR;
    EXPECT_TRUE(test_diagnostic_matches(TLV_ERR_VISITOR, &base));
    EXPECT_TRUE(test_diagnostic_matches(TLV_OK, &base));
    tlv_query_diagnostic_t query{};
    EXPECT_FALSE(test_query_diagnostic_matches(TLV_ERR_INVALID_ARG, &query));
    query.kind = TLV_QUERY_ERROR_READER;
    EXPECT_FALSE(test_query_diagnostic_matches(TLV_NEED_MORE_DATA, &query));
    query.diagnostic.code = TLV_NEED_MORE_DATA;
    EXPECT_FALSE(test_query_diagnostic_matches(TLV_NEED_MORE_DATA, &query));
    query.has_reader = 1;
    EXPECT_TRUE(test_query_diagnostic_matches(TLV_NEED_MORE_DATA, &query));
    query.kind = TLV_QUERY_ERROR_CODEC;
    EXPECT_FALSE(test_query_diagnostic_matches(TLV_ERR_INVALID_VALUE, &query));
    query.codec = TLV_CODEC_ERR_INVALID_VALUE;
    query.diagnostic.code = TLV_ERR_INVALID_VALUE;
    EXPECT_TRUE(test_query_diagnostic_matches(TLV_ERR_INVALID_VALUE, &query));
    for (auto kind : {TLV_QUERY_ERROR_EVENTS, TLV_QUERY_ERROR_BINDING, TLV_QUERY_ERROR_READER}) {
        query.kind = kind;
        query.diagnostic.code = TLV_ERR_INVALID_STATE;
        EXPECT_FALSE(test_query_diagnostic_matches(TLV_ERR_INVALID_STATE, &query));
    }
    query.kind = TLV_QUERY_ERROR_STATE;
    query.diagnostic.code = TLV_ERR_INVALID_STATE;
    EXPECT_TRUE(test_query_diagnostic_matches(TLV_ERR_INVALID_STATE, &query));
}

TEST(Unit_Tlv_Diagnostic, QueryCopyOwnsOnePathAndPreservesReaderDetail) {
    uint8_t                tag[] = {0x70};
    tlv_query_diagnostic_t original{};
    original.kind = TLV_QUERY_ERROR_READER;
    original.has_reader = 1;
    original.reader.operation = TLV_READER_OP_VALUE;
    original.reader.has_required = 1;
    original.reader.required = 7;
    tlv_diagnostic_init(&original.diagnostic, TLV_ERR_BUFFER_TOO_SHORT,
                        TLV_DIAGNOSTIC_SEVERITY_ERROR);
    tlv_diagnostic_path_t path{};
    ASSERT_EQ(TLV_OK, tlv_diagnostic_path_push(&path, tlv_tag(tag, sizeof tag)));
    tlv_diagnostic_set_path(&original.diagnostic, &path);
    const tlv_query_diagnostic_t copy = original;
    original = {};
    path = {};
    EXPECT_TRUE(test_query_diagnostic_matches(TLV_ERR_BUFFER_TOO_SHORT, &copy));
    ASSERT_TRUE(copy.diagnostic.has_path);
    ASSERT_EQ(1u, copy.diagnostic.path.length);
    EXPECT_EQ(tag, copy.diagnostic.path.tags[0].data);
    EXPECT_EQ(TLV_READER_OP_VALUE, copy.reader.operation);
    EXPECT_TRUE(copy.reader.has_required);
    EXPECT_EQ(7u, copy.reader.required);
}

TEST(Unit_Tlv_Diagnostic, TruncatedPathUnwindsBeforeReplacingASibling) {
    uint8_t               tags[40]{};
    tlv_diagnostic_path_t path;
    tlv_diagnostic_path_init(&path);
    for (size_t i = 0; i < 40; ++i) {
        tags[i] = static_cast<uint8_t>(i + 1);
        EXPECT_EQ(i < TLV_DIAGNOSTIC_PATH_MAX ? TLV_OK : TLV_ERR_BUFFER_TOO_SHORT,
                  tlv_diagnostic_path_push(&path, tlv_tag(&tags[i], 1)));
    }
    ASSERT_EQ(32u, path.length);
    EXPECT_EQ(8u, path.omitted);
    for (size_t i = 0; i < path.length; ++i) EXPECT_EQ(i + 1, path.tags[i].data[0]);
    for (size_t i = 0; i < 8; ++i) tlv_diagnostic_path_pop(&path);
    EXPECT_EQ(32u, path.length);
    EXPECT_EQ(0u, path.omitted);
    tlv_diagnostic_path_pop(&path);
    EXPECT_EQ(31u, path.length);
    EXPECT_EQ(TLV_OK, tlv_diagnostic_path_push(&path, TLV_TAG(0x77)));
    EXPECT_TRUE(tlv_tag_equal(path.tags[31], TLV_TAG(0x77)));
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_diagnostic_path_push(&path, TLV_TAG(0x88)));
    tlv_diagnostic_path_init(&path);
    EXPECT_EQ(0u, path.length);
    EXPECT_EQ(0u, path.omitted);
}

TEST(Unit_Tlv_Diagnostic, TruncatedPathStringMarksOmissionsAndMeasuresSuffix) {
    tlv_diagnostic_path_t path{};
    for (size_t i = 0; i < 40; ++i)
        ASSERT_EQ(i < TLV_DIAGNOSTIC_PATH_MAX ? TLV_OK : TLV_ERR_BUFFER_TOO_SHORT,
                  tlv_diagnostic_path_push(&path, TLV_TAG(0x6F)));
    std::string expected = "6F";
    for (size_t i = 1; i < 32; ++i) expected += " > 6F";
    expected += " > ...";
    size_t length = 0;
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_diagnostic_path_string(&path, nullptr, 0, &length));
    EXPECT_EQ(expected.size(), length);
    std::vector<char> output(length + 1, 'x');
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              tlv_diagnostic_path_string(&path, output.data(), length, nullptr));
    EXPECT_EQ('\0', output[0]);
    EXPECT_EQ(TLV_OK, tlv_diagnostic_path_string(&path, output.data(), output.size(), &length));
    EXPECT_EQ(expected, output.data());
    path.omitted = SIZE_MAX;
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_diagnostic_path_push(&path, TLV_TAG(0x77)));
    EXPECT_EQ(SIZE_MAX, path.omitted);
}
