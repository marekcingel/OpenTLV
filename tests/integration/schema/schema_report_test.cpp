// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/builtins/asn1/ber.h"
#include "tlv/reader/visitor.h"
#include "tlv/schema/schema.h"
#include <cstring>
#include <gtest/gtest.h>
#include <string>
#include <vector>

extern "C" tlv_result_t tlv_test_schema_unknown_policy(const uint8_t*, size_t, const tlv_format_t*,
                                                       const tlv_structure_schema_t*, int,
                                                       tlv_schema_diagnostic_report_t*);

namespace {
using Wire = std::vector<uint8_t>;

// Template 77: AIP (82) and Application Cryptogram-like tag 9F36 are required, nothing else.
const tlv_schema_entry_t rules77_fields[] = {
    {TLV_TAG(0x82), 2, 2, 0, "aip", 0},
    {TLV_TAG(0x9F, 0x36), 2, 2, 0, "application_cryptogram", 0}};
const tlv_structure_rule_t rules77[] = {
    {&rules77_fields[0], 1, 1, TLV_SCHEMA_PRIMITIVE, nullptr, 0},
    {&rules77_fields[1], 1, 1, TLV_SCHEMA_PRIMITIVE, nullptr, 0}};
const tlv_structure_schema_t schema77 = {rules77, 2, 0, nullptr, 0, TLV_SCHEMA_ORDER_ANY};

// Template 70: 5A required; 5F24 optional once; 77 optional once; 9F4A may repeat.
const tlv_schema_entry_t rules70_fields[] = {
    {TLV_TAG(0x5A), 1, 10, 0, "primary_account_number", 0},
    {TLV_TAG(0x5F, 0x24), 3, 3, 0, "expiration_date", 0},
    {TLV_TAG(0x77), 0, SIZE_MAX, 0, "response_message_template2", 0},
    {TLV_TAG(0x9F, 0x4A), 0, SIZE_MAX, 0, nullptr, 0}};
const tlv_structure_rule_t rules70[] = {
    {&rules70_fields[0], 1, 1, TLV_SCHEMA_PRIMITIVE, nullptr, 0},
    {&rules70_fields[1], 0, 1, TLV_SCHEMA_PRIMITIVE, nullptr, 0},
    {&rules70_fields[2], 0, 1, TLV_SCHEMA_CONSTRUCTED, &schema77, 0},
    {&rules70_fields[3], 0, SIZE_MAX, TLV_SCHEMA_PRIMITIVE, nullptr, 0}};
const tlv_structure_schema_t schema70 = {rules70, 4, 1, nullptr, 0, TLV_SCHEMA_ORDER_ANY};

const tlv_schema_entry_t rootRules_fields[] = {
    {TLV_TAG(0x70), 0, SIZE_MAX, 0, "read_record_template", 0}};
const tlv_structure_rule_t rootRules[] = {
    {&rootRules_fields[0], 1, 1, TLV_SCHEMA_CONSTRUCTED, &schema70, 0}};
const tlv_structure_schema_t rootSchema = {rootRules, 1, 1, nullptr, 0, TLV_SCHEMA_ORDER_ANY};

struct DiagOutcome {
    tlv_result_t                         rc;
    size_t                               count;
    size_t                               errorOffset;
    std::vector<tlv_schema_diagnostic_t> diagnostics;
};

DiagOutcome runDiag(const Wire& wire, const tlv_structure_schema_t& schema = rootSchema,
                    tlv_schema_unknown_policy_t unknown = TLV_SCHEMA_UNKNOWN_BY_SCHEMA,
                    size_t                      capacity = 16) {
    DiagOutcome out{TLV_OK, 99, 99, std::vector<tlv_schema_diagnostic_t>(capacity)};
    tlv_schema_diagnostic_report_t report = {out.diagnostics.data(), capacity, 99};
    tlv_schema_diagnostic_t        failure{};
    out.rc = tlv_schema_validate_all_diag(wire.data(), wire.size(), &tlv_format_ber, &schema,
                                          TLV_TREE_DEFAULT_DEPTH, 1000, unknown, &report, &failure);
    out.errorOffset = failure.diagnostic.location.begin;
    out.count = report.count;
    out.diagnostics.resize(report.count < capacity ? report.count : capacity);
    return out;
}

std::string pathOf(const tlv_schema_diagnostic_t& diagnostic) {
    char   text[64];
    size_t length = 0;
    EXPECT_EQ(TLV_OK,
              tlv_diagnostic_path_string(&diagnostic.diagnostic.path, text, sizeof(text), &length));
    EXPECT_EQ(std::string(text).size(), length);
    return text;
}

// Applications may render a full field path by appending the affected tag.
std::string fullPathOf(const tlv_schema_diagnostic_t& diagnostic) {
    auto path = diagnostic.diagnostic.path;
    EXPECT_EQ(TLV_OK, tlv_diagnostic_path_push(&path, diagnostic.tag));
    char text[128];
    EXPECT_EQ(TLV_OK, tlv_diagnostic_path_string(&path, text, sizeof(text), nullptr));
    return text;
}

const tlv_schema_diagnostic_t* findDiag(const DiagOutcome& out, tlv_schema_issue_kind_t kind) {
    for (const auto& diagnostic : out.diagnostics)
        if (diagnostic.kind == kind) return &diagnostic;
    return nullptr;
}

// 70 09 | 5A 01 12 | 77 04 82 02 00 00
const Wire missing9F36 = {0x70, 0x09, 0x5A, 0x01, 0x12, 0x77, 0x04, 0x82, 0x02, 0x00, 0x00};
// 70 0E | 5A 01 12 | 77 09 82 02 00 00 9F 36 02 00 01
const Wire valid = {0x70, 0x0E, 0x5A, 0x01, 0x12, 0x77, 0x09, 0x82,
                    0x02, 0x00, 0x00, 0x9F, 0x36, 0x02, 0x00, 0x01};
} // namespace

TEST(Integration_Tlv_SchemaReport, EndpointLengthPolicySurvivesDiagnostics) {
    const tlv_schema_entry_t rules_fields[] = {
        {TLV_TAG(0x04), 1, 3, TLV_SCHEMA_LENGTH_ENDPOINTS, "field", 0}};
    const tlv_structure_rule_t rules[] = {
        {&rules_fields[0], 1, 1, TLV_SCHEMA_PRIMITIVE, nullptr, 0}};
    const tlv_structure_schema_t schema = {rules, 1, 0, nullptr, 0, TLV_SCHEMA_ORDER_ANY};
    const auto                   result = runDiag({0x04, 0x02, 0xAA, 0xBB}, schema);
    ASSERT_EQ(1u, result.diagnostics.size());
    const auto& diagnostic = result.diagnostics[0];
    EXPECT_TRUE(diagnostic.has_length);
    EXPECT_EQ(1u, diagnostic.min_length);
    EXPECT_EQ(3u, diagnostic.max_length);
    EXPECT_EQ(2u, diagnostic.actual_length);
    EXPECT_EQ(static_cast<uint32_t>(TLV_SCHEMA_LENGTH_ENDPOINTS), diagnostic.length_flags);
    EXPECT_TRUE(runDiag({0x04, 0x01, 0xAA}, schema).diagnostics.empty());
    EXPECT_TRUE(runDiag({0x04, 0x03, 0xAA, 0xBB, 0xCC}, schema).diagnostics.empty());
}

TEST(Integration_Tlv_SchemaReport, AcceptsConformingTemplateWithoutViolations) {
    DiagOutcome out = runDiag(valid);
    EXPECT_EQ(TLV_OK, out.rc);
    EXPECT_EQ(0u, out.count);
}

TEST(Integration_Tlv_SchemaReport, BorrowedFieldIsAuthoritativeForValidationAndDiagnostics) {
    const tlv_schema_entry_t     field = {TLV_TAG(0x04), 1, 3, TLV_SCHEMA_LENGTH_ENDPOINTS,
                                          "shared",      0};
    const tlv_structure_rule_t   rules[] = {{&field, 1, 1, TLV_SCHEMA_PRIMITIVE, nullptr, 0}};
    const tlv_structure_schema_t schema = {rules, 1, 0, nullptr, 0, TLV_SCHEMA_ORDER_ANY};
    const Wire                   wire = {0x04, 2, 0xAA, 0xBB};
    EXPECT_EQ(&field, rules[0].entry);
    EXPECT_EQ(TLV_ERR_SCHEMA, tlv_schema_validate(wire.data(), wire.size(), &tlv_format_ber,
                                                  &schema, TLV_TREE_DEFAULT_DEPTH, 1000, nullptr));
    const auto result = runDiag(wire, schema);
    ASSERT_EQ(1u, result.diagnostics.size());
    EXPECT_STREQ("shared", result.diagnostics[0].field);
    EXPECT_EQ(1u, result.diagnostics[0].min_length);
    EXPECT_EQ(3u, result.diagnostics[0].max_length);
    EXPECT_EQ(static_cast<uint32_t>(TLV_SCHEMA_LENGTH_ENDPOINTS),
              result.diagnostics[0].length_flags);
    EXPECT_TRUE(runDiag({0x04, 1, 0xAA}, schema).diagnostics.empty());
    const auto missing = runDiag({}, schema);
    ASSERT_EQ(1u, missing.diagnostics.size());
    EXPECT_EQ("", pathOf(missing.diagnostics[0]));
    EXPECT_TRUE(tlv_tag_equal(field.tag, missing.diagnostics[0].tag));
    EXPECT_STREQ("shared", missing.diagnostics[0].field);
}

TEST(Integration_Tlv_SchemaReport, ReportsMissingRequiredTagWithFullPathAndScopeEnd) {
    DiagOutcome out = runDiag(missing9F36);
    ASSERT_EQ(TLV_ERR_SCHEMA, out.rc);
    ASSERT_EQ(1u, out.count);
    EXPECT_EQ(TLV_SCHEMA_ISSUE_MISSING, out.diagnostics[0].kind);
    EXPECT_EQ("70 > 77 > 9F36", fullPathOf(out.diagnostics[0]));
    ASSERT_TRUE(out.diagnostics[0].diagnostic.location.kind);
    EXPECT_EQ(11u, out.diagnostics[0].diagnostic.location.begin); // End of the enclosing 77.
    EXPECT_EQ(TLV_LOCATION_SCOPE_END, out.diagnostics[0].diagnostic.location.kind);
}

TEST(Integration_Tlv_SchemaReport, ReportsMissingTopLevelTagAtScopeEnd) {
    const Wire  wire = {};
    DiagOutcome out = runDiag(wire);
    ASSERT_EQ(TLV_ERR_SCHEMA, out.rc);
    ASSERT_EQ(1u, out.count);
    EXPECT_EQ(TLV_SCHEMA_ISSUE_MISSING, out.diagnostics[0].kind);
    EXPECT_EQ("70", fullPathOf(out.diagnostics[0]));
    EXPECT_TRUE(out.diagnostics[0].diagnostic.location.kind);
    EXPECT_EQ(wire.size(), out.diagnostics[0].diagnostic.location.begin);
}

TEST(Integration_Tlv_SchemaReport, ReportsEmptyContainerRequirements) {
    const Wire  wire = {0x70, 0x00};
    DiagOutcome out = runDiag(wire);
    ASSERT_EQ(1u, out.count);
    EXPECT_EQ("70 > 5A", fullPathOf(out.diagnostics[0]));
    EXPECT_EQ(wire.size(), out.diagnostics[0].diagnostic.location.begin);
}

TEST(Integration_Tlv_SchemaReport,
     ReportsDuplicateAtTheExcessOccurrenceButAllowsConfiguredRepeats) {
    // 70 | 5A 01 12 | 5F24 03 .. | 5F24 03 .. | 9F4A 01 00 | 9F4A 01 01
    Wire wire = {0x70, 0x1A, 0x5A, 0x01, 0x12, 0x5F, 0x24, 0x03, 0x01, 0x02, 0x03, 0x5F, 0x24,
                 0x03, 0x01, 0x02, 0x03, 0x9F, 0x4A, 0x01, 0x00, 0x9F, 0x4A, 0x01, 0x01};
    wire[1] = static_cast<uint8_t>(wire.size() - 2);
    DiagOutcome out = runDiag(wire);
    ASSERT_EQ(TLV_ERR_SCHEMA, out.rc);
    ASSERT_EQ(1u, out.count);
    EXPECT_EQ(TLV_SCHEMA_ISSUE_DUPLICATE, out.diagnostics[0].kind);
    EXPECT_EQ("70 > 5F24", fullPathOf(out.diagnostics[0]));
    EXPECT_EQ(11u, out.diagnostics[0].diagnostic.location.begin);
}

TEST(Integration_Tlv_SchemaReport, ReportsUnexpectedTagAndLengthAndHonoursUnknownPolicy) {
    // 70 | 5A 01 12 | 5F24 02 AA BB (bad length) | 77 .. | 5F 2A 01 00 inside 77
    Wire wire = {0x70, 0x00, 0x5A, 0x01, 0x12, 0x5F, 0x24, 0x02, 0xAA, 0xBB, 0x77, 0x0D, 0x82,
                 0x02, 0x00, 0x00, 0x9F, 0x36, 0x02, 0x00, 0x01, 0x5F, 0x2A, 0x01, 0x00};
    wire[1] = static_cast<uint8_t>(wire.size() - 2);

    DiagOutcome out = runDiag(wire);
    ASSERT_EQ(2u, out.count);
    const tlv_schema_diagnostic_t* length = findDiag(out, TLV_SCHEMA_ISSUE_LENGTH);
    const tlv_schema_diagnostic_t* unexpected = findDiag(out, TLV_SCHEMA_ISSUE_UNEXPECTED);
    ASSERT_NE(nullptr, length);
    ASSERT_NE(nullptr, unexpected);
    EXPECT_EQ("70 > 5F24", fullPathOf(*length));
    EXPECT_EQ(5u, length->diagnostic.location.begin);
    EXPECT_EQ("70 > 77 > 5F2A", fullPathOf(*unexpected));
    EXPECT_EQ(21u, unexpected->diagnostic.location.begin);

    out = runDiag(wire, rootSchema, TLV_SCHEMA_UNKNOWN_ALLOW);
    ASSERT_EQ(1u, out.count);
    EXPECT_EQ(TLV_SCHEMA_ISSUE_LENGTH, out.diagnostics[0].kind);

    // 70 allows unknown tags by its schema; rejecting them everywhere adds a finding there.
    wire.push_back(0x5F);
    wire.push_back(0x2B);
    wire.push_back(0x00);
    wire[1] = static_cast<uint8_t>(wire.size() - 2);
    EXPECT_EQ(2u, runDiag(wire).count);
    EXPECT_EQ(3u, runDiag(wire, rootSchema, TLV_SCHEMA_UNKNOWN_REJECT).count);
}

TEST(Integration_Tlv_SchemaReport, ReportsPrimitiveConstructedMismatchAndDoesNotDescend) {
    static const tlv_schema_entry_t kindRules_fields[] = {
        {TLV_TAG(0x5A), 0, SIZE_MAX, 0, "constructed_field", 0},
        {TLV_TAG(0x6F), 0, SIZE_MAX, 0, "primitive_field", 0}};
    static const tlv_structure_rule_t kindRules[] = {
        {&kindRules_fields[0], 0, 1, TLV_SCHEMA_CONSTRUCTED, nullptr, 0},
        {&kindRules_fields[1], 0, 1, TLV_SCHEMA_PRIMITIVE, nullptr, 0}};
    static const tlv_structure_schema_t kindSchema = {kindRules, 2, 0,
                                                      nullptr,   0, TLV_SCHEMA_ORDER_ANY};
    const Wire                          wire = {0x5A, 0x01, 0x00, 0x6F, 0x00};
    DiagOutcome                         out = runDiag(wire, kindSchema);
    ASSERT_EQ(TLV_ERR_SCHEMA, out.rc);
    ASSERT_EQ(2u, out.count);
    EXPECT_EQ(TLV_SCHEMA_ISSUE_KIND, out.diagnostics[0].kind);
    EXPECT_EQ("5A", fullPathOf(out.diagnostics[0]));
    EXPECT_EQ(0u, out.diagnostics[0].diagnostic.location.begin);
    EXPECT_EQ("6F", fullPathOf(out.diagnostics[1]));
    EXPECT_EQ(3u, out.diagnostics[1].diagnostic.location.begin);
}

TEST(Integration_Tlv_SchemaReport, ReportsSeveralViolationsInOnePass) {
    // 70 | 5F24 02 AA BB | 5F24 03 .. | 77 0D | 82 02 00 00 | 9F36 02 00 01 | 5F2A 01 00
    Wire        wire = {0x70, 0x1A, 0x5F, 0x24, 0x02, 0xAA, 0xBB, 0x5F, 0x24, 0x03,
                        0x01, 0x02, 0x03, 0x77, 0x0D, 0x82, 0x02, 0x00, 0x00, 0x9F,
                        0x36, 0x02, 0x00, 0x01, 0x5F, 0x2A, 0x01, 0x00};
    DiagOutcome out = runDiag(wire);
    ASSERT_EQ(TLV_ERR_SCHEMA, out.rc);
    ASSERT_EQ(4u, out.count);
    ASSERT_NE(nullptr, findDiag(out, TLV_SCHEMA_ISSUE_MISSING));
    ASSERT_NE(nullptr, findDiag(out, TLV_SCHEMA_ISSUE_DUPLICATE));
    ASSERT_NE(nullptr, findDiag(out, TLV_SCHEMA_ISSUE_LENGTH));
    ASSERT_NE(nullptr, findDiag(out, TLV_SCHEMA_ISSUE_UNEXPECTED));
    EXPECT_EQ("70 > 5A", fullPathOf(*findDiag(out, TLV_SCHEMA_ISSUE_MISSING)));
    EXPECT_EQ(wire.size(), findDiag(out, TLV_SCHEMA_ISSUE_MISSING)->diagnostic.location.begin);
    EXPECT_EQ("70 > 5F24", fullPathOf(*findDiag(out, TLV_SCHEMA_ISSUE_DUPLICATE)));
    EXPECT_EQ(7u, findDiag(out, TLV_SCHEMA_ISSUE_DUPLICATE)->diagnostic.location.begin);
    EXPECT_EQ("70 > 77 > 5F2A", fullPathOf(*findDiag(out, TLV_SCHEMA_ISSUE_UNEXPECTED)));
    EXPECT_EQ(24u, findDiag(out, TLV_SCHEMA_ISSUE_UNEXPECTED)->diagnostic.location.begin);
}

TEST(Integration_Tlv_SchemaReport, CountsAllViolationsWhenStorageIsSmaller) {
    const Wire  wire = {0x70, 0x00, 0x70, 0x00};
    DiagOutcome out = runDiag(wire, rootSchema, TLV_SCHEMA_UNKNOWN_BY_SCHEMA, 1);
    EXPECT_EQ(TLV_ERR_SCHEMA, out.rc);
    EXPECT_EQ(3u, out.count); // A duplicate 70, and 5A missing under each 70.
    EXPECT_EQ(1u, out.diagnostics.size());

    tlv_schema_diagnostic_report_t report = {nullptr, 0, 99};
    const Wire                     count_only = {0x70, 0x00};
    EXPECT_EQ(TLV_ERR_SCHEMA,
              tlv_schema_validate_all_diag(count_only.data(), count_only.size(), &tlv_format_ber,
                                           &rootSchema, TLV_TREE_DEFAULT_DEPTH, 1000,
                                           TLV_SCHEMA_UNKNOWN_BY_SCHEMA, &report, nullptr));
    EXPECT_EQ(1u, report.count);
}

TEST(Integration_Tlv_SchemaReport, WireErrorsAbortWithoutViolations) {
    const Wire  wire = {0x70, 0x05, 0x5A, 0x01};
    DiagOutcome out = runDiag(wire);
    EXPECT_NE(TLV_OK, out.rc);
    EXPECT_NE(TLV_ERR_SCHEMA, out.rc);
    EXPECT_EQ(0u, out.count);
    EXPECT_EQ(2u, out.errorOffset);
}

TEST(Integration_Tlv_SchemaReport, RejectsInvalidArgumentsAndRuleTables) {
    const Wire                     wire = valid;
    tlv_schema_diagnostic_t        storage[2];
    tlv_schema_diagnostic_report_t report = {storage, 2, 0};
    auto                           call = [&](const tlv_structure_schema_t* schema, int unknown,
                                              tlv_schema_diagnostic_report_t* r) {
        return tlv_test_schema_unknown_policy(wire.data(), wire.size(), &tlv_format_ber, schema,
                                              unknown, r);
    };
    EXPECT_EQ(TLV_ERR_NULL_ARG, call(&rootSchema, TLV_SCHEMA_UNKNOWN_BY_SCHEMA, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, call(nullptr, TLV_SCHEMA_UNKNOWN_BY_SCHEMA, &report));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, call(&rootSchema, 7, &report));

    const tlv_structure_rule_t   duplicateRules[] = {rootRules[0], rootRules[0]};
    const tlv_structure_schema_t duplicateSchema = {duplicateRules, 2, 1,
                                                    nullptr,        0, TLV_SCHEMA_ORDER_ANY};
    EXPECT_EQ(TLV_ERR_INVALID_SCHEMA,
              call(&duplicateSchema, TLV_SCHEMA_UNKNOWN_BY_SCHEMA, &report));
    EXPECT_EQ(0u, report.count);
    const tlv_structure_schema_t nullRules = {nullptr, 1, 1, nullptr, 0, TLV_SCHEMA_ORDER_ANY};
    EXPECT_EQ(TLV_ERR_INVALID_SCHEMA, call(&nullRules, TLV_SCHEMA_UNKNOWN_BY_SCHEMA, &report));
}

TEST(Integration_Tlv_SchemaReport, LimitsSchemaNestingIndependentlyOfPathCapacity) {
    static tlv_structure_schema_t   recursive;
    static tlv_structure_rule_t     recursiveRules[1];
    static const tlv_schema_entry_t recursiveField = {TLV_TAG(0x6F), 0, SIZE_MAX, 0, nullptr, 0};
    recursiveRules[0] = {&recursiveField, 0, 1, TLV_SCHEMA_CONSTRUCTED, &recursive, 0};
    recursive = {recursiveRules, 1, 0, nullptr, 0, TLV_SCHEMA_ORDER_ANY};

    Wire wire = {0x6F, 0x00};
    for (int i = 1; i < TLV_DIAGNOSTIC_PATH_MAX + 4; ++i) {
        wire.insert(wire.begin(), static_cast<uint8_t>(wire.size()));
        wire.insert(wire.begin(), 0x6F);
    }
    DiagOutcome out = runDiag(wire, recursive);
    EXPECT_EQ(TLV_OK, out.rc);
    EXPECT_EQ(0u, out.count);
    tlv_schema_diagnostic_t        diagnostic{};
    tlv_schema_diagnostic_report_t report{&diagnostic, 1, 0};
    EXPECT_EQ(TLV_ERR_LIMIT,
              tlv_schema_validate_all_diag(wire.data(), wire.size(), &tlv_format_ber, &recursive,
                                           TLV_DIAGNOSTIC_PATH_MAX, 1000,
                                           TLV_SCHEMA_UNKNOWN_BY_SCHEMA, &report, nullptr));
    EXPECT_EQ(0u, report.count);

    Wire shallow = {0x6F, 0x00};
    for (int i = 1; i < TLV_DIAGNOSTIC_PATH_MAX; ++i) {
        shallow.insert(shallow.begin(), static_cast<uint8_t>(shallow.size()));
        shallow.insert(shallow.begin(), 0x6F);
    }
    EXPECT_EQ(TLV_OK, runDiag(shallow, recursive).rc);
}

TEST(Integration_Tlv_SchemaReport, FormatsKindNames) {
    EXPECT_STREQ("missing", tlv_schema_issue_kind_string(TLV_SCHEMA_ISSUE_MISSING));
    EXPECT_STREQ("duplicate", tlv_schema_issue_kind_string(TLV_SCHEMA_ISSUE_DUPLICATE));
    EXPECT_STREQ("unexpected", tlv_schema_issue_kind_string(TLV_SCHEMA_ISSUE_UNEXPECTED));
    EXPECT_STREQ("kind", tlv_schema_issue_kind_string(TLV_SCHEMA_ISSUE_KIND));
    EXPECT_STREQ("length", tlv_schema_issue_kind_string(TLV_SCHEMA_ISSUE_LENGTH));
    EXPECT_STREQ("unknown", tlv_schema_issue_kind_string(static_cast<tlv_schema_issue_kind_t>(99)));
}

TEST(Integration_Tlv_SchemaReport, DiagReportsMissingRequiredTagWithFieldNameAndPath) {
    DiagOutcome out = runDiag(missing9F36);
    ASSERT_EQ(TLV_ERR_SCHEMA, out.rc);
    ASSERT_EQ(1u, out.count);
    const tlv_schema_diagnostic_t& d = out.diagnostics[0];
    EXPECT_EQ(TLV_SCHEMA_ISSUE_MISSING, d.kind);
    EXPECT_EQ(TLV_ERR_SCHEMA, d.diagnostic.code);
    EXPECT_STREQ("application_cryptogram", d.field);
    EXPECT_EQ("70 > 77", pathOf(d));
    EXPECT_TRUE(tlv_tag_equal(d.tag, TLV_TAG(0x9F, 0x36)));
    ASSERT_TRUE(d.diagnostic.location.kind);
    EXPECT_EQ(11u, d.diagnostic.location.begin);
    ASSERT_TRUE(d.has_occurs);
    EXPECT_EQ(1u, d.min_occurs);
    EXPECT_EQ(1u, d.max_occurs);
    EXPECT_EQ(0u, d.occurs);
    EXPECT_FALSE(d.has_length);
    EXPECT_FALSE(d.has_form);
    EXPECT_TRUE(d.diagnostic.has_path); // Caller-attached only; see `path` above.
}

TEST(Integration_Tlv_SchemaReport, DiagReportsMissingTopLevelTagWithEmptyPath) {
    const Wire  wire = {};
    DiagOutcome out = runDiag(wire);
    ASSERT_EQ(1u, out.count);
    const tlv_schema_diagnostic_t& d = out.diagnostics[0];
    EXPECT_STREQ("read_record_template", d.field);
    EXPECT_EQ("", pathOf(d));
    EXPECT_TRUE(d.diagnostic.location.kind);
    EXPECT_EQ(0u, d.diagnostic.location.begin);
    EXPECT_EQ(TLV_LOCATION_SCOPE_END, d.diagnostic.location.kind);
}

TEST(Integration_Tlv_SchemaReport, DiagReportsDuplicateWithOccurrenceCounts) {
    Wire wire = {0x70, 0x1A, 0x5A, 0x01, 0x12, 0x5F, 0x24, 0x03, 0x01, 0x02, 0x03, 0x5F, 0x24,
                 0x03, 0x01, 0x02, 0x03, 0x9F, 0x4A, 0x01, 0x00, 0x9F, 0x4A, 0x01, 0x01};
    wire[1] = static_cast<uint8_t>(wire.size() - 2);
    DiagOutcome out = runDiag(wire);
    ASSERT_EQ(1u, out.count);
    const tlv_schema_diagnostic_t& d = out.diagnostics[0];
    EXPECT_EQ(TLV_SCHEMA_ISSUE_DUPLICATE, d.kind);
    EXPECT_EQ(TLV_ERR_SCHEMA, d.diagnostic.code);
    EXPECT_STREQ("expiration_date", d.field);
    EXPECT_EQ("70", pathOf(d));
    EXPECT_EQ(11u, d.diagnostic.location.begin);
    ASSERT_TRUE(d.has_occurs);
    EXPECT_EQ(0u, d.min_occurs);
    EXPECT_EQ(1u, d.max_occurs);
    EXPECT_EQ(2u, d.occurs);
}

TEST(Integration_Tlv_SchemaReport, DiagReportsLengthAndUnexpectedDetail) {
    Wire wire = {0x70, 0x00, 0x5A, 0x01, 0x12, 0x5F, 0x24, 0x02, 0xAA, 0xBB, 0x77, 0x0D, 0x82,
                 0x02, 0x00, 0x00, 0x9F, 0x36, 0x02, 0x00, 0x01, 0x5F, 0x2A, 0x01, 0x00};
    wire[1] = static_cast<uint8_t>(wire.size() - 2);

    DiagOutcome out = runDiag(wire);
    ASSERT_EQ(2u, out.count);
    const tlv_schema_diagnostic_t* length = findDiag(out, TLV_SCHEMA_ISSUE_LENGTH);
    const tlv_schema_diagnostic_t* unexpected = findDiag(out, TLV_SCHEMA_ISSUE_UNEXPECTED);
    ASSERT_NE(nullptr, length);
    ASSERT_NE(nullptr, unexpected);

    EXPECT_EQ(TLV_ERR_SCHEMA, length->diagnostic.code);
    EXPECT_STREQ("expiration_date", length->field);
    ASSERT_TRUE(length->has_length);
    EXPECT_EQ(3u, length->min_length);
    EXPECT_EQ(3u, length->max_length);
    EXPECT_EQ(2u, length->actual_length);
    EXPECT_FALSE(length->has_occurs);
    EXPECT_FALSE(length->has_form);

    EXPECT_EQ(TLV_ERR_SCHEMA, unexpected->diagnostic.code);
    EXPECT_EQ(nullptr, unexpected->field);
    EXPECT_EQ("70 > 77", pathOf(*unexpected));
    EXPECT_FALSE(unexpected->has_length);
    EXPECT_FALSE(unexpected->has_occurs);
    EXPECT_FALSE(unexpected->has_form);
}

TEST(Integration_Tlv_SchemaReport, DiagReportsPrimitiveConstructedMismatchDetail) {
    static const tlv_schema_entry_t kindRules_fields[] = {
        {TLV_TAG(0x5A), 0, SIZE_MAX, 0, "constructed_field", 0},
        {TLV_TAG(0x6F), 0, SIZE_MAX, 0, "primitive_field", 0}};
    static const tlv_structure_rule_t kindRules[] = {
        {&kindRules_fields[0], 0, 1, TLV_SCHEMA_CONSTRUCTED, nullptr, 0},
        {&kindRules_fields[1], 0, 1, TLV_SCHEMA_PRIMITIVE, nullptr, 0}};
    static const tlv_structure_schema_t kindSchema = {kindRules, 2, 0,
                                                      nullptr,   0, TLV_SCHEMA_ORDER_ANY};
    const Wire                          wire = {0x5A, 0x01, 0x00, 0x6F, 0x00};
    DiagOutcome                         out = runDiag(wire, kindSchema);
    ASSERT_EQ(2u, out.count);

    const tlv_schema_diagnostic_t& constructedExpected = out.diagnostics[0];
    EXPECT_STREQ("constructed_field", constructedExpected.field);
    ASSERT_TRUE(constructedExpected.has_form);
    EXPECT_EQ(TLV_SCHEMA_CONSTRUCTED, constructedExpected.expected_form);
    EXPECT_FALSE(constructedExpected.actual_constructed);

    const tlv_schema_diagnostic_t& primitiveExpected = out.diagnostics[1];
    EXPECT_STREQ("primitive_field", primitiveExpected.field);
    ASSERT_TRUE(primitiveExpected.has_form);
    EXPECT_EQ(TLV_SCHEMA_PRIMITIVE, primitiveExpected.expected_form);
    EXPECT_TRUE(primitiveExpected.actual_constructed);
}

TEST(Integration_Tlv_SchemaReport, DiagCountsAllViolationsWhenStorageIsSmaller) {
    const Wire  wire = {0x70, 0x00, 0x70, 0x00};
    DiagOutcome out = runDiag(wire, rootSchema, TLV_SCHEMA_UNKNOWN_BY_SCHEMA, 1);
    EXPECT_EQ(TLV_ERR_SCHEMA, out.rc);
    EXPECT_EQ(3u, out.count);
    EXPECT_EQ(1u, out.diagnostics.size());
}

TEST(Integration_Tlv_SchemaReport, DiagRejectsInvalidArguments) {
    const Wire                     wire = valid;
    tlv_schema_diagnostic_t        storage[2];
    tlv_schema_diagnostic_report_t report = {storage, 2, 0};
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              tlv_schema_validate_all_diag(wire.data(), wire.size(), &tlv_format_ber, &rootSchema,
                                           TLV_TREE_DEFAULT_DEPTH, 1000,
                                           TLV_SCHEMA_UNKNOWN_BY_SCHEMA, nullptr, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              tlv_schema_validate_all_diag(wire.data(), wire.size(), &tlv_format_ber, nullptr,
                                           TLV_TREE_DEFAULT_DEPTH, 1000,
                                           TLV_SCHEMA_UNKNOWN_BY_SCHEMA, &report, nullptr));

    memset(&storage[0], 0xAB, sizeof(storage[0]));
    tlv_schema_diagnostic_init(&storage[0]);
    EXPECT_EQ(TLV_OK, storage[0].diagnostic.code);
    EXPECT_FALSE(storage[0].diagnostic.location.kind);
    EXPECT_EQ(nullptr, storage[0].field);
}

TEST(Integration_Tlv_SchemaReport, MissingFieldReferenceIsRejectedWithoutDereferencing) {
    const tlv_structure_rule_t   rules[] = {{nullptr, 0, 1, TLV_SCHEMA_ANY, nullptr, 0}};
    const tlv_structure_schema_t schema = {rules, 1, 0, nullptr, 0, TLV_SCHEMA_ORDER_ANY};
    for (const Wire& wire : {Wire{}, Wire{0x04, 0}}) {
        EXPECT_EQ(TLV_ERR_INVALID_SCHEMA,
                  tlv_schema_validate(wire.data(), wire.size(), &tlv_format_ber, &schema, 8, 100,
                                      nullptr));
        const auto report = runDiag(wire, schema);
        EXPECT_EQ(TLV_ERR_INVALID_SCHEMA, report.rc);
        EXPECT_EQ(0u, report.count);
        const auto diagnostics = runDiag(wire, schema);
        EXPECT_EQ(TLV_ERR_INVALID_SCHEMA, diagnostics.rc);
        EXPECT_EQ(0u, diagnostics.count);
    }
}

TEST(Integration_Tlv_SchemaReport, DeepPathsKeepRootPrefixAndCountInnerOmissions) {
    for (size_t depth : {31u, 32u, 33u, 40u, 63u}) {
        SCOPED_TRACE(depth);
        std::vector<uint8_t>                tags(depth);
        std::vector<tlv_schema_entry_t>     entries(depth + 1);
        std::vector<tlv_structure_rule_t>   rules(depth + 1);
        std::vector<tlv_structure_schema_t> schemas(depth + 1);
        entries[depth] = {TLV_TAG(0x04), 1, 1, 0, "leaf", 0};
        rules[depth] = {&entries[depth], 1, 1, TLV_SCHEMA_PRIMITIVE, nullptr, 0};
        schemas[depth] = {&rules[depth], 1, 0, nullptr, 0, TLV_SCHEMA_ORDER_ANY};
        Wire wire = {0x04, 0};
        for (size_t i = depth; i-- > 0;) {
            tags[i] = static_cast<uint8_t>(0xa0 + i % 30);
            entries[i] = {tlv_tag(&tags[i], 1), 0, SIZE_MAX, 0, "container", 0};
            rules[i] = {&entries[i], 1, 1, TLV_SCHEMA_CONSTRUCTED, &schemas[i + 1], 0};
            schemas[i] = {&rules[i], 1, 0, nullptr, 0, TLV_SCHEMA_ORDER_ANY};
            wire.insert(wire.begin(), {tags[i], static_cast<uint8_t>(wire.size())});
        }
        tlv_schema_diagnostic_t        diagnostic{};
        tlv_schema_diagnostic_report_t report{&diagnostic, 1, 0};
        ASSERT_EQ(TLV_ERR_SCHEMA, tlv_schema_validate_all_diag(
                                      wire.data(), wire.size(), &tlv_format_ber, &schemas[0], 64,
                                      100, TLV_SCHEMA_UNKNOWN_BY_SCHEMA, &report, nullptr));
        ASSERT_EQ(1u, report.count);
        const size_t retained = depth < 32 ? depth : 32;
        ASSERT_EQ(retained, diagnostic.diagnostic.path.length);
        EXPECT_EQ(depth - retained, diagnostic.diagnostic.path.omitted);
        for (size_t i = 0; i < retained; ++i)
            EXPECT_TRUE(tlv_tag_equal(tlv_tag(&tags[i], 1), diagnostic.diagnostic.path.tags[i]));

        tlv_schema_diagnostic_t failFast;
        ASSERT_EQ(TLV_ERR_SCHEMA, tlv_schema_validate(wire.data(), wire.size(), &tlv_format_ber,
                                                      &schemas[0], 64, 100, &failFast));
        ASSERT_EQ(retained, failFast.diagnostic.path.length);
        EXPECT_EQ(depth - retained, failFast.diagnostic.path.omitted);
        for (size_t i = 0; i < retained; ++i)
            EXPECT_TRUE(tlv_tag_equal(tlv_tag(&tags[i], 1), failFast.diagnostic.path.tags[i]));
    }
}
