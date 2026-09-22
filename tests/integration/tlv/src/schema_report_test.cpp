#include "tlv/formats/asn1/ber.h"
#include "tlv/reader/walker.h"
#include "tlv/schemas/schema.h"
#include <cstring>
#include <gtest/gtest.h>
#include <string>
#include <vector>

namespace {
using Wire = std::vector<uint8_t>;

// Template 77: AIP (82) and Application Cryptogram-like tag 9F36 are required, nothing else.
const tlv_structure_rule_t rules77[] = {
    {{TLV_TAG(0x82), 2, 2, 0, "aip"}, 1, 1, TLV_SCHEMA_PRIMITIVE, nullptr},
    {{TLV_TAG(0x9F, 0x36), 2, 2, 0, "application_cryptogram"}, 1, 1, TLV_SCHEMA_PRIMITIVE, nullptr},
};
const tlv_structure_schema_t schema77 = {rules77, 2, 0};

// Template 70: 5A required; 5F24 optional once; 77 optional once; 9F4A may repeat.
const tlv_structure_rule_t rules70[] = {
    {{TLV_TAG(0x5A), 1, 10, 0, "primary_account_number"}, 1, 1, TLV_SCHEMA_PRIMITIVE, nullptr},
    {{TLV_TAG(0x5F, 0x24), 3, 3, 0, "expiration_date"}, 0, 1, TLV_SCHEMA_PRIMITIVE, nullptr},
    {{TLV_TAG(0x77), 0, SIZE_MAX, 0, "response_message_template2"},
     0,
     1,
     TLV_SCHEMA_CONSTRUCTED,
     &schema77},
    {{TLV_TAG(0x9F, 0x4A), 0, SIZE_MAX, 0, nullptr}, 0, SIZE_MAX, TLV_SCHEMA_PRIMITIVE, nullptr},
};
const tlv_structure_schema_t schema70 = {rules70, 4, 1};

const tlv_structure_rule_t rootRules[] = {
    {{TLV_TAG(0x70), 0, SIZE_MAX, 0, "read_record_template"},
     1,
     1,
     TLV_SCHEMA_CONSTRUCTED,
     &schema70},
};
const tlv_structure_schema_t rootSchema = {rootRules, 1, 1};

struct Outcome {
    tlv_result_t                    rc;
    size_t                          count;
    size_t                          errorOffset;
    std::vector<tlv_schema_issue_t> issues;
};

Outcome run(const Wire& wire, const tlv_structure_schema_t& schema = rootSchema,
            tlv_schema_unknown_policy_t unknown = TLV_SCHEMA_UNKNOWN_BY_SCHEMA,
            size_t                      capacity = 16) {
    Outcome             out{TLV_OK, 99, 99, std::vector<tlv_schema_issue_t>(capacity)};
    tlv_schema_report_t report = {out.issues.data(), capacity, 99};
    out.rc = tlv_schema_validate_all(wire.data(), wire.size(), &tlv_reader_format_ber,
                                     tlv_ber_is_constructed, &schema, TLV_WALK_MAX_DEPTH, 1000,
                                     unknown, &report, &out.errorOffset);
    out.count = report.count;
    out.issues.resize(report.count < capacity ? report.count : capacity);
    return out;
}

std::string pathOf(const tlv_schema_issue_t& issue) {
    char   text[64];
    size_t length = 0;
    EXPECT_EQ(TLV_OK, tlv_schema_issue_path_string(&issue, text, sizeof(text), &length));
    EXPECT_EQ(std::string(text).size(), length);
    return text;
}

const tlv_schema_issue_t* find(const Outcome& out, tlv_schema_issue_kind_t kind) {
    for (const auto& issue : out.issues)
        if (issue.kind == kind) return &issue;
    return nullptr;
}

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
    out.rc = tlv_schema_validate_all_diag(wire.data(), wire.size(), &tlv_reader_format_ber,
                                          tlv_ber_is_constructed, &schema, TLV_WALK_MAX_DEPTH, 1000,
                                          unknown, &report, &out.errorOffset);
    out.count = report.count;
    out.diagnostics.resize(report.count < capacity ? report.count : capacity);
    return out;
}

std::string pathOf(const tlv_schema_diagnostic_t& diagnostic) {
    char   text[64];
    size_t length = 0;
    EXPECT_EQ(TLV_OK, tlv_diagnostic_path_string(&diagnostic.path, text, sizeof(text), &length));
    EXPECT_EQ(std::string(text).size(), length);
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

TEST(Integration_SchemaReport, AcceptsConformingTemplateWithoutViolations) {
    Outcome out = run(valid);
    EXPECT_EQ(TLV_OK, out.rc);
    EXPECT_EQ(0u, out.count);
}

TEST(Integration_SchemaReport, ReportsMissingRequiredTagWithFullPathAndParentOffset) {
    Outcome out = run(missing9F36);
    ASSERT_EQ(TLV_ERR_SCHEMA, out.rc);
    ASSERT_EQ(1u, out.count);
    EXPECT_EQ(TLV_SCHEMA_ISSUE_MISSING, out.issues[0].kind);
    EXPECT_EQ("70/77/9F36", pathOf(out.issues[0]));
    ASSERT_TRUE(out.issues[0].has_offset);
    EXPECT_EQ(5u, out.issues[0].offset); // The offset of the enclosing 77.
}

TEST(Integration_SchemaReport, ReportsMissingTopLevelTagWithoutOffset) {
    const Wire wire = {};
    Outcome    out = run(wire);
    ASSERT_EQ(TLV_ERR_SCHEMA, out.rc);
    ASSERT_EQ(1u, out.count);
    EXPECT_EQ(TLV_SCHEMA_ISSUE_MISSING, out.issues[0].kind);
    EXPECT_EQ("70", pathOf(out.issues[0]));
    EXPECT_FALSE(out.issues[0].has_offset);
}

TEST(Integration_SchemaReport, ReportsEmptyContainerRequirements) {
    const Wire wire = {0x70, 0x00};
    Outcome    out = run(wire);
    ASSERT_EQ(1u, out.count);
    EXPECT_EQ("70/5A", pathOf(out.issues[0]));
    EXPECT_EQ(0u, out.issues[0].offset);
}

TEST(Integration_SchemaReport, ReportsDuplicateAtTheExcessOccurrenceButAllowsConfiguredRepeats) {
    // 70 | 5A 01 12 | 5F24 03 .. | 5F24 03 .. | 9F4A 01 00 | 9F4A 01 01
    Wire wire = {0x70, 0x1A, 0x5A, 0x01, 0x12, 0x5F, 0x24, 0x03, 0x01, 0x02, 0x03, 0x5F, 0x24,
                 0x03, 0x01, 0x02, 0x03, 0x9F, 0x4A, 0x01, 0x00, 0x9F, 0x4A, 0x01, 0x01};
    wire[1] = static_cast<uint8_t>(wire.size() - 2);
    Outcome out = run(wire);
    ASSERT_EQ(TLV_ERR_SCHEMA, out.rc);
    ASSERT_EQ(1u, out.count);
    EXPECT_EQ(TLV_SCHEMA_ISSUE_DUPLICATE, out.issues[0].kind);
    EXPECT_EQ("70/5F24", pathOf(out.issues[0]));
    EXPECT_EQ(11u, out.issues[0].offset);
}

TEST(Integration_SchemaReport, ReportsUnexpectedTagAndLengthAndHonoursUnknownPolicy) {
    // 70 | 5A 01 12 | 5F24 02 AA BB (bad length) | 77 .. | 5F 2A 01 00 inside 77
    Wire wire = {0x70, 0x00, 0x5A, 0x01, 0x12, 0x5F, 0x24, 0x02, 0xAA, 0xBB, 0x77, 0x0D, 0x82,
                 0x02, 0x00, 0x00, 0x9F, 0x36, 0x02, 0x00, 0x01, 0x5F, 0x2A, 0x01, 0x00};
    wire[1] = static_cast<uint8_t>(wire.size() - 2);

    Outcome out = run(wire);
    ASSERT_EQ(2u, out.count);
    const tlv_schema_issue_t* length = find(out, TLV_SCHEMA_ISSUE_LENGTH);
    const tlv_schema_issue_t* unexpected = find(out, TLV_SCHEMA_ISSUE_UNEXPECTED);
    ASSERT_NE(nullptr, length);
    ASSERT_NE(nullptr, unexpected);
    EXPECT_EQ("70/5F24", pathOf(*length));
    EXPECT_EQ(5u, length->offset);
    EXPECT_EQ("70/77/5F2A", pathOf(*unexpected));
    EXPECT_EQ(21u, unexpected->offset);

    out = run(wire, rootSchema, TLV_SCHEMA_UNKNOWN_ALLOW);
    ASSERT_EQ(1u, out.count);
    EXPECT_EQ(TLV_SCHEMA_ISSUE_LENGTH, out.issues[0].kind);

    // 70 allows unknown tags by its schema; rejecting them everywhere adds a finding there.
    wire.push_back(0x5F);
    wire.push_back(0x2B);
    wire.push_back(0x00);
    wire[1] = static_cast<uint8_t>(wire.size() - 2);
    EXPECT_EQ(2u, run(wire).count);
    EXPECT_EQ(3u, run(wire, rootSchema, TLV_SCHEMA_UNKNOWN_REJECT).count);
}

TEST(Integration_SchemaReport, ReportsPrimitiveConstructedMismatchAndDoesNotDescend) {
    static const tlv_structure_rule_t kindRules[] = {
        {{TLV_TAG(0x5A), 0, SIZE_MAX, 0, "constructed_field"},
         0,
         1,
         TLV_SCHEMA_CONSTRUCTED,
         nullptr},
        {{TLV_TAG(0x6F), 0, SIZE_MAX, 0, "primitive_field"}, 0, 1, TLV_SCHEMA_PRIMITIVE, nullptr},
    };
    static const tlv_structure_schema_t kindSchema = {kindRules, 2, 0};
    const Wire                          wire = {0x5A, 0x01, 0x00, 0x6F, 0x00};
    Outcome                             out = run(wire, kindSchema);
    ASSERT_EQ(TLV_ERR_SCHEMA, out.rc);
    ASSERT_EQ(2u, out.count);
    EXPECT_EQ(TLV_SCHEMA_ISSUE_KIND, out.issues[0].kind);
    EXPECT_EQ("5A", pathOf(out.issues[0]));
    EXPECT_EQ(0u, out.issues[0].offset);
    EXPECT_EQ("6F", pathOf(out.issues[1]));
    EXPECT_EQ(3u, out.issues[1].offset);
}

TEST(Integration_SchemaReport, ReportsSeveralViolationsInOnePass) {
    // 70 | 5F24 02 AA BB | 5F24 03 .. | 77 0D | 82 02 00 00 | 9F36 02 00 01 | 5F2A 01 00
    Wire    wire = {0x70, 0x1A, 0x5F, 0x24, 0x02, 0xAA, 0xBB, 0x5F, 0x24, 0x03,
                    0x01, 0x02, 0x03, 0x77, 0x0D, 0x82, 0x02, 0x00, 0x00, 0x9F,
                    0x36, 0x02, 0x00, 0x01, 0x5F, 0x2A, 0x01, 0x00};
    Outcome out = run(wire);
    ASSERT_EQ(TLV_ERR_SCHEMA, out.rc);
    ASSERT_EQ(4u, out.count);
    ASSERT_NE(nullptr, find(out, TLV_SCHEMA_ISSUE_MISSING));
    ASSERT_NE(nullptr, find(out, TLV_SCHEMA_ISSUE_DUPLICATE));
    ASSERT_NE(nullptr, find(out, TLV_SCHEMA_ISSUE_LENGTH));
    ASSERT_NE(nullptr, find(out, TLV_SCHEMA_ISSUE_UNEXPECTED));
    EXPECT_EQ("70/5A", pathOf(*find(out, TLV_SCHEMA_ISSUE_MISSING)));
    EXPECT_EQ(0u, find(out, TLV_SCHEMA_ISSUE_MISSING)->offset);
    EXPECT_EQ("70/5F24", pathOf(*find(out, TLV_SCHEMA_ISSUE_DUPLICATE)));
    EXPECT_EQ(7u, find(out, TLV_SCHEMA_ISSUE_DUPLICATE)->offset);
    EXPECT_EQ("70/77/5F2A", pathOf(*find(out, TLV_SCHEMA_ISSUE_UNEXPECTED)));
    EXPECT_EQ(24u, find(out, TLV_SCHEMA_ISSUE_UNEXPECTED)->offset);
}

TEST(Integration_SchemaReport, CountsAllViolationsWhenStorageIsSmaller) {
    const Wire wire = {0x70, 0x00, 0x70, 0x00};
    Outcome    out = run(wire, rootSchema, TLV_SCHEMA_UNKNOWN_BY_SCHEMA, 1);
    EXPECT_EQ(TLV_ERR_SCHEMA, out.rc);
    EXPECT_EQ(3u, out.count); // A duplicate 70, and 5A missing under each 70.
    EXPECT_EQ(1u, out.issues.size());

    tlv_schema_report_t report = {nullptr, 0, 99};
    const Wire          count_only = {0x70, 0x00};
    EXPECT_EQ(TLV_ERR_SCHEMA,
              tlv_schema_validate_all(count_only.data(), count_only.size(), &tlv_reader_format_ber,
                                      tlv_ber_is_constructed, &rootSchema, TLV_WALK_MAX_DEPTH, 1000,
                                      TLV_SCHEMA_UNKNOWN_BY_SCHEMA, &report, nullptr));
    EXPECT_EQ(1u, report.count);
}

TEST(Integration_SchemaReport, WireErrorsAbortWithoutViolations) {
    const Wire wire = {0x70, 0x05, 0x5A, 0x01};
    Outcome    out = run(wire);
    EXPECT_NE(TLV_OK, out.rc);
    EXPECT_NE(TLV_ERR_SCHEMA, out.rc);
    EXPECT_EQ(0u, out.count);
    EXPECT_EQ(0u, out.errorOffset);
}

TEST(Integration_SchemaReport, RejectsInvalidArgumentsAndRuleTables) {
    const Wire          wire = valid;
    tlv_schema_issue_t  storage[2];
    tlv_schema_report_t report = {storage, 2, 0};
    auto call = [&](const tlv_structure_schema_t* schema, tlv_schema_unknown_policy_t unknown,
                    tlv_schema_report_t* r) {
        return tlv_schema_validate_all(wire.data(), wire.size(), &tlv_reader_format_ber,
                                       tlv_ber_is_constructed, schema, TLV_WALK_MAX_DEPTH, 1000,
                                       unknown, r, nullptr);
    };
    EXPECT_EQ(TLV_ERR_NULL_ARG, call(&rootSchema, TLV_SCHEMA_UNKNOWN_BY_SCHEMA, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, call(nullptr, TLV_SCHEMA_UNKNOWN_BY_SCHEMA, &report));
    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              call(&rootSchema, static_cast<tlv_schema_unknown_policy_t>(7), &report));

    const tlv_structure_rule_t   duplicateRules[] = {rootRules[0], rootRules[0]};
    const tlv_structure_schema_t duplicateSchema = {duplicateRules, 2, 1};
    EXPECT_EQ(TLV_ERR_INVALID_ARG, call(&duplicateSchema, TLV_SCHEMA_UNKNOWN_BY_SCHEMA, &report));
    EXPECT_EQ(0u, report.count);
    const tlv_structure_schema_t nullRules = {nullptr, 1, 1};
    EXPECT_EQ(TLV_ERR_INVALID_ARG, call(&nullRules, TLV_SCHEMA_UNKNOWN_BY_SCHEMA, &report));
}

TEST(Integration_SchemaReport, LimitsSchemaNestingToThePathCapacity) {
    static tlv_structure_schema_t recursive;
    static tlv_structure_rule_t   recursiveRules[1];
    recursiveRules[0] = {
        {TLV_TAG(0x6F), 0, SIZE_MAX, 0, nullptr}, 0, 1, TLV_SCHEMA_CONSTRUCTED, &recursive};
    recursive = {recursiveRules, 1, 0};

    Wire wire = {0x6F, 0x00};
    for (int i = 1; i < TLV_SCHEMA_PATH_MAX + 4; ++i) {
        wire.insert(wire.begin(), static_cast<uint8_t>(wire.size()));
        wire.insert(wire.begin(), 0x6F);
    }
    Outcome out = run(wire, recursive);
    EXPECT_EQ(TLV_ERR_LIMIT, out.rc);
    EXPECT_EQ(0u, out.count);

    Wire shallow = {0x6F, 0x00};
    for (int i = 1; i < TLV_SCHEMA_PATH_MAX - 1; ++i) {
        shallow.insert(shallow.begin(), static_cast<uint8_t>(shallow.size()));
        shallow.insert(shallow.begin(), 0x6F);
    }
    EXPECT_EQ(TLV_OK, run(shallow, recursive).rc);
}

TEST(Integration_SchemaReport, FormatsPathsAndKindNames) {
    tlv_schema_issue_t issue = {};
    issue.kind = TLV_SCHEMA_ISSUE_MISSING;
    issue.path[0] = TLV_TAG(0x70);
    issue.path[1] = TLV_TAG(0x77);
    issue.path[2] = TLV_TAG(0x9F, 0x36);
    issue.path_length = 3;

    char   text[16];
    size_t length = 0;
    EXPECT_EQ(TLV_OK, tlv_schema_issue_path_string(&issue, text, sizeof(text), &length));
    EXPECT_STREQ("70/77/9F36", text);
    EXPECT_EQ(10u, length);

    char small[10];
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              tlv_schema_issue_path_string(&issue, small, sizeof(small), &length));
    EXPECT_EQ(10u, length);
    // A NULL destination with zero capacity only measures the text.
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_schema_issue_path_string(&issue, nullptr, 0, &length));
    EXPECT_EQ(10u, length);
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_schema_issue_path_string(nullptr, text, sizeof(text), &length));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_schema_issue_path_string(&issue, nullptr, 4, &length));
    issue.path_length = 0;
    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              tlv_schema_issue_path_string(&issue, text, sizeof(text), &length));

    EXPECT_STREQ("missing", tlv_schema_issue_kind_string(TLV_SCHEMA_ISSUE_MISSING));
    EXPECT_STREQ("duplicate", tlv_schema_issue_kind_string(TLV_SCHEMA_ISSUE_DUPLICATE));
    EXPECT_STREQ("unexpected", tlv_schema_issue_kind_string(TLV_SCHEMA_ISSUE_UNEXPECTED));
    EXPECT_STREQ("kind", tlv_schema_issue_kind_string(TLV_SCHEMA_ISSUE_KIND));
    EXPECT_STREQ("length", tlv_schema_issue_kind_string(TLV_SCHEMA_ISSUE_LENGTH));
    EXPECT_STREQ("unknown", tlv_schema_issue_kind_string(static_cast<tlv_schema_issue_kind_t>(0)));
}

TEST(Integration_SchemaReport, DiagReportsMissingRequiredTagWithFieldNameAndPath) {
    DiagOutcome out = runDiag(missing9F36);
    ASSERT_EQ(TLV_ERR_SCHEMA, out.rc);
    ASSERT_EQ(1u, out.count);
    const tlv_schema_diagnostic_t& d = out.diagnostics[0];
    EXPECT_EQ(TLV_SCHEMA_ISSUE_MISSING, d.kind);
    EXPECT_EQ(TLV_ERR_SCHEMA_MISSING, d.diagnostic.code);
    EXPECT_STREQ("application_cryptogram", d.field);
    EXPECT_EQ("70 > 77", pathOf(d));
    EXPECT_TRUE(tlv_tag_equal(d.tag, TLV_TAG(0x9F, 0x36)));
    ASSERT_TRUE(d.diagnostic.has_offset);
    EXPECT_EQ(5u, d.diagnostic.offset);
    ASSERT_TRUE(d.has_occurs);
    EXPECT_EQ(1u, d.min_occurs);
    EXPECT_EQ(1u, d.max_occurs);
    EXPECT_EQ(0u, d.occurs);
    EXPECT_FALSE(d.has_length);
    EXPECT_FALSE(d.has_form);
    EXPECT_EQ(nullptr, d.diagnostic.path); // Caller-attached only; see `path` above.
}

TEST(Integration_SchemaReport, DiagReportsMissingTopLevelTagWithEmptyPath) {
    const Wire  wire = {};
    DiagOutcome out = runDiag(wire);
    ASSERT_EQ(1u, out.count);
    const tlv_schema_diagnostic_t& d = out.diagnostics[0];
    EXPECT_STREQ("read_record_template", d.field);
    EXPECT_EQ("", pathOf(d));
    EXPECT_FALSE(d.diagnostic.has_offset);
}

TEST(Integration_SchemaReport, DiagReportsDuplicateWithOccurrenceCounts) {
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
    EXPECT_EQ(11u, d.diagnostic.offset);
    ASSERT_TRUE(d.has_occurs);
    EXPECT_EQ(0u, d.min_occurs);
    EXPECT_EQ(1u, d.max_occurs);
    EXPECT_EQ(2u, d.occurs);
}

TEST(Integration_SchemaReport, DiagReportsLengthAndUnexpectedDetail) {
    Wire wire = {0x70, 0x00, 0x5A, 0x01, 0x12, 0x5F, 0x24, 0x02, 0xAA, 0xBB, 0x77, 0x0D, 0x82,
                 0x02, 0x00, 0x00, 0x9F, 0x36, 0x02, 0x00, 0x01, 0x5F, 0x2A, 0x01, 0x00};
    wire[1] = static_cast<uint8_t>(wire.size() - 2);

    DiagOutcome out = runDiag(wire);
    ASSERT_EQ(2u, out.count);
    const tlv_schema_diagnostic_t* length = findDiag(out, TLV_SCHEMA_ISSUE_LENGTH);
    const tlv_schema_diagnostic_t* unexpected = findDiag(out, TLV_SCHEMA_ISSUE_UNEXPECTED);
    ASSERT_NE(nullptr, length);
    ASSERT_NE(nullptr, unexpected);

    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, length->diagnostic.code);
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

TEST(Integration_SchemaReport, DiagReportsPrimitiveConstructedMismatchDetail) {
    static const tlv_structure_rule_t kindRules[] = {
        {{TLV_TAG(0x5A), 0, SIZE_MAX, 0, "constructed_field"},
         0,
         1,
         TLV_SCHEMA_CONSTRUCTED,
         nullptr},
        {{TLV_TAG(0x6F), 0, SIZE_MAX, 0, "primitive_field"}, 0, 1, TLV_SCHEMA_PRIMITIVE, nullptr},
    };
    static const tlv_structure_schema_t kindSchema = {kindRules, 2, 0};
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

TEST(Integration_SchemaReport, DiagCountsAllViolationsWhenStorageIsSmaller) {
    const Wire  wire = {0x70, 0x00, 0x70, 0x00};
    DiagOutcome out = runDiag(wire, rootSchema, TLV_SCHEMA_UNKNOWN_BY_SCHEMA, 1);
    EXPECT_EQ(TLV_ERR_SCHEMA, out.rc);
    EXPECT_EQ(3u, out.count);
    EXPECT_EQ(1u, out.diagnostics.size());
}

TEST(Integration_SchemaReport, DiagRejectsInvalidArguments) {
    const Wire                     wire = valid;
    tlv_schema_diagnostic_t        storage[2];
    tlv_schema_diagnostic_report_t report = {storage, 2, 0};
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              tlv_schema_validate_all_diag(wire.data(), wire.size(), &tlv_reader_format_ber,
                                           tlv_ber_is_constructed, &rootSchema, TLV_WALK_MAX_DEPTH,
                                           1000, TLV_SCHEMA_UNKNOWN_BY_SCHEMA, nullptr, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              tlv_schema_validate_all_diag(wire.data(), wire.size(), &tlv_reader_format_ber,
                                           tlv_ber_is_constructed, nullptr, TLV_WALK_MAX_DEPTH,
                                           1000, TLV_SCHEMA_UNKNOWN_BY_SCHEMA, &report, nullptr));

    memset(&storage[0], 0xAB, sizeof(storage[0]));
    tlv_schema_diagnostic_init(&storage[0]);
    EXPECT_EQ(TLV_OK, storage[0].diagnostic.code);
    EXPECT_FALSE(storage[0].diagnostic.has_offset);
    EXPECT_EQ(nullptr, storage[0].field);
}
