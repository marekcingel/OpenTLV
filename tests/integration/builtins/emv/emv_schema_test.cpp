#include "tlv/builtins/asn1/ber.h"
#include "tlv/builtins/emv/emv_schema.h"
#include "tlv/reader/walker.h"
#include <gtest/gtest.h>
#include <vector>

namespace {
tlv_result_t validate(const std::vector<uint8_t>& wire, size_t* offset = nullptr) {
    return tlv_schema_validate(wire.data(), wire.size(), &tlv_reader_format_ber,
                               tlv_ber_is_constructed, &tlv_emv_structure_schema,
                               TLV_WALK_MAX_DEPTH, 1000, offset);
}
} // namespace

TEST(Integration_Tlv_EmvSchema, AcceptsAnFciTemplateWithJustAMandatoryDfName) {
    // 6F 09 | 84 07 A0 00 00 00 03 10 10 (DF Name, an AID)
    const std::vector<uint8_t> wire{0x6F, 0x09, 0x84, 0x07, 0xA0, 0x00,
                                    0x00, 0x00, 0x03, 0x10, 0x10};
    EXPECT_EQ(TLV_OK, validate(wire));
}

TEST(Integration_Tlv_EmvSchema, RejectsAnFciTemplateMissingTheMandatoryDfName) {
    const std::vector<uint8_t> wire{0x6F, 0x00};
    size_t                     offset = 99;
    EXPECT_EQ(TLV_ERR_SCHEMA_MISSING, validate(wire, &offset));
    EXPECT_EQ(2u, offset); // The end of the empty FCI Template's value.
}

TEST(Integration_Tlv_EmvSchema, RejectsATagForbiddenDirectlyUnderTheFciTemplate) {
    // 6F 0C | 84 07 <AID> | 50 01 41 (Application Label does not belong here)
    const std::vector<uint8_t> wire{0x6F, 0x0C, 0x84, 0x07, 0xA0, 0x00, 0x00,
                                    0x00, 0x03, 0x10, 0x10, 0x50, 0x01, 0x41};
    size_t                     offset = 0;
    EXPECT_EQ(TLV_ERR_SCHEMA, validate(wire, &offset));
    EXPECT_EQ(11u, offset); // Where the forbidden 50 tag begins.
}

TEST(Integration_Tlv_EmvSchema, RejectsADuplicateDfNameInsideOneFciTemplate) {
    const std::vector<uint8_t> wire{0x6F, 0x12, 0x84, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x10,
                                    0x10, 0x84, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10};
    EXPECT_EQ(TLV_ERR_SCHEMA, validate(wire));
}

TEST(Integration_Tlv_EmvSchema, RejectsADfNameShorterThanTheDictionaryMinimum) {
    // DF Name's dictionary length is 5..16; two bytes is too short.
    const std::vector<uint8_t> wire{0x6F, 0x04, 0x84, 0x02, 0xAA, 0xBB};
    size_t                     offset = 0;
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, validate(wire, &offset));
    EXPECT_EQ(2u, offset);
}

TEST(Integration_Tlv_EmvSchema, AcceptsAnFciProprietaryTemplateNestedInsideTheFci) {
    // 6F 0C | 84 05 3132333435 | A5 03 | 50 01 41 (Application Label)
    const std::vector<uint8_t> wire{0x6F, 0x0C, 0x84, 0x05, 0x31, 0x32, 0x33,
                                    0x34, 0x35, 0xA5, 0x03, 0x50, 0x01, 0x41};
    EXPECT_EQ(TLV_OK, validate(wire));
}

TEST(Integration_Tlv_EmvSchema, AcceptsAnUnknownProprietaryTagInsideTheFciProprietaryTemplate) {
    // 6F 0D | 84 05 3132333435 | A5 04 | DF 01 01 00 (kernel-specific, not in the dictionary)
    const std::vector<uint8_t> wire{0x6F, 0x0D, 0x84, 0x05, 0x31, 0x32, 0x33, 0x34,
                                    0x35, 0xA5, 0x04, 0xDF, 0x01, 0x01, 0x00};
    EXPECT_EQ(TLV_OK, validate(wire));
}

TEST(Integration_Tlv_EmvSchema, AcceptsAGpoResponseFormat2WithExactlyAipAndAfl) {
    // 77 0A | 82 02 1980 (AIP) | 94 04 08010100 (AFL)
    const std::vector<uint8_t> wire{0x77, 0x0A, 0x82, 0x02, 0x19, 0x80,
                                    0x94, 0x04, 0x08, 0x01, 0x01, 0x00};
    EXPECT_EQ(TLV_OK, validate(wire));
}

TEST(Integration_Tlv_EmvSchema, RejectsAGpoResponseFormat2MissingTheMandatoryAfl) {
    const std::vector<uint8_t> wire{0x77, 0x04, 0x82, 0x02, 0x19, 0x80};
    EXPECT_EQ(TLV_ERR_SCHEMA_MISSING, validate(wire));
}

TEST(Integration_Tlv_EmvSchema, AcceptsUnmodeledTopLevelTagsUnchecked) {
    // The Read Record Template (70) has no modeled child rules: any framed
    // BER content is accepted at the root, including tags outside the
    // dictionary and even an empty value.
    const std::vector<uint8_t> wire{0x70, 0x03, 0xDF, 0x01, 0x00};
    EXPECT_EQ(TLV_OK, validate(wire));
}

TEST(Integration_Tlv_EmvSchema, MissingFieldReportsTheDistinctCodeEvenWhenASiblingFollows) {
    // A malformed, empty FCI Template immediately followed by a valid GPO
    // response: the missing-DF-Name offset (2) is also where the next
    // sibling happens to start, so the distinct TLV_ERR_SCHEMA_MISSING code
    // (rather than TLV_ERR_SCHEMA) is what tells a caller not to treat a tag
    // read at that offset as the cause.
    const std::vector<uint8_t> wire{0x6F, 0x00, 0x77, 0x0A, 0x82, 0x02, 0x19,
                                    0x80, 0x94, 0x04, 0x08, 0x01, 0x01, 0x00};
    size_t                     offset = 0;
    EXPECT_EQ(TLV_ERR_SCHEMA_MISSING, validate(wire, &offset));
    EXPECT_EQ(2u, offset);
}

TEST(Integration_Tlv_EmvSchema, AcceptsSeveralTopLevelTemplatesConcatenated) {
    const std::vector<uint8_t> wire{0x6F, 0x02, 0x84, 0x00, // Malformed FCI is unreachable below.
                                    0x77, 0x0A, 0x82, 0x02, 0x19, 0x80,
                                    0x94, 0x04, 0x08, 0x01, 0x01, 0x00};
    // The malformed FCI (DF Name too short) is caught before the second element.
    size_t offset = 0;
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, validate(wire, &offset));
    EXPECT_EQ(2u, offset);
}

TEST(Integration_Tlv_EmvSchema, ReportsFciViolationsWithPathsInOnePass) {
    // 6F 08 | 50 01 41 (unexpected under 6F) | A5 03 87 01 01 (valid); DF Name is missing
    const std::vector<uint8_t> wire{0x6F, 0x08, 0x50, 0x01, 0x41, 0xA5, 0x03, 0x87, 0x01, 0x01};
    tlv_schema_issue_t         issues[4];
    tlv_schema_report_t        report = {issues, 4, 0};
    EXPECT_EQ(TLV_ERR_SCHEMA,
              tlv_schema_validate_all(wire.data(), wire.size(), &tlv_reader_format_ber,
                                      tlv_ber_is_constructed, &tlv_emv_structure_schema,
                                      TLV_WALK_MAX_DEPTH, 1000, TLV_SCHEMA_UNKNOWN_BY_SCHEMA,
                                      &report, nullptr));
    ASSERT_EQ(2u, report.count);
    char text[32];
    for (size_t i = 0; i < report.count; ++i) {
        ASSERT_EQ(TLV_OK, tlv_schema_issue_path_string(&issues[i], text, sizeof(text), nullptr));
        if (issues[i].kind == TLV_SCHEMA_ISSUE_MISSING) {
            EXPECT_STREQ("6F/84", text);
            EXPECT_EQ(0u, issues[i].offset);
        } else {
            EXPECT_EQ(TLV_SCHEMA_ISSUE_UNEXPECTED, issues[i].kind);
            EXPECT_STREQ("6F/50", text);
            EXPECT_EQ(2u, issues[i].offset);
        }
    }
}

TEST(Integration_Tlv_EmvSchema, ReportAgreesWithFailFastValidationOnConformingInput) {
    const std::vector<uint8_t> wire{0x6F, 0x09, 0x84, 0x07, 0xA0, 0x00,
                                    0x00, 0x00, 0x03, 0x10, 0x10};
    tlv_schema_report_t        report = {nullptr, 0, 99};
    EXPECT_EQ(TLV_OK, validate(wire));
    EXPECT_EQ(TLV_OK, tlv_schema_validate_all(wire.data(), wire.size(), &tlv_reader_format_ber,
                                              tlv_ber_is_constructed, &tlv_emv_structure_schema,
                                              TLV_WALK_MAX_DEPTH, 1000,
                                              TLV_SCHEMA_UNKNOWN_BY_SCHEMA, &report, nullptr));
    EXPECT_EQ(0u, report.count);
}
