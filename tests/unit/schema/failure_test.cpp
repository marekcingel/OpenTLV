// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/schema/schema.h"
#include "tlv/schema/constraint.h"
#include "controlled_format.h"
#include <gtest/gtest.h>

TEST(Unit_Tlv_SchemaFailure, DefinitionIsIndependentOfInputAndOptionalChildren) {
    const tlv_schema_entry_t     field = {TLV_TAG(1), 0, 8, 0, "parent", 0};
    const tlv_structure_schema_t invalid = {nullptr, 1, 0, nullptr, 0, TLV_SCHEMA_ORDER_ANY};
    const tlv_structure_rule_t   rule = {&field, 0, 1, TLV_SCHEMA_CONSTRUCTED, &invalid, 0};
    const tlv_structure_schema_t root = {&rule, 1, 0, nullptr, 0, TLV_SCHEMA_ORDER_ANY};
    tlv_schema_diagnostic_t      diagnostic{};
    EXPECT_EQ(TLV_ERR_INVALID_SCHEMA, tlv_schema_check(&root, &diagnostic));
    EXPECT_EQ(TLV_SCHEMA_ISSUE_DEFINITION, diagnostic.kind);
    EXPECT_FALSE(diagnostic.diagnostic.has_offset);
    EXPECT_EQ(TLV_ERR_INVALID_SCHEMA,
              tlv_schema_validate(nullptr, 0, &controlled::format, &root, 8, 16, &diagnostic));
    EXPECT_EQ(TLV_ERR_INVALID_SCHEMA, diagnostic.diagnostic.code);
    const uint8_t malformed[] = {1};
    EXPECT_EQ(TLV_ERR_INVALID_SCHEMA,
              tlv_schema_validate(malformed, sizeof(malformed), &controlled::format, &root, 8, 16,
                                  nullptr));
    tlv_schema_diagnostic_report_t report = {&diagnostic, 1, 42};
    EXPECT_EQ(TLV_ERR_INVALID_SCHEMA,
              tlv_schema_validate_all_diag(nullptr, 0, &controlled::format, &root, 8, 16,
                                           TLV_SCHEMA_UNKNOWN_BY_SCHEMA, &report, nullptr));
    EXPECT_EQ(0u, report.count);
}

TEST(Unit_Tlv_SchemaFailure, MissingHasOneResultAndExplicitScopeEnd) {
    const tlv_schema_entry_t     field = {TLV_TAG(1), 0, 8, 0, "required", 0};
    const tlv_structure_rule_t   rule = {&field, 1, 1, TLV_SCHEMA_PRIMITIVE, nullptr, 0};
    const tlv_structure_schema_t schema = {&rule, 1, 0, nullptr, 0, TLV_SCHEMA_ORDER_ANY};
    tlv_schema_diagnostic_t      diagnostic{};
    EXPECT_EQ(TLV_ERR_SCHEMA,
              tlv_schema_validate(nullptr, 0, &controlled::format, &schema, 8, 16, &diagnostic));
    EXPECT_EQ(TLV_ERR_SCHEMA, diagnostic.diagnostic.code);
    EXPECT_EQ(TLV_SCHEMA_ISSUE_MISSING, diagnostic.kind);
    EXPECT_EQ(TLV_SCHEMA_ANCHOR_SCOPE_END, diagnostic.anchor);
    ASSERT_TRUE(diagnostic.diagnostic.has_offset);
    EXPECT_EQ(0u, diagnostic.diagnostic.offset);
    EXPECT_TRUE(tlv_tag_equal(field.tag, diagnostic.tag));
    EXPECT_EQ(1u, diagnostic.min_occurs);
    EXPECT_EQ(0u, diagnostic.occurs);
    tlv_schema_diagnostic_report_t report = {&diagnostic, 1, 0};
    EXPECT_EQ(TLV_ERR_SCHEMA,
              tlv_schema_validate_all_diag(nullptr, 0, &controlled::format, &schema, 8, 16,
                                           TLV_SCHEMA_UNKNOWN_BY_SCHEMA, &report, nullptr));
    EXPECT_EQ(1u, report.count);
    EXPECT_EQ(TLV_SCHEMA_ISSUE_MISSING, diagnostic.kind);
    EXPECT_EQ(TLV_SCHEMA_ANCHOR_SCOPE_END, diagnostic.anchor);
    EXPECT_TRUE(diagnostic.diagnostic.has_offset);
    EXPECT_EQ(TLV_ERR_SCHEMA,
              tlv_schema_validate(nullptr, 0, &controlled::format, &schema, 8, 16, nullptr));
}

TEST(Unit_Tlv_SchemaFailure, ConstraintDefinitionAndInputRemainDistinct) {
    const tlv_value_constraint_t reversed = {TLV_VALUE_CONSTRAINT_RANGE, 2, 1, nullptr, 0, nullptr};
    const tlv_value_constraint_t invalid = {
        TLV_VALUE_CONSTRAINT_ALLOWED_VALUES, 0, 0, nullptr, 1, nullptr};
    const tlv_value_constraint_t valid = {TLV_VALUE_CONSTRAINT_RANGE, 1, 2, nullptr, 0, nullptr};
    EXPECT_EQ(TLV_ERR_INVALID_SCHEMA, tlv_value_constraint_check(&reversed));
    EXPECT_EQ(TLV_ERR_INVALID_SCHEMA, tlv_value_constraint_validate(&invalid, 1));
    EXPECT_EQ(TLV_ERR_SCHEMA, tlv_value_constraint_validate(&valid, 3));
    EXPECT_EQ(TLV_OK, tlv_value_constraint_validate(&valid, 2));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_value_constraint_check(nullptr));
}

TEST(Unit_Tlv_SchemaFailure, RecursiveDefinitionsAndCapabilityBoundsAreDistinct) {
    const tlv_schema_entry_t field = {TLV_TAG(1), 0, SIZE_MAX, 0, "recursive", 0};
    tlv_structure_schema_t   schemas[TLV_SCHEMA_MAX_TABLES + 1]{};
    tlv_structure_rule_t     rules[TLV_SCHEMA_MAX_TABLES + 1]{};
    for (size_t i = 0; i < TLV_SCHEMA_MAX_TABLES + 1; ++i) {
        rules[i] = {&field,
                    0,
                    1,
                    TLV_SCHEMA_CONSTRUCTED,
                    i < TLV_SCHEMA_MAX_TABLES ? &schemas[i + 1] : nullptr,
                    0};
        schemas[i] = {&rules[i], 1, 0, nullptr, 0, TLV_SCHEMA_ORDER_ANY};
    }
    tlv_schema_diagnostic_t diagnostic{};
    EXPECT_EQ(TLV_ERR_UNSUPPORTED_TYPE, tlv_schema_check(schemas, &diagnostic));
    EXPECT_EQ(TLV_ERR_UNSUPPORTED_TYPE, diagnostic.diagnostic.code);
    EXPECT_EQ(TLV_SCHEMA_ISSUE_NONE, diagnostic.kind);
    EXPECT_FALSE(diagnostic.diagnostic.has_offset);
    rules[TLV_SCHEMA_MAX_TABLES - 1].children = nullptr;
    EXPECT_EQ(TLV_OK, tlv_schema_check(schemas, &diagnostic));
    rules[0].children = schemas;
    EXPECT_EQ(TLV_OK, tlv_schema_check(schemas, &diagnostic));
    EXPECT_EQ(TLV_OK, diagnostic.diagnostic.code);
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_schema_check(nullptr, &diagnostic));
    EXPECT_EQ(TLV_SCHEMA_ISSUE_NONE, diagnostic.kind);
    EXPECT_FALSE(diagnostic.diagnostic.has_offset);
}

TEST(Unit_Tlv_SchemaFailure, SharedDagIsCheckedByIdentityIncludingUnvisitedDefinitions) {
    const tlv_schema_entry_t fields[] = {{TLV_TAG(1), 0, SIZE_MAX, 0, "a", 0},
                                         {TLV_TAG(2), 0, SIZE_MAX, 0, "b", 0}};
    tlv_structure_schema_t   tables[40]{};
    tlv_structure_rule_t     rules[40][2]{};
    for (size_t i = 0; i < 40; ++i) {
        tables[i] = {rules[i], 2, 0, nullptr, 0, TLV_SCHEMA_ORDER_ANY};
        for (size_t j = 0; j < 2; ++j)
            rules[i][j] = {
                &fields[j], 0, 1, TLV_SCHEMA_CONSTRUCTED, i + 1 < 40 ? &tables[i + 1] : nullptr, 0};
    }
    EXPECT_EQ(TLV_OK, tlv_schema_check(tables, nullptr));
    EXPECT_EQ(TLV_OK, tlv_schema_validate(nullptr, 0, &controlled::format, tables, 0, 0, nullptr));
    tlv_schema_diagnostic_report_t report{};
    EXPECT_EQ(TLV_OK, tlv_schema_validate_all_diag(nullptr, 0, &controlled::format, tables, 0, 0,
                                                   TLV_SCHEMA_UNKNOWN_BY_SCHEMA, &report, nullptr));
    rules[39][1].entry = nullptr;
    EXPECT_EQ(TLV_ERR_INVALID_SCHEMA, tlv_schema_check(tables, nullptr));
}
