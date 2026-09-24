#include "tlv/schema/constraint.h"
#include <gtest/gtest.h>

namespace {
static const tlv_value_constraint_t none_constraint = {
    TLV_VALUE_CONSTRAINT_NONE, 0, 0, nullptr, 0, nullptr};
static const tlv_value_constraint_t range_constraint = {
    TLV_VALUE_CONSTRAINT_RANGE, 0, 255, nullptr, 0, nullptr};
static const int64_t                allowed[] = {978, 840, 826};
static const tlv_value_constraint_t allowed_constraint = {
    TLV_VALUE_CONSTRAINT_ALLOWED_VALUES,  0,      0, allowed,
    sizeof(allowed) / sizeof(allowed[0]), nullptr};
/* 826 (GBP) intentionally has no name, to cover a partially named list. */
static const char* const            currency_names[] = {"EUR", "USD", nullptr};
static const tlv_value_constraint_t named_allowed_constraint = {TLV_VALUE_CONSTRAINT_ALLOWED_VALUES,
                                                                0,
                                                                0,
                                                                allowed,
                                                                sizeof(allowed) /
                                                                    sizeof(allowed[0]),
                                                                currency_names};
} // namespace

TEST(Unit_Tlv_Constraint, NoneAlwaysPasses) {
    EXPECT_EQ(TLV_OK, tlv_value_constraint_validate(&none_constraint, -1));
    EXPECT_EQ(TLV_OK, tlv_value_constraint_validate(&none_constraint, 0));
    EXPECT_EQ(TLV_OK, tlv_value_constraint_validate(&none_constraint, INT64_MAX));
}

TEST(Unit_Tlv_Constraint, RangeAcceptsInclusiveBoundsAndRejectsOutside) {
    EXPECT_EQ(TLV_OK, tlv_value_constraint_validate(&range_constraint, 0));
    EXPECT_EQ(TLV_OK, tlv_value_constraint_validate(&range_constraint, 255));
    EXPECT_EQ(TLV_OK, tlv_value_constraint_validate(&range_constraint, 128));
    EXPECT_EQ(TLV_ERR_SCHEMA, tlv_value_constraint_validate(&range_constraint, -1));
    EXPECT_EQ(TLV_ERR_SCHEMA, tlv_value_constraint_validate(&range_constraint, 256));
}

TEST(Unit_Tlv_Constraint, ReversedRangeBoundsAlwaysFail) {
    const tlv_value_constraint_t reversed = {
        TLV_VALUE_CONSTRAINT_RANGE, 10, 5, nullptr, 0, nullptr};
    EXPECT_EQ(TLV_ERR_SCHEMA, tlv_value_constraint_validate(&reversed, 7));
}

TEST(Unit_Tlv_Constraint, AllowedValuesAcceptsMembersAndRejectsOthers) {
    EXPECT_EQ(TLV_OK, tlv_value_constraint_validate(&allowed_constraint, 978));
    EXPECT_EQ(TLV_OK, tlv_value_constraint_validate(&allowed_constraint, 840));
    EXPECT_EQ(TLV_OK, tlv_value_constraint_validate(&allowed_constraint, 826));
    EXPECT_EQ(TLV_ERR_SCHEMA, tlv_value_constraint_validate(&allowed_constraint, 999));
}

TEST(Unit_Tlv_Constraint, EmptyAllowedValuesRejectsEverything) {
    const tlv_value_constraint_t empty = {
        TLV_VALUE_CONSTRAINT_ALLOWED_VALUES, 0, 0, nullptr, 0, nullptr};
    EXPECT_EQ(TLV_ERR_SCHEMA, tlv_value_constraint_validate(&empty, 0));
}

TEST(Unit_Tlv_Constraint, NullAllowedValuesWithNonzeroCountFails) {
    const tlv_value_constraint_t invalid = {
        TLV_VALUE_CONSTRAINT_ALLOWED_VALUES, 0, 0, nullptr, 3, nullptr};
    EXPECT_EQ(TLV_ERR_SCHEMA, tlv_value_constraint_validate(&invalid, 0));
}

TEST(Unit_Tlv_Constraint, UnrecognizedKindFails) {
    tlv_value_constraint_t unknown = none_constraint;
    unknown.kind = static_cast<tlv_value_constraint_kind_t>(99);
    EXPECT_EQ(TLV_ERR_SCHEMA, tlv_value_constraint_validate(&unknown, 0));
}

TEST(Unit_Tlv_Constraint, NullConstraintFails) {
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_value_constraint_validate(nullptr, 0));
}

TEST(Unit_Tlv_Constraint, NameLooksUpAllowedValueName) {
    EXPECT_STREQ("EUR", tlv_value_constraint_name(&named_allowed_constraint, 978));
    EXPECT_STREQ("USD", tlv_value_constraint_name(&named_allowed_constraint, 840));
    /* 826 is allowed but has no name of its own. */
    EXPECT_EQ(nullptr, tlv_value_constraint_name(&named_allowed_constraint, 826));
    /* Not an allowed value at all. */
    EXPECT_EQ(nullptr, tlv_value_constraint_name(&named_allowed_constraint, 999));
}

TEST(Unit_Tlv_Constraint, NameIsNullWithoutNamesOrWrongKindOrNullConstraint) {
    EXPECT_EQ(nullptr, tlv_value_constraint_name(&allowed_constraint, 978));
    EXPECT_EQ(nullptr, tlv_value_constraint_name(&range_constraint, 128));
    EXPECT_EQ(nullptr, tlv_value_constraint_name(nullptr, 0));
}
