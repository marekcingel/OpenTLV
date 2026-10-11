// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/builtins/asn1/ber.h"
#include "tlv/reader/visitor.h"
#include "tlv/schema/schema.h"
#include <cstdio>
#include <gtest/gtest.h>
#include <string>
#include <vector>

// The fail-fast diagnostic and the first report entry describe one violation
// identically. Each fixture holds a single violation and states the expected
// diagnostic, so a defect shared by both implementations also fails.

namespace {
using Wire = std::vector<uint8_t>;

const tlv_schema_entry_t   itemFields[] = {{TLV_TAG(0x87), 0, SIZE_MAX, 0, "item", 0}};
const tlv_structure_rule_t itemRules[] = {
    {&itemFields[0], 0, SIZE_MAX, TLV_SCHEMA_PRIMITIVE, nullptr, 0}};
const tlv_structure_schema_t itemSchema = {itemRules, 1, 0, nullptr, 0, TLV_SCHEMA_ORDER_ANY};

// Sequence 80 81 A2 24 {83 | 84}; 24 is a constructed tag modelled as primitive.
const tlv_schema_entry_t   recordFields[] = {{TLV_TAG(0x80), 1, 1, 0, "id", 0},
                                             {TLV_TAG(0x81), 2, 8, 0, "payload", 2},
                                             {TLV_TAG(0xA2), 0, SIZE_MAX, 0, "items", 0},
                                             {TLV_TAG(0x24), 0, SIZE_MAX, 0, "blob", 0},
                                             {TLV_TAG(0x83), 0, SIZE_MAX, 0, "choice_a", 0},
                                             {TLV_TAG(0x84), 0, SIZE_MAX, 0, "choice_b", 0}};
const tlv_structure_rule_t recordRules[] = {
    {&recordFields[0], 1, 1, TLV_SCHEMA_PRIMITIVE, nullptr, 0},
    {&recordFields[1], 0, 1, TLV_SCHEMA_PRIMITIVE, nullptr, 0},
    {&recordFields[2], 0, 1, TLV_SCHEMA_CONSTRUCTED, &itemSchema, 0},
    {&recordFields[3], 0, 1, TLV_SCHEMA_PRIMITIVE, nullptr, 0},
    {&recordFields[4], 0, 1, TLV_SCHEMA_PRIMITIVE, nullptr, 1},
    {&recordFields[5], 0, 1, TLV_SCHEMA_PRIMITIVE, nullptr, 1}};
const tlv_structure_group_t  recordGroups[] = {{1, 1, 1, "choice"}};
const tlv_structure_schema_t recordSchema = {recordRules,  6, 0,
                                             recordGroups, 1, TLV_SCHEMA_ORDER_SEQUENCE};

const tlv_schema_entry_t   rootFields[] = {{TLV_TAG(0x30), 0, SIZE_MAX, 0, "record", 0}};
const tlv_structure_rule_t rootRules[] = {
    {&rootFields[0], 1, 1, TLV_SCHEMA_CONSTRUCTED, &recordSchema, 0}};
const tlv_structure_schema_t rootSchema = {rootRules, 1, 0, nullptr, 0, TLV_SCHEMA_ORDER_ANY};

std::string hex(const tlv_tag_t& tag) {
    std::string out;
    char        byte[3];
    for (size_t i = 0; i < tag.size; ++i) {
        std::snprintf(byte, sizeof byte, "%02X", tag.data[i]);
        out += byte;
    }
    return out;
}

const char* form(int constructed) {
    return constructed ? "constructed" : "primitive";
}

// Renders every field by meaning: tag and path bytes, names and bounds, never
// pointer identity. Fields whose has_* flag is clear are not rendered.
std::string describe(const tlv_schema_diagnostic_t& d) {
    const tlv_location_t& at = d.diagnostic.location;
    std::string           out =
        std::string("severity=") + tlv_diagnostic_severity_string(d.diagnostic.severity) +
        " kind=" + tlv_schema_issue_kind_string(d.detail.kind) + " tag=" + hex(d.detail.tag);
    out += " path=";
    if (!d.diagnostic.has_path) {
        out += "-";
    } else {
        for (size_t i = 0; i < d.diagnostic.path.length; ++i)
            out += (i ? ">" : "") + hex(d.diagnostic.path.tags[i]);
        out += "+" + std::to_string(d.diagnostic.path.omitted);
    }
    out += " field=" + std::string(d.detail.field ? d.detail.field : "-") +
           (d.detail.is_group ? " group" : "");
    if (d.detail.has_occurs)
        out += " occurs=" + std::to_string(d.detail.occurs) + "[" +
               std::to_string(d.detail.min_occurs) + "," + std::to_string(d.detail.max_occurs) +
               "]";
    if (d.detail.has_length)
        out += " length=" + std::to_string(d.detail.actual_length) + "[" +
               std::to_string(d.detail.min_length) + "," + std::to_string(d.detail.max_length) +
               "]%" + std::to_string(d.detail.length_multiple) +
               " flags=" + std::to_string(d.detail.length_flags);
    if (d.detail.has_form)
        out += std::string(" expected=") + form(d.detail.expected_form == TLV_SCHEMA_CONSTRUCTED) +
               " actual=" + form(d.detail.actual_constructed);
    out += " at=" + std::string(tlv_location_kind_string(at.kind)) + ":" +
           std::to_string(at.begin) + "-" + std::to_string(at.end);
    return out;
}

struct Fixture {
    const char* name;
    Wire        wire;
    const char* expected;
};

const Fixture fixtures[] = {
    {"missing top-level rule",
     {},
     "severity=error kind=missing tag=30 path=+0 field=record occurs=0[1,1] "
     "at=scope_end:0-0"},
    {"missing nested rule",
     {0x30, 0x08, 0x81, 0x02, 0x00, 0x00, 0xA2, 0x00, 0x83, 0x00},
     "severity=error kind=missing tag=80 path=30+0 field=id occurs=0[1,1] "
     "at=scope_end:10-10"},
    {"duplicate rule",
     {0x30, 0x0E, 0x80, 0x01, 0x01, 0x80, 0x01, 0x02, 0x81, 0x02, 0x00, 0x00, 0xA2, 0x00, 0x83,
      0x00},
     "severity=error kind=duplicate tag=80 path=30+0 field=id occurs=2[1,1] "
     "at=point:5-5"},
    {"missing group",
     {0x30, 0x09, 0x80, 0x01, 0x01, 0x81, 0x02, 0x00, 0x00, 0xA2, 0x00},
     "severity=error kind=missing tag=83 path=30+0 field=choice group occurs=0[1,1] "
     "at=scope_end:11-11"},
    {"duplicate group",
     {0x30, 0x0D, 0x80, 0x01, 0x01, 0x81, 0x02, 0x00, 0x00, 0xA2, 0x00, 0x83, 0x00, 0x84, 0x00},
     "severity=error kind=duplicate tag=84 path=30+0 field=choice group occurs=2[1,1] "
     "at=point:13-13"},
    {"unexpected top-level tag",
     {0x30, 0x0B, 0x80, 0x01, 0x01, 0x81, 0x02, 0x00, 0x00, 0xA2, 0x00, 0x83, 0x00, 0x05, 0x00},
     "severity=error kind=unexpected tag=05 path=+0 field=- at=point:13-13"},
    {"unexpected nested tag",
     {0x30, 0x0D, 0x80, 0x01, 0x01, 0x81, 0x02, 0x00, 0x00, 0xA2, 0x02, 0x86, 0x00, 0x83, 0x00},
     "severity=error kind=unexpected tag=86 path=30>A2+0 field=- at=point:11-11"},
    {"kind",
     {0x30, 0x0D, 0x80, 0x01, 0x01, 0x81, 0x02, 0x00, 0x00, 0xA2, 0x00, 0x24, 0x00, 0x83, 0x00},
     "severity=error kind=kind tag=24 path=30+0 field=blob expected=primitive "
     "actual=constructed at=point:11-11"},
    {"length",
     {0x30, 0x0C, 0x80, 0x01, 0x01, 0x81, 0x03, 0x00, 0x00, 0x00, 0xA2, 0x00, 0x83, 0x00},
     "severity=error kind=length tag=81 path=30+0 field=payload length=3[2,8]%2 "
     "flags=0 at=point:5-5"},
    {"order",
     {0x30, 0x0B, 0x80, 0x01, 0x01, 0xA2, 0x00, 0x81, 0x02, 0x00, 0x00, 0x83, 0x00},
     "severity=error kind=order tag=81 path=30+0 field=payload at=point:7-7"},
};
} // namespace

TEST(Integration_Tlv_SchemaParity, AcceptsConformingRecord) {
    const Wire                     wire = {0x30, 0x0D, 0x80, 0x01, 0x01, 0x81, 0x02, 0x00,
                                           0x00, 0xA2, 0x02, 0x87, 0x00, 0x83, 0x00};
    tlv_schema_diagnostic_report_t report = {nullptr, 0, 0};
    EXPECT_EQ(TLV_OK, tlv_schema_validate(wire.data(), wire.size(), &tlv_format_ber, &rootSchema,
                                          TLV_TREE_DEFAULT_DEPTH, 100, nullptr));
    EXPECT_EQ(TLV_OK, tlv_schema_validate_all_diag(wire.data(), wire.size(), &tlv_format_ber,
                                                   &rootSchema, TLV_TREE_DEFAULT_DEPTH, 100,
                                                   TLV_SCHEMA_UNKNOWN_BY_SCHEMA, &report, nullptr));
}

TEST(Integration_Tlv_SchemaParity, FailFastMatchesFirstReportEntry) {
    for (const auto& fixture : fixtures) {
        SCOPED_TRACE(fixture.name);
        tlv_schema_diagnostic_t        failFast;
        tlv_schema_diagnostic_t        entries[4];
        tlv_schema_diagnostic_report_t report = {entries, 4, 0};
        EXPECT_EQ(TLV_ERR_SCHEMA,
                  tlv_schema_validate(fixture.wire.data(), fixture.wire.size(), &tlv_format_ber,
                                      &rootSchema, TLV_TREE_DEFAULT_DEPTH, 100, &failFast));
        ASSERT_EQ(TLV_ERR_SCHEMA,
                  tlv_schema_validate_all_diag(
                      fixture.wire.data(), fixture.wire.size(), &tlv_format_ber, &rootSchema,
                      TLV_TREE_DEFAULT_DEPTH, 100, TLV_SCHEMA_UNKNOWN_BY_SCHEMA, &report, nullptr));
        ASSERT_EQ(1u, report.count);
        EXPECT_EQ(TLV_ERR_SCHEMA, failFast.diagnostic.code);
        EXPECT_EQ(TLV_ERR_SCHEMA, entries[0].diagnostic.code);
        EXPECT_EQ(fixture.expected, describe(failFast));
        EXPECT_EQ(fixture.expected, describe(entries[0]));
    }
}
