// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_SCHEMA_DIAGNOSTIC_INTERNAL_H
#define OPENTLV_SCHEMA_DIAGNOSTIC_INTERNAL_H
#include "tlv/schema/schema.h"

/* Violation detail shared by tlv_schema_validate() and the report API, so both
 * describe one violation identically. Each helper fills only its kind's fields. */

static void schema_issue_occurs(tlv_schema_diagnostic_t* diagnostic,
                                const tlv_structure_rule_t* rule,
                                const tlv_structure_group_t* group, size_t occurs) {
    diagnostic->detail.field = group ? group->name : rule->entry->name;
    diagnostic->detail.is_group = group != NULL;
    diagnostic->detail.has_occurs = 1;
    diagnostic->detail.min_occurs = group ? group->min_occurs : rule->min_occurs;
    diagnostic->detail.max_occurs = group ? group->max_occurs : rule->max_occurs;
    diagnostic->detail.occurs = occurs;
}

static void schema_issue_length(tlv_schema_diagnostic_t* diagnostic,
                                const tlv_structure_rule_t* rule, size_t actual_length) {
    diagnostic->detail.field = rule->entry->name;
    diagnostic->detail.has_length = 1;
    diagnostic->detail.min_length = rule->entry->min_length;
    diagnostic->detail.max_length = rule->entry->max_length;
    diagnostic->detail.actual_length = actual_length;
    diagnostic->detail.length_multiple = rule->entry->length_multiple;
    diagnostic->detail.length_flags = rule->entry->flags;
}

static void schema_issue_form(tlv_schema_diagnostic_t* diagnostic, const tlv_structure_rule_t* rule,
                              int actual_constructed) {
    diagnostic->detail.field = rule->entry->name;
    diagnostic->detail.has_form = 1;
    diagnostic->detail.expected_form = rule->kind;
    diagnostic->detail.actual_constructed = actual_constructed;
}
#endif
