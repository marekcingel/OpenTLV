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
    diagnostic->field = group ? group->name : rule->entry->name;
    diagnostic->is_group = group != NULL;
    diagnostic->has_occurs = 1;
    diagnostic->min_occurs = group ? group->min_occurs : rule->min_occurs;
    diagnostic->max_occurs = group ? group->max_occurs : rule->max_occurs;
    diagnostic->occurs = occurs;
}

static void schema_issue_length(tlv_schema_diagnostic_t* diagnostic,
                                const tlv_structure_rule_t* rule, size_t actual_length) {
    diagnostic->field = rule->entry->name;
    diagnostic->has_length = 1;
    diagnostic->min_length = rule->entry->min_length;
    diagnostic->max_length = rule->entry->max_length;
    diagnostic->actual_length = actual_length;
    diagnostic->length_multiple = rule->entry->length_multiple;
    diagnostic->length_flags = rule->entry->flags;
}

static void schema_issue_form(tlv_schema_diagnostic_t* diagnostic, const tlv_structure_rule_t* rule,
                              int actual_constructed) {
    diagnostic->field = rule->entry->name;
    diagnostic->has_form = 1;
    diagnostic->expected_form = rule->kind;
    diagnostic->actual_constructed = actual_constructed;
}
#endif
