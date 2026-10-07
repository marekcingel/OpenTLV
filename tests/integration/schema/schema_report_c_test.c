// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/schema/schema.h"
#include "tlv/reader/tree.h"

/* Construct unknown enum values in C rather than loading them in a C++ lambda. */
tlv_result_t tlv_test_schema_unknown_policy(const uint8_t* data, size_t size,
                                            const tlv_format_t*           format,
                                            const tlv_structure_schema_t* schema, int unknown,
                                            tlv_schema_diagnostic_report_t* report) {
    return tlv_schema_validate_all_diag(data, size, format, schema, TLV_TREE_DEFAULT_DEPTH, 1000,
                                        (tlv_schema_unknown_policy_t)unknown, report, NULL);
}
