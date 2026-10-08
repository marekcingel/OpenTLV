// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/formats/fixed.h"
#include "tlv/schema/query.h"
#include <stddef.h>

/* C99 alignment probe: a leading byte exposes the next member's alignment. */
struct identifier_alignment {
    char                   prefix;
    tlv_fixed_identifier_t value;
};
struct length_alignment {
    char               prefix;
    tlv_fixed_length_t value;
};
struct format_alignment {
    char               prefix;
    tlv_fixed_format_t value;
};
struct path_alignment {
    char                  prefix;
    tlv_diagnostic_path_t value;
};
struct schema_alignment {
    char                    prefix;
    tlv_schema_diagnostic_t value;
};
struct schema_query_alignment {
    char                          prefix;
    tlv_schema_query_diagnostic_t value;
};

size_t opentlv_test_fixed_abi(size_t index) {
    const size_t values[] = {sizeof(tlv_fixed_identifier_t),
                             offsetof(struct identifier_alignment, value),
                             offsetof(tlv_fixed_identifier_t, size),
                             sizeof(tlv_fixed_length_t),
                             offsetof(struct length_alignment, value),
                             offsetof(tlv_fixed_length_t, size),
                             offsetof(tlv_fixed_length_t, byte_order),
                             sizeof(tlv_fixed_format_t),
                             offsetof(struct format_alignment, value),
                             offsetof(tlv_fixed_format_t, identifier),
                             offsetof(tlv_fixed_format_t, length),
                             offsetof(tlv_fixed_format_t, element_order),
                             offsetof(tlv_fixed_format_t, length_scope),
                             sizeof(tlv_diagnostic_path_t),
                             offsetof(struct path_alignment, value),
                             offsetof(tlv_diagnostic_path_t, tags),
                             offsetof(tlv_diagnostic_path_t, length),
                             offsetof(tlv_diagnostic_path_t, omitted),
                             sizeof(tlv_schema_diagnostic_t),
                             offsetof(struct schema_alignment, value),
                             offsetof(tlv_schema_diagnostic_t, diagnostic),
                             offsetof(tlv_schema_diagnostic_t, kind),
                             offsetof(tlv_schema_diagnostic_t, tag),
                             offsetof(tlv_schema_diagnostic_t, path),
                             offsetof(tlv_schema_diagnostic_t, field),
                             offsetof(tlv_schema_diagnostic_t, is_group),
                             offsetof(tlv_schema_diagnostic_t, has_occurs),
                             offsetof(tlv_schema_diagnostic_t, min_occurs),
                             offsetof(tlv_schema_diagnostic_t, max_occurs),
                             offsetof(tlv_schema_diagnostic_t, occurs),
                             offsetof(tlv_schema_diagnostic_t, has_length),
                             offsetof(tlv_schema_diagnostic_t, min_length),
                             offsetof(tlv_schema_diagnostic_t, max_length),
                             offsetof(tlv_schema_diagnostic_t, actual_length),
                             offsetof(tlv_schema_diagnostic_t, has_form),
                             offsetof(tlv_schema_diagnostic_t, expected_form),
                             offsetof(tlv_schema_diagnostic_t, actual_constructed),
                             offsetof(tlv_schema_diagnostic_t, length_multiple),
                             offsetof(tlv_schema_diagnostic_t, length_flags),
                             sizeof(tlv_schema_query_diagnostic_t),
                             offsetof(struct schema_query_alignment, value),
                             offsetof(tlv_schema_query_diagnostic_t, rule),
                             offsetof(tlv_schema_query_diagnostic_t, schema),
                             offsetof(tlv_schema_query_diagnostic_t, query)};
    return index < sizeof values / sizeof values[0] ? values[index] : SIZE_MAX;
}
