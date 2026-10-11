// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/builtins/lldp/schema.h"
#include "tlv/builtins/lldp/lldp.h"
#include "tlv/reader/reader.h"
#include <string.h>

static const uint8_t identifiers[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 127};
static const tlv_schema_entry_t fields[] = {
    {{identifiers + 0, 1}, 0, 0, 0, "End of LLDPDU", 0},
    {{identifiers + 1, 1}, 2, 256, 0, "Chassis ID", 0},
    {{identifiers + 2, 1}, 2, 256, 0, "Port ID", 0},
    {{identifiers + 3, 1}, 2, 2, 0, "Time To Live", 0},
    {{identifiers + 4, 1}, 0, 255, 0, "Port Description", 0},
    {{identifiers + 5, 1}, 0, 255, 0, "System Name", 0},
    {{identifiers + 6, 1}, 0, 255, 0, "System Description", 0},
    {{identifiers + 7, 1}, 4, 4, 0, "System Capabilities", 0},
    {{identifiers + 8, 1}, 9, 167, 0, "Management Address", 0},
    {{identifiers + 9, 1}, 4, 511, 0, "Organisationally Specific", 0}};

static const tlv_structure_rule_t rules[] = {
    {&fields[0], 0, 1, TLV_SCHEMA_PRIMITIVE, NULL, 0},
    {&fields[1], 1, 1, TLV_SCHEMA_PRIMITIVE, NULL, 0},
    {&fields[2], 1, 1, TLV_SCHEMA_PRIMITIVE, NULL, 0},
    {&fields[3], 1, 1, TLV_SCHEMA_PRIMITIVE, NULL, 0},
    {&fields[4], 0, 1, TLV_SCHEMA_PRIMITIVE, NULL, 0},
    {&fields[5], 0, 1, TLV_SCHEMA_PRIMITIVE, NULL, 0},
    {&fields[6], 0, 1, TLV_SCHEMA_PRIMITIVE, NULL, 0},
    {&fields[7], 0, 1, TLV_SCHEMA_PRIMITIVE, NULL, 0},
    {&fields[8], 0, SIZE_MAX, TLV_SCHEMA_PRIMITIVE, NULL, 0},
    {&fields[9], 0, SIZE_MAX, TLV_SCHEMA_PRIMITIVE, NULL, 0}};

const tlv_structure_schema_t tlv_lldp_schema = {
    rules, sizeof(rules) / sizeof(rules[0]), 1, NULL, 0, TLV_SCHEMA_ORDER_ANY};

static tlv_result_t failure(tlv_schema_diagnostic_t* diagnostic, tlv_result_t rc, size_t offset,
                            const char* expected) {
    if (diagnostic) {
        tlv_diagnostic_init(&diagnostic->diagnostic, rc, TLV_DIAGNOSTIC_SEVERITY_ERROR);
        if (rc != TLV_ERR_NULL_ARG && rc != TLV_ERR_INVALID_ARG) {
            tlv_diagnostic_set_location(&diagnostic->diagnostic, TLV_LOCATION_INPUT,
                                        TLV_LOCATION_POINT, offset, offset);
            diagnostic->diagnostic.location.kind = TLV_LOCATION_POINT;
        }
        if (rc == TLV_ERR_SCHEMA) diagnostic->detail.kind = TLV_SCHEMA_ISSUE_UNEXPECTED;
        diagnostic->diagnostic.expected = expected;
        diagnostic->diagnostic.actual = tlv_result_string(rc);
    }
    return rc;
}

tlv_result_t tlv_lldp_validate(const uint8_t* data, size_t size, size_t max_elements,
                               tlv_schema_diagnostic_t* diagnostic) {
    tlv_reader_t reader;
    tlv_element_t element;
    size_t offset = 0, index = 0;
    tlv_result_t rc;
    if (diagnostic) memset(diagnostic, 0, sizeof(*diagnostic));
    if (!data && size) return failure(diagnostic, TLV_ERR_NULL_ARG, 0, "non-NULL TLV region");
    rc = tlv_schema_validate(data, size, &tlv_format_lldp, &tlv_lldp_schema, 0, max_elements,
                             diagnostic);
    if (rc != TLV_OK) return rc;
    rc = tlv_reader_init(&reader, data, size, &tlv_format_lldp);
    if (rc != TLV_OK) return failure(diagnostic, rc, 0, "readable LLDP region");
    while (!tlv_reader_at_end(&reader)) {
        offset = reader.pos;
        rc = tlv_reader_next(&reader, &element);
        if (rc != TLV_OK) return failure(diagnostic, rc, offset, "complete LLDP TLV");
        if (index < 3 && element.tag.data[0] != index + 1) {
            rc = failure(diagnostic, TLV_ERR_SCHEMA, offset, "Chassis ID, Port ID, TTL prefix");
            if (diagnostic) diagnostic->detail.kind = TLV_SCHEMA_ISSUE_ORDER;
            return rc;
        }
        if (element.tag.data[0] == 0 && !tlv_reader_at_end(&reader))
            return failure(diagnostic, TLV_ERR_SCHEMA, reader.pos, "end of region after End TLV");
        ++index;
    }
    return TLV_OK;
}
