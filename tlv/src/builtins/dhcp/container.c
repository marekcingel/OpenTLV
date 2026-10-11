// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/builtins/dhcp/container.h"
#include "tlv/builtins/dhcp/dhcpv4.h"
#include "tlv/reader/reader.h"
#include <string.h>

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

tlv_result_t tlv_dhcpv4_options_validate(const uint8_t* data, size_t size,
                                         const tlv_dhcpv4_options_rules_t* rules,
                                         size_t max_elements, size_t* significant_size,
                                         tlv_schema_diagnostic_t* diagnostic) {
    const tlv_dhcpv4_options_rules_t defaults = {1, TLV_DHCPV4_OPTIONS_TAIL_PAD};
    tlv_reader_t reader;
    size_t count = 0;
    tlv_result_t rc;
    if (diagnostic) memset(diagnostic, 0, sizeof(*diagnostic));
    if (!significant_size || (!data && size))
        return failure(diagnostic, TLV_ERR_NULL_ARG, 0, "valid input and output storage");
    if (!rules) rules = &defaults;
    if (rules->tail != TLV_DHCPV4_OPTIONS_TAIL_PAD &&
        rules->tail != TLV_DHCPV4_OPTIONS_TAIL_EMPTY &&
        rules->tail != TLV_DHCPV4_OPTIONS_TAIL_IGNORE)
        return failure(diagnostic, TLV_ERR_INVALID_ARG, 0, "known DHCP tail policy");
    rc = tlv_reader_init(&reader, data, size, &tlv_format_dhcpv4);
    if (rc != TLV_OK) return failure(diagnostic, rc, 0, "readable DHCP options region");
    while (!tlv_reader_at_end(&reader)) {
        tlv_element_t element;
        if (count == max_elements)
            return failure(diagnostic, TLV_ERR_LIMIT, reader.pos, "element count within limit");
        if (diagnostic) {
            tlv_reader_diagnostic_t detail;
            rc = tlv_reader_next_diag(&reader, &element, &detail);
            if (rc != TLV_OK) {
                diagnostic->diagnostic = detail.diagnostic;
                diagnostic->diagnostic.location.kind =
                    detail.diagnostic.location.kind ? TLV_LOCATION_POINT : TLV_LOCATION_UNKNOWN;
            }
        } else {
            rc = tlv_reader_next(&reader, &element);
        }
        if (rc != TLV_OK) return rc;
        ++count;
        if (element.tag.data[0] == 255) {
            size_t i;
            if (rules->tail == TLV_DHCPV4_OPTIONS_TAIL_EMPTY && reader.pos != size)
                return failure(diagnostic, TLV_ERR_SCHEMA, reader.pos, "no bytes after End");
            if (rules->tail == TLV_DHCPV4_OPTIONS_TAIL_PAD) {
                for (i = reader.pos; i < size; ++i) {
                    if (data[i] != 0)
                        return failure(diagnostic, TLV_ERR_SCHEMA, i, "zero padding after End");
                }
            }
            *significant_size = reader.pos;
            return TLV_OK;
        }
    }
    if (rules->require_end) {
        static const uint8_t end_tag = 255;
        rc = failure(diagnostic, TLV_ERR_SCHEMA, size, "DHCP End option");
        if (diagnostic) {
            diagnostic->detail.kind = TLV_SCHEMA_ISSUE_MISSING;
            diagnostic->diagnostic.location.kind = TLV_LOCATION_SCOPE_END;
            diagnostic->detail.tag = tlv_tag(&end_tag, 1);
            diagnostic->detail.has_occurs = 1;
            diagnostic->detail.min_occurs = diagnostic->detail.max_occurs = 1;
        }
        return rc;
    }
    *significant_size = size;
    return TLV_OK;
}
