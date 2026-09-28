#include "tlv/builtins/dhcp/container.h"
#include "tlv/builtins/dhcp/dhcpv4.h"
#include "tlv/reader/reader.h"

static tlv_result_t failure(tlv_diagnostic_t* diagnostic, tlv_result_t rc, size_t offset,
                            const char* expected) {
    if (diagnostic) {
        tlv_diagnostic_init(diagnostic, rc, TLV_DIAGNOSTIC_SEVERITY_ERROR);
        tlv_diagnostic_set_offset(diagnostic, offset);
        diagnostic->expected = expected;
        diagnostic->actual = tlv_strerror(rc);
    }
    return rc;
}

tlv_result_t tlv_dhcpv4_options_validate(const uint8_t* data, size_t size,
                                         const tlv_dhcpv4_options_rules_t* rules,
                                         size_t max_elements, size_t* significant_size,
                                         tlv_diagnostic_t* diagnostic) {
    const tlv_dhcpv4_options_rules_t defaults = {1, TLV_DHCPV4_OPTIONS_TAIL_PAD};
    tlv_reader_t reader;
    size_t count = 0;
    tlv_result_t rc;
    if (diagnostic) tlv_diagnostic_init(diagnostic, TLV_OK, TLV_DIAGNOSTIC_SEVERITY_INFO);
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
            if (rc != TLV_OK) *diagnostic = detail.diagnostic;
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
    if (rules->require_end)
        return failure(diagnostic, TLV_ERR_SCHEMA_MISSING, size, "DHCP End option");
    *significant_size = size;
    return TLV_OK;
}
