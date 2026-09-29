#include "tlv/builtins/lldp/schema.h"
#include "tlv/builtins/lldp/lldp.h"
#include "tlv/reader/reader.h"

static const uint8_t identifiers[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 127};
#define RULE(index, min, max, required, occurs, name)                                              \
    {{{identifiers + index, 1}, min, max, 0, name, 0},                                             \
     required,                                                                                     \
     occurs,                                                                                       \
     TLV_SCHEMA_PRIMITIVE,                                                                         \
     NULL,                                                                                         \
     0,                                                                                            \
     NULL}
static const tlv_structure_rule_t rules[] = {
    RULE(0, 0, 0, 0, 1, "End of LLDPDU"),
    RULE(1, 2, 256, 1, 1, "Chassis ID"),
    RULE(2, 2, 256, 1, 1, "Port ID"),
    RULE(3, 2, 2, 1, 1, "Time To Live"),
    RULE(4, 0, 255, 0, 1, "Port Description"),
    RULE(5, 0, 255, 0, 1, "System Name"),
    RULE(6, 0, 255, 0, 1, "System Description"),
    RULE(7, 4, 4, 0, 1, "System Capabilities"),
    RULE(8, 9, 167, 0, SIZE_MAX, "Management Address"),
    RULE(9, 4, 511, 0, SIZE_MAX, "Organisationally Specific"),
};
#undef RULE

const tlv_structure_schema_t tlv_lldp_schema = {
    rules, sizeof(rules) / sizeof(rules[0]), 1, NULL, 0, TLV_SCHEMA_ORDER_ANY};

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

tlv_result_t tlv_lldp_validate(const uint8_t* data, size_t size, size_t max_elements,
                               tlv_diagnostic_t* diagnostic) {
    tlv_reader_t reader;
    tlv_element_t element;
    size_t offset = 0, index = 0;
    tlv_result_t rc;
    if (diagnostic) tlv_diagnostic_init(diagnostic, TLV_OK, TLV_DIAGNOSTIC_SEVERITY_INFO);
    if (!data && size) return failure(diagnostic, TLV_ERR_NULL_ARG, 0, "non-NULL TLV region");
    rc = tlv_schema_validate(data, size, &tlv_format_lldp, &tlv_lldp_schema, 0, max_elements,
                             &offset);
    if (rc != TLV_OK) return failure(diagnostic, rc, offset, "LLDP base lengths and occurrences");
    rc = tlv_reader_init(&reader, data, size, &tlv_format_lldp);
    if (rc != TLV_OK) return failure(diagnostic, rc, 0, "readable LLDP region");
    while (!tlv_reader_at_end(&reader)) {
        offset = reader.pos;
        rc = tlv_reader_next(&reader, &element);
        if (rc != TLV_OK) return failure(diagnostic, rc, offset, "complete LLDP TLV");
        if (index < 3 && element.tag.data[0] != index + 1)
            return failure(diagnostic, TLV_ERR_SCHEMA, offset, "Chassis ID, Port ID, TTL prefix");
        if (element.tag.data[0] == 0 && !tlv_reader_at_end(&reader))
            return failure(diagnostic, TLV_ERR_SCHEMA, reader.pos, "end of region after End TLV");
        ++index;
    }
    return TLV_OK;
}
