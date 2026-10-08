// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/builtins/lldp/lldp.h"
#include "tlv/builtins/lldp/schema.h"
#include "tlv/builtins/lldp/codec.h"
#include "tlv/reader/reader.h"

int main(void) {
    /* Local IDs "c"/"p", TTL 120 seconds, optional End. No Ethernet padding. */
    const uint8_t           wire[] = {2, 2, 7, 'c', 4, 2, 7, 'p', 6, 2, 0, 120, 0, 0};
    tlv_schema_diagnostic_t diagnostic;
    tlv_reader_t            reader;
    tlv_element_t           element;
    tlv_result_t            rc;
    if (tlv_lldp_validate(wire, sizeof(wire), 16, &diagnostic) != TLV_OK) return 1;
    if (tlv_reader_init(&reader, wire, sizeof(wire), &tlv_format_lldp) != TLV_OK) return 1;
    while ((rc = tlv_reader_next(&reader, &element)) == TLV_OK) {
        if (!tlv_definition_find(&tlv_lldp_types, &element.tag)) return 1;
        if (element.tag.data[0] == 3) {
            uint16_t seconds;
            size_t   size;
            if (tlv_size_to_native(element.value.size, &size) != TLV_OK) return 1;
            if (tlv_codec_decode(&tlv_lldp_codec_ttl, element.value.data, size, &seconds,
                                 sizeof(seconds)) != TLV_CODEC_OK)
                return 1;
            if (seconds != 120) return 1;
        }
    }
    return rc == TLV_ERR_END_OF_BUFFER ? 0 : 1;
}
