// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/builtins/bluetooth/ad_data.h"
#include "tlv/builtins/bluetooth/bluetooth_ltv.h"
#include "tlv/reader/reader.h"

tlv_result_t tlv_bluetooth_ad_data_validate(const uint8_t* data, size_t size,
                                            size_t* significant_size,
                                            tlv_reader_diagnostic_t* diagnostic) {
    tlv_reader_t reader;
    tlv_result_t rc;
    if (!significant_size || (!data && size)) {
        if (diagnostic) {
            tlv_reader_diagnostic_init(diagnostic);
            diagnostic->diagnostic.code = TLV_ERR_NULL_ARG;
        }
        /* diagnostic-return: the initialized base code is set above. */
        return TLV_ERR_NULL_ARG;
    }
    rc = tlv_reader_init(&reader, data, size, &tlv_format_bluetooth_ltv);
    if (rc != TLV_OK) {
        if (diagnostic) {
            tlv_reader_diagnostic_init(diagnostic);
            diagnostic->diagnostic.code = rc;
        }
        return rc;
    }
    while (!tlv_reader_at_end(&reader)) {
        tlv_element_t element;
        if (data[reader.pos] == 0) {
            size_t i;
            for (i = reader.pos; i < size; ++i) {
                if (data[i] != 0) {
                    if (diagnostic) {
                        tlv_reader_diagnostic_init(diagnostic);
                        diagnostic->diagnostic.code = TLV_ERR_INVALID_VALUE;
                        tlv_diagnostic_set_location(&diagnostic->diagnostic, TLV_LOCATION_INPUT,
                                                    TLV_LOCATION_POINT, i, i);
                    }
                    /* diagnostic-return: the initialized base code is set above. */
                    return TLV_ERR_INVALID_VALUE;
                }
            }
            break;
        }
        rc = tlv_reader_next_diag(&reader, &element, diagnostic);
        if (rc != TLV_OK) return rc;
    }
    *significant_size = reader.pos;
    return TLV_OK;
}
