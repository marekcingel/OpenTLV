#include "tlv/builtins/bluetooth/ad_data.h"
#include "tlv/builtins/bluetooth/bluetooth_ltv.h"
#include "tlv/reader/reader.h"

tlv_result_t tlv_bluetooth_ad_data_validate(const uint8_t* data, size_t size,
                                            size_t* significant_size, size_t* error_offset) {
    tlv_reader_t reader;
    tlv_result_t rc;
    if (!significant_size || (!data && size)) {
        if (error_offset) *error_offset = 0;
        return TLV_ERR_NULL_ARG;
    }
    rc = tlv_reader_init(&reader, data, size, &tlv_format_bluetooth_ltv);
    if (rc != TLV_OK) {
        if (error_offset) *error_offset = 0;
        return rc;
    }
    while (!tlv_reader_at_end(&reader)) {
        tlv_element_t element;
        if (data[reader.pos] == 0) {
            size_t i;
            for (i = reader.pos; i < size; ++i) {
                if (data[i] != 0) {
                    if (error_offset) *error_offset = i;
                    return TLV_ERR_INVALID_VALUE;
                }
            }
            break;
        }
        if (error_offset) {
            tlv_reader_diagnostic_t diagnostic;
            rc = tlv_reader_next_diag(&reader, &element, &diagnostic);
            if (rc != TLV_OK)
                *error_offset =
                    diagnostic.diagnostic.has_offset ? diagnostic.diagnostic.offset : reader.pos;
        } else {
            rc = tlv_reader_next(&reader, &element);
        }
        if (rc != TLV_OK) return rc;
    }
    *significant_size = reader.pos;
    return TLV_OK;
}
