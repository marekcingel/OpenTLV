#include "tlv/walker.h"
#include "tlv/reader.h"

tlv_result_t tlv_walk(const uint8_t* data, size_t size,
                      const tlv_format_t* format, tlv_visitor_t visitor,
                      void* context) {
    tlv_reader_t reader;
    tlv_result_t rc;
    if (!visitor) return TLV_ERR_NULL_ARG;
    rc = tlv_reader_init(&reader, data, size, format);
    if (rc != TLV_OK) return rc;
    while (!tlv_reader_at_end(&reader)) {
        tlv_view_t view;
        rc = tlv_reader_next(&reader, &view);
        if (rc != TLV_OK) return rc;
        switch (visitor(&view, context)) {
            case TLV_VISIT_CONTINUE: break;
            case TLV_VISIT_STOP: return TLV_OK;
            default: return TLV_ERR_VISITOR;
        }
    }
    return TLV_OK;
}
