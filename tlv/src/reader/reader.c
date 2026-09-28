#include "tlv/reader/reader.h"
#include <string.h>
void tlv_reader_diagnostic_init(tlv_reader_diagnostic_t* diagnostic) {
    if (diagnostic) memset(diagnostic, 0, sizeof(*diagnostic));
}

static void diag_start(tlv_reader_diagnostic_t* diagnostic, tlv_result_t code,
                       tlv_reader_operation_t operation, size_t offset) {
    tlv_reader_diagnostic_init(diagnostic);
    tlv_diagnostic_init(&diagnostic->diagnostic, code, TLV_DIAGNOSTIC_SEVERITY_ERROR);
    tlv_diagnostic_set_offset(&diagnostic->diagnostic, offset);
    diagnostic->operation = operation;
}

static tlv_result_t tlv_read_impl(const uint8_t* data, size_t size, const tlv_format_t* format,
                                  tlv_element_t* out_element, size_t* consumed,
                                  tlv_source_t* source, tlv_reader_diagnostic_t* diagnostic) {
    tlv_decoded_t decoded;
    tlv_format_error_t error = {0};
    tlv_result_t rc;
    if (!out_element || !consumed) return TLV_ERR_NULL_ARG;
    rc = tlv_format_decode(format, data, size, &decoded, &error);
    if (rc == TLV_OK) {
        if (source) *source = decoded.source;
        *out_element = decoded.element;
        *consumed = decoded.source.size;
        return TLV_OK;
    }
    if (diagnostic) {
        tlv_reader_operation_t operation = TLV_READER_OP_HEADER;
        if (error.region == TLV_REGION_TAG) operation = TLV_READER_OP_TAG;
        if (error.region == TLV_REGION_LENGTH) operation = TLV_READER_OP_LENGTH;
        if (error.region == TLV_REGION_VALUE) operation = TLV_READER_OP_VALUE;
        if (error.region == TLV_REGION_TRAILER) operation = TLV_READER_OP_TRAILER;
        diag_start(diagnostic, rc, operation, error.offset);
        diagnostic->diagnostic.has_offset = error.has_offset;
        diagnostic->has_tag_offset = error.tag.present;
        diagnostic->tag_offset = error.tag.offset;
        diagnostic->has_tag = error.tag.present;
        if (error.tag.present) diagnostic->tag = tlv_tag(data + error.tag.offset, error.tag.size);
        diagnostic->has_length_offset = error.length.present;
        diagnostic->length_offset = error.length.offset;
        diagnostic->has_raw_length = error.length.present && error.length.size;
        if (diagnostic->has_raw_length)
            diagnostic->raw_length = (tlv_length_t){data + error.length.offset, error.length.size};
        diagnostic->has_value_offset = error.value.present || error.region == TLV_REGION_VALUE;
        diagnostic->value_offset = error.value.present ? error.value.offset : error.offset;
        diagnostic->has_declared_length = error.has_required && error.region == TLV_REGION_VALUE;
        diagnostic->declared_length = error.required;
        diagnostic->has_available = error.has_offset && error.offset <= size;
        diagnostic->available = diagnostic->has_available ? size - error.offset : 0;
        diagnostic->has_enclosing_end = 1;
        diagnostic->enclosing_end = size;
    }
    return rc;
}

tlv_result_t tlv_reader_init(tlv_reader_t* reader, const uint8_t* data, size_t size,
                             const tlv_format_t* format) {
    if (!reader || (!data && size) || !tlv_format_can_read(format)) return TLV_ERR_NULL_ARG;
    reader->data = data;
    reader->size = size;
    reader->pos = 0;
    reader->format = format;
    return TLV_OK;
}

int tlv_reader_at_end(const tlv_reader_t* reader) {
    return !reader || reader->pos >= reader->size;
}

tlv_result_t tlv_read(const uint8_t* data, size_t size, const tlv_format_t* format,
                      tlv_element_t* out_element, size_t* consumed) {
    return tlv_read_impl(data, size, format, out_element, consumed, NULL, NULL);
}

tlv_result_t tlv_read_diag(const uint8_t* data, size_t size, const tlv_format_t* format,
                           tlv_element_t* out_element, size_t* consumed,
                           tlv_reader_diagnostic_t* out_diagnostic) {
    return tlv_read_impl(data, size, format, out_element, consumed, NULL, out_diagnostic);
}

tlv_result_t tlv_reader_next(tlv_reader_t* reader, tlv_element_t* out_element) {
    size_t consumed;
    tlv_result_t rc;
    if (!reader || !out_element) return TLV_ERR_NULL_ARG;
    if (tlv_reader_at_end(reader)) return TLV_ERR_END_OF_BUFFER;
    if (!reader->data) return TLV_ERR_NULL_ARG;
    rc = tlv_read(reader->data + reader->pos, reader->size - reader->pos, reader->format,
                  out_element, &consumed);
    if (rc == TLV_OK) reader->pos += consumed;
    return rc;
}

tlv_result_t tlv_reader_next_diag(tlv_reader_t* reader, tlv_element_t* out_element,
                                  tlv_reader_diagnostic_t* out_diagnostic) {
    size_t consumed;
    tlv_result_t rc;
    if (!reader || !out_element) {
        if (out_diagnostic) diag_start(out_diagnostic, TLV_ERR_NULL_ARG, TLV_READER_OP_HEADER, 0);
        return TLV_ERR_NULL_ARG;
    }
    if (tlv_reader_at_end(reader)) {
        if (out_diagnostic) {
            diag_start(out_diagnostic, TLV_ERR_END_OF_BUFFER, TLV_READER_OP_HEADER, reader->pos);
            out_diagnostic->has_available = 1;
            out_diagnostic->available = 0;
        }
        return TLV_ERR_END_OF_BUFFER;
    }
    if (!reader->data) {
        if (out_diagnostic)
            diag_start(out_diagnostic, TLV_ERR_NULL_ARG, TLV_READER_OP_HEADER, reader->pos);
        return TLV_ERR_NULL_ARG;
    }
    rc = tlv_read_impl(reader->data + reader->pos, reader->size - reader->pos, reader->format,
                       out_element, &consumed, NULL, out_diagnostic);
    if (rc == TLV_OK) {
        reader->pos += consumed;
    } else if (out_diagnostic) {
        if (out_diagnostic->diagnostic.has_offset) out_diagnostic->diagnostic.offset += reader->pos;
        if (out_diagnostic->has_tag_offset) out_diagnostic->tag_offset += reader->pos;
        if (out_diagnostic->has_length_offset) out_diagnostic->length_offset += reader->pos;
        if (out_diagnostic->has_value_offset) out_diagnostic->value_offset += reader->pos;
        if (out_diagnostic->has_enclosing_end) out_diagnostic->enclosing_end += reader->pos;
    }
    return rc;
}

tlv_result_t tlv_read_source_diag(const uint8_t* data, size_t size, const tlv_format_t* format,
                                  tlv_element_t* element, size_t* consumed, tlv_source_t* source,
                                  tlv_reader_diagnostic_t* diagnostic) {
    if (!source) return TLV_ERR_NULL_ARG;
    return tlv_read_impl(data, size, format, element, consumed, source, diagnostic);
}
