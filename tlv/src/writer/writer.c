#include "tlv/writer/writer.h"
#include "tlv/size.h"
#include <string.h>
tlv_result_t tlv_writer_init(tlv_writer_t* writer, uint8_t* buf, size_t capacity,
                             const tlv_format_t* format) {
    if (!writer || (!buf && capacity) || !tlv_format_can_write(format)) return TLV_ERR_NULL_ARG;
    writer->buf = buf;
    writer->capacity = capacity;
    writer->pos = 0;
    writer->format = format;
    return TLV_OK;
}

void tlv_writer_diagnostic_init(tlv_writer_diagnostic_t* diagnostic) {
    if (diagnostic) memset(diagnostic, 0, sizeof(*diagnostic));
}

static void wdiag_start(tlv_writer_diagnostic_t* diagnostic, tlv_result_t code,
                        tlv_writer_operation_t operation, size_t offset) {
    tlv_writer_diagnostic_init(diagnostic);
    tlv_diagnostic_init(&diagnostic->diagnostic, code, TLV_DIAGNOSTIC_SEVERITY_ERROR);
    tlv_diagnostic_set_offset(&diagnostic->diagnostic, offset);
    diagnostic->operation = operation;
}

tlv_result_t tlv_encoded_size(tlv_tag_t tag, size_t length, const tlv_format_t* format,
                              size_t* size) {
    tlv_element_t element = {tag, {NULL, length}};
    tlv_encoding_t encoding;
    tlv_result_t rc;
    if (!size) return TLV_ERR_NULL_ARG;
    rc = tlv_format_measure(format, &element, &encoding, NULL);
    if (rc != TLV_OK) return rc;
    return tlv_size_to_native(encoding.total, size);
}

static tlv_result_t tlv_write_impl(uint8_t* data, size_t capacity, const tlv_format_t* format,
                                   tlv_tag_t tag, const uint8_t* value, size_t length,
                                   size_t* written, tlv_writer_diagnostic_t* diagnostic) {
    tlv_element_t element = {tag, {value, length}};
    tlv_format_error_t error = {0};
    tlv_result_t rc = tlv_format_encode(format, &element, data, capacity, written, &error);
    if (rc != TLV_OK && diagnostic) {
        tlv_writer_operation_t operation = TLV_WRITER_OP_HEADER;
        if (error.region == TLV_REGION_TAG) operation = TLV_WRITER_OP_TAG;
        if (error.region == TLV_REGION_LENGTH) operation = TLV_WRITER_OP_LENGTH;
        if (error.region == TLV_REGION_VALUE) operation = TLV_WRITER_OP_VALUE;
        if (error.region == TLV_REGION_TRAILER) operation = TLV_WRITER_OP_TRAILER;
        wdiag_start(diagnostic, rc, operation, error.offset);
        diagnostic->diagnostic.has_offset = error.has_offset;
        diagnostic->has_tag = 1;
        diagnostic->tag = tag;
        diagnostic->has_length = 1;
        diagnostic->length = length;
        if (error.has_required && error.required <= SIZE_MAX) {
            diagnostic->has_required = 1;
            diagnostic->required = (size_t)error.required;
        }
        diagnostic->has_available = 1;
        diagnostic->available = capacity;
    }
    return rc;
}

tlv_result_t tlv_write(uint8_t* data, size_t capacity, const tlv_format_t* format, tlv_tag_t tag,
                       const uint8_t* value, size_t length, size_t* out_written) {
    return tlv_write_impl(data, capacity, format, tag, value, length, out_written, NULL);
}

tlv_result_t tlv_write_diag(uint8_t* data, size_t capacity, const tlv_format_t* format,
                            tlv_tag_t tag, const uint8_t* value, size_t length, size_t* out_written,
                            tlv_writer_diagnostic_t* out_diagnostic) {
    return tlv_write_impl(data, capacity, format, tag, value, length, out_written, out_diagnostic);
}

tlv_result_t tlv_writer_write(tlv_writer_t* writer, tlv_tag_t tag, const uint8_t* value,
                              size_t length) {
    size_t written;
    tlv_result_t rc;
    if (!writer) return TLV_ERR_NULL_ARG;
    if (writer->pos > writer->capacity) return TLV_ERR_BUFFER_TOO_SHORT;
    rc = tlv_write(writer->buf ? writer->buf + writer->pos : NULL, writer->capacity - writer->pos,
                   writer->format, tag, value, length, &written);
    if (rc == TLV_OK) writer->pos += written;
    return rc;
}

tlv_result_t tlv_writer_write_diag(tlv_writer_t* writer, tlv_tag_t tag, const uint8_t* value,
                                   size_t length, tlv_writer_diagnostic_t* out_diagnostic) {
    size_t written;
    tlv_result_t rc;
    if (!writer) {
        if (out_diagnostic) wdiag_start(out_diagnostic, TLV_ERR_NULL_ARG, TLV_WRITER_OP_TAG, 0);
        return TLV_ERR_NULL_ARG;
    }
    if (writer->pos > writer->capacity) {
        if (out_diagnostic) {
            wdiag_start(out_diagnostic, TLV_ERR_BUFFER_TOO_SHORT, TLV_WRITER_OP_VALUE, writer->pos);
            out_diagnostic->has_tag = 1;
            out_diagnostic->tag = tag;
            out_diagnostic->has_length = 1;
            out_diagnostic->length = length;
            out_diagnostic->has_available = 1;
            out_diagnostic->available = 0;
        }
        return TLV_ERR_BUFFER_TOO_SHORT;
    }
    rc = tlv_write_diag(writer->buf ? writer->buf + writer->pos : NULL,
                        writer->capacity - writer->pos, writer->format, tag, value, length,
                        &written, out_diagnostic);
    if (rc == TLV_OK) {
        writer->pos += written;
    } else if (out_diagnostic && out_diagnostic->diagnostic.has_offset) {
        out_diagnostic->diagnostic.offset += writer->pos;
    }
    return rc;
}

tlv_result_t tlv_writer_copy_element(tlv_writer_t* writer, const tlv_element_t* element) {
    size_t length = 0, written = 0;
    tlv_result_t rc;
    if (!writer) return TLV_ERR_NULL_ARG;
    if (writer->pos > writer->capacity) return TLV_ERR_BUFFER_TOO_SHORT;
    if (!element || (!element->value.data && element->value.size)) return TLV_ERR_NULL_ARG;
    rc = tlv_size_to_native(element->value.size, &length);
    if (rc != TLV_OK) return rc;
    rc = tlv_write(writer->buf ? writer->buf + writer->pos : NULL, writer->capacity - writer->pos,
                   writer->format, element->tag, element->value.data, length, &written);
    if (rc == TLV_OK) writer->pos += written;
    return rc;
}

tlv_result_t tlv_writer_copy_encoded(tlv_writer_t* writer, const uint8_t* encoded_data,
                                     size_t encoded_length) {
    uint8_t* dest;
    if (!writer) return TLV_ERR_NULL_ARG;
    if (writer->pos > writer->capacity) return TLV_ERR_BUFFER_TOO_SHORT;
    if (!encoded_data && encoded_length) return TLV_ERR_NULL_ARG;
    if (writer->capacity - writer->pos < encoded_length) return TLV_ERR_BUFFER_TOO_SHORT;
    dest = writer->buf ? writer->buf + writer->pos : NULL;
    if (encoded_length) {
        if (!dest) return TLV_ERR_BUFFER_TOO_SHORT;
        memmove(dest, encoded_data, encoded_length);
    }
    writer->pos += encoded_length;
    return TLV_OK;
}

size_t tlv_writer_size(const tlv_writer_t* writer) {
    return writer ? writer->pos : 0;
}
