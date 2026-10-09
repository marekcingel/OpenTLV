// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/writer/writer.h"
#include "tlv/copy.h"
#include "tlv/size.h"
#include <string.h>

tlv_result_t tlv_writer_init(tlv_writer_t* writer, uint8_t* buf, size_t capacity,
                             const tlv_format_t* format) {
    if (!writer || (!buf && capacity) || !tlv_format_can_write(format)) return TLV_ERR_NULL_ARG;
    *writer = (tlv_writer_t){format, buf, capacity, 0};
    return TLV_OK;
}

void tlv_writer_diagnostic_init(tlv_writer_diagnostic_t* diagnostic) {
    if (diagnostic) memset(diagnostic, 0, sizeof(*diagnostic));
}

static void wdiag(tlv_writer_diagnostic_t* diagnostic, tlv_result_t code,
                  tlv_writer_operation_t operation, const tlv_element_t* element, size_t offset,
                  const size_t* available, const size_t* required) {
    if (!diagnostic) return;
    tlv_writer_diagnostic_init(diagnostic);
    tlv_diagnostic_init(&diagnostic->diagnostic, code, TLV_DIAGNOSTIC_SEVERITY_ERROR);
    tlv_diagnostic_set_location(&diagnostic->diagnostic, TLV_LOCATION_OUTPUT, TLV_LOCATION_POINT,
                                offset, offset);
    diagnostic->operation = operation;
    if (element) {
        diagnostic->has_tag = 1;
        diagnostic->tag = element->tag;
        if (element->value.size <= SIZE_MAX) {
            diagnostic->has_length = 1;
            diagnostic->length = (size_t)element->value.size;
        }
    }
    if (available) {
        diagnostic->has_available = 1;
        diagnostic->available = *available;
    }
    if (required) {
        diagnostic->has_required = 1;
        diagnostic->required = *required;
    }
}

static void wdiag_format(tlv_writer_diagnostic_t* diagnostic, tlv_result_t code,
                         const tlv_element_t* element, const tlv_format_error_t* error,
                         const size_t* available) {
    tlv_writer_operation_t operation = TLV_WRITER_OP_HEADER;
    size_t required;
    if (error->region == TLV_REGION_TAG) operation = TLV_WRITER_OP_TAG;
    if (error->region == TLV_REGION_LENGTH) operation = TLV_WRITER_OP_LENGTH;
    if (error->region == TLV_REGION_VALUE) operation = TLV_WRITER_OP_VALUE;
    if (error->region == TLV_REGION_TRAILER) operation = TLV_WRITER_OP_TRAILER;
    wdiag(diagnostic, code, operation, element, error->has_offset ? error->offset : 0, available,
          NULL);
    if (diagnostic && !error->has_offset)
        memset(&diagnostic->diagnostic.location, 0, sizeof diagnostic->diagnostic.location);
    if (diagnostic && error->has_required &&
        tlv_size_to_native(error->required, &required) == TLV_OK) {
        diagnostic->has_required = 1;
        diagnostic->required = required;
    }
}

tlv_result_t tlv_element_encoded_size_diag(const tlv_element_t* element, const tlv_format_t* format,
                                           size_t* size, tlv_writer_diagnostic_t* diagnostic) {
    tlv_encoding_t encoding;
    tlv_format_error_t error = {0};
    tlv_result_t rc =
        size ? tlv_format_measure(format, element, &encoding, &error) : TLV_ERR_NULL_ARG;
    if (rc == TLV_OK) rc = tlv_size_to_native(encoding.total, size);
    if (rc != TLV_OK) wdiag_format(diagnostic, rc, element, &error, NULL);
    return rc;
}

tlv_result_t tlv_element_encoded_size(const tlv_element_t* element, const tlv_format_t* format,
                                      size_t* size) {
    return tlv_element_encoded_size_diag(element, format, size, NULL);
}

tlv_result_t tlv_encoded_size(tlv_tag_t tag, size_t length, const tlv_format_t* format,
                              size_t* size) {
    const tlv_element_t element = {tag, {NULL, length}};
    return tlv_element_encoded_size(&element, format, size);
}

tlv_result_t tlv_write_element_diag(uint8_t* data, size_t capacity, const tlv_format_t* format,
                                    const tlv_element_t* element, size_t* written,
                                    tlv_writer_diagnostic_t* diagnostic) {
    tlv_format_error_t error = {0};
    tlv_result_t rc = tlv_format_encode(format, element, data, capacity, written, &error);
    if (rc != TLV_OK) wdiag_format(diagnostic, rc, element, &error, &capacity);
    return rc;
}

tlv_result_t tlv_write_element(uint8_t* data, size_t capacity, const tlv_format_t* format,
                               const tlv_element_t* element, size_t* written) {
    return tlv_write_element_diag(data, capacity, format, element, written, NULL);
}

tlv_result_t tlv_write_diag(uint8_t* data, size_t capacity, const tlv_format_t* format,
                            tlv_tag_t tag, const uint8_t* value, size_t length, size_t* written,
                            tlv_writer_diagnostic_t* diagnostic) {
    const tlv_element_t element = {tag, {value, length}};
    return tlv_write_element_diag(data, capacity, format, &element, written, diagnostic);
}

tlv_result_t tlv_write(uint8_t* data, size_t capacity, const tlv_format_t* format, tlv_tag_t tag,
                       const uint8_t* value, size_t length, size_t* written) {
    return tlv_write_diag(data, capacity, format, tag, value, length, written, NULL);
}

/* Validate before pointer arithmetic; zero capacity is always a real destination. */
static tlv_result_t writer_destination(tlv_writer_t* writer, uint8_t** data, size_t* available,
                                       const tlv_element_t* element,
                                       tlv_writer_diagnostic_t* diagnostic) {
    tlv_result_t rc = TLV_OK;
    *available = 0;
    if (!writer)
        rc = TLV_ERR_NULL_ARG;
    else if (writer->pos > writer->capacity)
        rc = TLV_ERR_BUFFER_TOO_SHORT;
    else if (!writer->buf && writer->capacity)
        rc = TLV_ERR_NULL_ARG;
    if (rc != TLV_OK) {
        wdiag(diagnostic, rc, TLV_WRITER_OP_VALUE, element, writer ? writer->pos : 0, available,
              NULL);
        if (diagnostic)
            memset(&diagnostic->diagnostic.location, 0, sizeof diagnostic->diagnostic.location);
        return rc;
    }
    *available = writer->capacity - writer->pos;
    *data = writer->buf ? writer->buf + writer->pos : NULL;
    return TLV_OK;
}

static tlv_result_t writer_finish(tlv_writer_t* writer, tlv_result_t rc, size_t written,
                                  tlv_writer_diagnostic_t* diagnostic) {
    if (rc == TLV_OK)
        writer->pos += written;
    else if (diagnostic && diagnostic->diagnostic.location.kind) {
        /* Do not wrap an unrepresentable callback offset. */
        tlv_location_translate(&diagnostic->diagnostic.location, writer->pos);
    }
    return rc;
}

tlv_result_t tlv_writer_write_element_diag(tlv_writer_t* writer, const tlv_element_t* element,
                                           tlv_writer_diagnostic_t* diagnostic) {
    uint8_t* data;
    size_t available, written = 0;
    tlv_result_t rc = writer_destination(writer, &data, &available, element, diagnostic);
    if (rc != TLV_OK) return rc;
    rc = tlv_write_element_diag(data, available, writer->format, element, &written, diagnostic);
    return writer_finish(writer, rc, written, diagnostic);
}

tlv_result_t tlv_writer_write_element(tlv_writer_t* writer, const tlv_element_t* element) {
    return tlv_writer_write_element_diag(writer, element, NULL);
}

tlv_result_t tlv_writer_write_diag(tlv_writer_t* writer, tlv_tag_t tag, const uint8_t* value,
                                   size_t length, tlv_writer_diagnostic_t* diagnostic) {
    const tlv_element_t element = {tag, {value, length}};
    return tlv_writer_write_element_diag(writer, &element, diagnostic);
}

tlv_result_t tlv_writer_write(tlv_writer_t* writer, tlv_tag_t tag, const uint8_t* value,
                              size_t length) {
    return tlv_writer_write_diag(writer, tag, value, length, NULL);
}

tlv_result_t tlv_writer_copy_element(tlv_writer_t* writer, const tlv_element_t* element) {
    size_t length;
    tlv_result_t rc;
    /* Retain the copy helper's native-size validation order. */
    if (!writer) return TLV_ERR_NULL_ARG;
    if (writer->pos > writer->capacity) return TLV_ERR_BUFFER_TOO_SHORT;
    if (!element || (!element->value.data && element->value.size)) return TLV_ERR_NULL_ARG;
    rc = tlv_size_to_native(element->value.size, &length);
    if (rc != TLV_OK) return rc;
    return tlv_writer_write_element(writer, element);
}

tlv_result_t tlv_writer_copy_encoded_diag(tlv_writer_t* writer, const uint8_t* encoded_data,
                                          size_t encoded_length,
                                          tlv_writer_diagnostic_t* diagnostic) {
    uint8_t* data;
    size_t available, written = 0;
    tlv_result_t rc = writer_destination(writer, &data, &available, NULL, diagnostic);
    if (rc != TLV_OK) return rc;
    if (!encoded_data && encoded_length)
        rc = TLV_ERR_NULL_ARG;
    else if (available < encoded_length)
        rc = TLV_ERR_BUFFER_TOO_SHORT;
    else
        rc = tlv_copy_encoded(encoded_data, encoded_length, data, available, &written);
    if (rc != TLV_OK)
        wdiag(diagnostic, rc, TLV_WRITER_OP_COPY, NULL, 0, &available, &encoded_length);
    return writer_finish(writer, rc, written, diagnostic);
}

tlv_result_t tlv_writer_copy_encoded(tlv_writer_t* writer, const uint8_t* encoded_data,
                                     size_t encoded_length) {
    return tlv_writer_copy_encoded_diag(writer, encoded_data, encoded_length, NULL);
}

tlv_result_t tlv_writer_preserve_diag(tlv_writer_t* writer, const tlv_source_t* source,
                                      const tlv_element_t* element,
                                      tlv_writer_diagnostic_t* diagnostic) {
    uint8_t* data;
    size_t available, required = 0, written = 0;
    tlv_result_t rc = writer_destination(writer, &data, &available, element, diagnostic);
    if (rc != TLV_OK) return rc;
    /* Query checks semantic equality without changing any output bytes. */
    rc = tlv_source_preserve(source, element, NULL, 0, &required);
    if (rc != TLV_OK) {
        wdiag(diagnostic, rc, TLV_WRITER_OP_PRESERVE, element, 0, &available, NULL);
    } else {
        rc = available < required
                 ? TLV_ERR_BUFFER_TOO_SHORT
                 : tlv_copy_encoded(source->data, required, data, available, &written);
        if (rc != TLV_OK)
            wdiag(diagnostic, rc, TLV_WRITER_OP_PRESERVE, element, 0, &available, &required);
    }
    return writer_finish(writer, rc, written, diagnostic);
}

tlv_result_t tlv_writer_preserve(tlv_writer_t* writer, const tlv_source_t* source,
                                 const tlv_element_t* element) {
    return tlv_writer_preserve_diag(writer, source, element, NULL);
}

size_t tlv_writer_size(const tlv_writer_t* writer) {
    return writer ? writer->pos : 0;
}

size_t tlv_writer_remaining(const tlv_writer_t* writer) {
    return writer && writer->pos <= writer->capacity ? writer->capacity - writer->pos : 0;
}
