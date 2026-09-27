#include "tlv/reader/reader.h"
#include "tlv/size.h"
#include <string.h>

void tlv_reader_diagnostic_init(tlv_reader_diagnostic_t* diagnostic) {
    if (!diagnostic) return;
    memset(diagnostic, 0, sizeof(*diagnostic));
}

static void diag_start(tlv_reader_diagnostic_t* diagnostic, tlv_result_t code,
                       tlv_reader_operation_t operation, size_t offset) {
    tlv_reader_diagnostic_init(diagnostic);
    tlv_diagnostic_init(&diagnostic->diagnostic, code, TLV_DIAGNOSTIC_SEVERITY_ERROR);
    tlv_diagnostic_set_offset(&diagnostic->diagnostic, offset);
    diagnostic->operation = operation;
}

static void diag_raw_length(tlv_reader_diagnostic_t* diagnostic, const uint8_t* data, size_t size,
                            tlv_length_t length) {
    uintptr_t base = (uintptr_t)data, field = (uintptr_t)length.data;
    if (!diagnostic || !length.size || !length.data || field < base || field - base > size ||
        length.size > size - (size_t)(field - base))
        return;
    diagnostic->has_raw_length = 1;
    diagnostic->raw_length = length;
    diagnostic->has_length_offset = 1;
    diagnostic->length_offset = (size_t)(field - base);
}

static tlv_result_t tlv_read_impl(const uint8_t* data, size_t size, const tlv_format_t* format,
                                  tlv_element_t* out_element, size_t* consumed,
                                  tlv_reader_diagnostic_t* out_diagnostic) {
    tlv_element_t element = {0};
    size_t tag_size = 0, length_size = 0, trailer_size = 0, remaining;
    size_t value_length = 0, length_offset = 0;
    tlv_size_t logical_length = 0;
    tlv_result_t rc;
    if ((!data && size) || !out_element || !consumed || !tlv_format_can_read(format)) {
        if (out_diagnostic) diag_start(out_diagnostic, TLV_ERR_NULL_ARG, TLV_READER_OP_TAG, 0);
        return TLV_ERR_NULL_ARG;
    }
    if (!size) {
        if (out_diagnostic) {
            diag_start(out_diagnostic, TLV_ERR_END_OF_BUFFER, TLV_READER_OP_TAG, 0);
            out_diagnostic->has_tag_offset = 1;
            out_diagnostic->tag_offset = 0;
            out_diagnostic->has_available = 1;
            out_diagnostic->available = 0;
        }
        return TLV_ERR_END_OF_BUFFER;
    }
    remaining = size;
    if (format->read_element) {
        /* The header is everything before the value, whatever order its fields use. */
        rc = format->read_element(format->context, data, remaining, &element.tag, &element.length,
                                  &length_size, &logical_length, &trailer_size);
        if (rc != TLV_OK) {
            if (out_diagnostic) {
                diag_start(out_diagnostic, rc, TLV_READER_OP_TAG, 0);
                out_diagnostic->has_tag_offset = 1;
                out_diagnostic->tag_offset = 0;
                diag_raw_length(out_diagnostic, data, size, element.length);
                if (out_diagnostic->has_raw_length) {
                    out_diagnostic->operation = TLV_READER_OP_LENGTH;
                    out_diagnostic->diagnostic.offset = out_diagnostic->length_offset;
                }
            }
            return rc;
        }
        if (!length_size || length_size > remaining) {
            if (out_diagnostic) {
                diag_start(out_diagnostic, TLV_ERR_INVALID_LENGTH, TLV_READER_OP_LENGTH, 0);
                out_diagnostic->has_tag = 1;
                out_diagnostic->tag = element.tag;
                out_diagnostic->has_declared_length = 1;
                out_diagnostic->declared_length = length_size;
                out_diagnostic->has_available = 1;
                out_diagnostic->available = remaining;
            }
            return TLV_ERR_INVALID_LENGTH;
        }
        if (element.tag.size && !element.tag.data) {
            if (out_diagnostic) {
                diag_start(out_diagnostic, TLV_ERR_INVALID_TAG, TLV_READER_OP_TAG, 0);
                out_diagnostic->has_tag_offset = 1;
                out_diagnostic->tag_offset = 0;
            }
            return TLV_ERR_INVALID_TAG;
        }
        if (element.length.size) {
            uintptr_t base = (uintptr_t)data, field = (uintptr_t)element.length.data;
            if (!element.length.data || field < base || field - base > length_size ||
                element.length.size > length_size - (size_t)(field - base)) {
                if (out_diagnostic)
                    diag_start(out_diagnostic, TLV_ERR_INVALID_LENGTH, TLV_READER_OP_LENGTH, 0);
                return TLV_ERR_INVALID_LENGTH;
            }
            length_offset = (size_t)(field - base);
        }
    } else {
        rc = format->read_tag(format->context, data, remaining, &element.tag, &tag_size);
        if (rc != TLV_OK) {
            if (out_diagnostic) {
                diag_start(out_diagnostic, rc, TLV_READER_OP_TAG, 0);
                out_diagnostic->has_tag_offset = 1;
                out_diagnostic->tag_offset = 0;
            }
            return rc;
        }
        if (!tag_size || tag_size > remaining) {
            if (out_diagnostic) {
                diag_start(out_diagnostic, TLV_ERR_INVALID_TAG, TLV_READER_OP_TAG, 0);
                out_diagnostic->has_tag_offset = 1;
                out_diagnostic->tag_offset = 0;
                out_diagnostic->has_declared_length = 1;
                out_diagnostic->declared_length = tag_size;
                out_diagnostic->has_available = 1;
                out_diagnostic->available = remaining;
            }
            return TLV_ERR_INVALID_TAG;
        }
        if (element.tag.size && !element.tag.data) {
            if (out_diagnostic) {
                diag_start(out_diagnostic, TLV_ERR_INVALID_TAG, TLV_READER_OP_TAG, 0);
                out_diagnostic->has_tag_offset = 1;
                out_diagnostic->tag_offset = 0;
            }
            return TLV_ERR_INVALID_TAG;
        }
        remaining -= tag_size;
        if (format->read_value_bounds)
            rc = format->read_value_bounds(format->context, &element.tag, data + tag_size,
                                           remaining, &length_size, &logical_length, &trailer_size);
        else
            rc = format->read_length(format->context, data + tag_size, remaining, &logical_length,
                                     &length_size);
        if (rc != TLV_OK) {
            if (out_diagnostic) {
                diag_start(out_diagnostic, rc, TLV_READER_OP_LENGTH, tag_size);
                out_diagnostic->has_tag = 1;
                out_diagnostic->tag = element.tag;
                out_diagnostic->has_tag_offset = 1;
                out_diagnostic->tag_offset = 0;
                out_diagnostic->has_length_offset = 1;
                out_diagnostic->length_offset = tag_size;
                element.length.data = data + tag_size;
                element.length.size = length_size;
                diag_raw_length(out_diagnostic, data, size, element.length);
            }
            return rc;
        }
        if (length_size > remaining) {
            if (out_diagnostic) {
                diag_start(out_diagnostic, TLV_ERR_INVALID_LENGTH, TLV_READER_OP_LENGTH, tag_size);
                out_diagnostic->has_tag = 1;
                out_diagnostic->tag = element.tag;
                out_diagnostic->has_tag_offset = 1;
                out_diagnostic->tag_offset = 0;
                out_diagnostic->has_length_offset = 1;
                out_diagnostic->length_offset = tag_size;
                out_diagnostic->has_declared_length = 1;
                out_diagnostic->declared_length = length_size;
                out_diagnostic->has_available = 1;
                out_diagnostic->available = remaining;
            }
            return TLV_ERR_INVALID_LENGTH;
        }
    }
    if (!format->read_element) {
        element.length.data = length_size ? data + tag_size : NULL;
        element.length.size = length_size;
        length_offset = tag_size;
    }
    remaining -= length_size;
    if (logical_length > remaining) {
        if (out_diagnostic) {
            diag_start(out_diagnostic, TLV_ERR_BUFFER_TOO_SHORT, TLV_READER_OP_VALUE,
                       tag_size + length_size);
            out_diagnostic->has_tag = 1;
            out_diagnostic->tag = element.tag;
            out_diagnostic->has_tag_offset = 1;
            out_diagnostic->tag_offset = 0;
            out_diagnostic->has_length_offset = 1;
            out_diagnostic->length_offset = length_offset;
            out_diagnostic->has_value_offset = 1;
            out_diagnostic->value_offset = tag_size + length_size;
            out_diagnostic->has_declared_length = 1;
            out_diagnostic->declared_length = logical_length;
            out_diagnostic->has_available = 1;
            out_diagnostic->available = remaining;
            out_diagnostic->has_enclosing_end = 1;
            out_diagnostic->enclosing_end = size;
            diag_raw_length(out_diagnostic, data, size, element.length);
        }
        return TLV_ERR_BUFFER_TOO_SHORT;
    }
    /* The bounds comparison above proves this narrowing is lossless. */
    value_length = (size_t)logical_length;
    remaining -= value_length;
    if (trailer_size > remaining) {
        if (out_diagnostic) {
            diag_start(out_diagnostic, TLV_ERR_BUFFER_TOO_SHORT, TLV_READER_OP_TRAILER,
                       tag_size + length_size + value_length);
            out_diagnostic->has_tag = 1;
            out_diagnostic->tag = element.tag;
            out_diagnostic->has_tag_offset = 1;
            out_diagnostic->tag_offset = 0;
            out_diagnostic->has_length_offset = 1;
            out_diagnostic->length_offset = length_offset;
            out_diagnostic->has_value_offset = 1;
            out_diagnostic->value_offset = tag_size + length_size;
            out_diagnostic->has_declared_length = 1;
            out_diagnostic->declared_length = trailer_size;
            out_diagnostic->has_available = 1;
            out_diagnostic->available = remaining;
            out_diagnostic->has_enclosing_end = 1;
            out_diagnostic->enclosing_end = size;
            diag_raw_length(out_diagnostic, data, size, element.length);
        }
        return TLV_ERR_BUFFER_TOO_SHORT;
    }
    element.value.size = logical_length;
    element.value.data = data + tag_size + length_size;
    *consumed = tag_size + length_size + value_length + trailer_size;
    *out_element = element;
    return TLV_OK;
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
    return tlv_read_impl(data, size, format, out_element, consumed, NULL);
}

tlv_result_t tlv_read_diag(const uint8_t* data, size_t size, const tlv_format_t* format,
                           tlv_element_t* out_element, size_t* consumed,
                           tlv_reader_diagnostic_t* out_diagnostic) {
    return tlv_read_impl(data, size, format, out_element, consumed, out_diagnostic);
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
        if (out_diagnostic) diag_start(out_diagnostic, TLV_ERR_NULL_ARG, TLV_READER_OP_TAG, 0);
        return TLV_ERR_NULL_ARG;
    }
    if (tlv_reader_at_end(reader)) {
        if (out_diagnostic) {
            diag_start(out_diagnostic, TLV_ERR_END_OF_BUFFER, TLV_READER_OP_TAG, reader->pos);
            out_diagnostic->has_tag_offset = 1;
            out_diagnostic->tag_offset = reader->pos;
            out_diagnostic->has_available = 1;
            out_diagnostic->available = reader->size - reader->pos;
        }
        return TLV_ERR_END_OF_BUFFER;
    }
    if (!reader->data) {
        if (out_diagnostic)
            diag_start(out_diagnostic, TLV_ERR_NULL_ARG, TLV_READER_OP_TAG, reader->pos);
        return TLV_ERR_NULL_ARG;
    }
    rc = tlv_read_impl(reader->data + reader->pos, reader->size - reader->pos, reader->format,
                       out_element, &consumed, out_diagnostic);
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
