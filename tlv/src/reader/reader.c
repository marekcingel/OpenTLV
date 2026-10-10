// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/reader/reader.h"
#include <string.h>
void tlv_reader_diagnostic_init(tlv_reader_diagnostic_t* diagnostic) {
    if (diagnostic) memset(diagnostic, 0, sizeof(*diagnostic));
}

static void diag_start(tlv_reader_diagnostic_t* diagnostic, tlv_result_t code,
                       tlv_reader_operation_t operation, size_t offset) {
    tlv_reader_diagnostic_init(diagnostic);
    tlv_diagnostic_init(&diagnostic->diagnostic, code,
                        code == TLV_NEED_MORE_DATA || code == TLV_END
                            ? TLV_DIAGNOSTIC_SEVERITY_INFO
                            : TLV_DIAGNOSTIC_SEVERITY_ERROR);
    tlv_diagnostic_set_location(&diagnostic->diagnostic, TLV_LOCATION_INPUT, TLV_LOCATION_POINT,
                                offset, offset);
    diagnostic->detail.operation = operation;
}

static tlv_result_t tlv_read_impl(const uint8_t* data, size_t size, const tlv_format_t* format,
                                  tlv_element_t* out_element, size_t* consumed,
                                  tlv_source_t* source, tlv_reader_diagnostic_t* diagnostic) {
    tlv_decoded_t decoded;
    tlv_format_error_t error;
    tlv_result_t rc;
    if (!out_element || !consumed) return TLV_ERR_NULL_ARG;
    /* Decode publishes complete error detail on every failure, including preflight. */
    rc = tlv_format_decode(format, data, size, &decoded, diagnostic ? &error : NULL);
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
        if (!error.has_offset || error.offset > size)
            memset(&diagnostic->diagnostic.location, 0, sizeof diagnostic->diagnostic.location);
        diagnostic->detail.has_tag_offset = error.tag.present;
        diagnostic->detail.tag_offset = error.tag.offset;
        diagnostic->detail.has_tag = error.tag.present;
        if (error.tag.present)
            diagnostic->detail.tag = tlv_tag(data + error.tag.offset, error.tag.size);
        diagnostic->detail.has_length_offset = error.length.present;
        diagnostic->detail.length_offset = error.length.offset;
        diagnostic->detail.has_raw_length = error.length.present && error.length.size;
        if (diagnostic->detail.has_raw_length)
            diagnostic->detail.raw_length =
                (tlv_length_t){data + error.length.offset, error.length.size};
        diagnostic->detail.has_value_offset =
            error.value.present || error.region == TLV_REGION_VALUE;
        diagnostic->detail.value_offset = error.value.present ? error.value.offset : error.offset;
        diagnostic->detail.has_declared_length =
            error.has_required && error.region == TLV_REGION_VALUE;
        diagnostic->detail.declared_length = error.required;
        diagnostic->detail.has_required = error.has_required;
        diagnostic->detail.required = error.required;
        diagnostic->detail.has_available = error.has_offset && error.offset <= size;
        diagnostic->detail.available = diagnostic->detail.has_available ? size - error.offset : 0;
        diagnostic->detail.has_enclosing_end = 1;
        diagnostic->detail.enclosing_end = size;
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
    reader->base_offset = 0;
    reader->final_input = 1;
    return TLV_OK;
}

tlv_result_t tlv_reader_init_incremental(tlv_reader_t* reader, const uint8_t* data, size_t size,
                                         const tlv_format_t* format) {
    tlv_result_t rc = tlv_reader_init(reader, data, size, format);
    if (rc == TLV_OK) reader->final_input = 0;
    return rc;
}

static tlv_result_t reader_valid(const tlv_reader_t* reader) {
    if (!reader || (!reader->data && reader->size) || !tlv_format_can_read(reader->format))
        return TLV_ERR_NULL_ARG;
    if (reader->pos > reader->size || (reader->final_input != 0 && reader->final_input != 1))
        return TLV_ERR_INVALID_ARG;
    if (reader->size > SIZE_MAX - reader->base_offset) return TLV_ERR_OVERFLOW;
    return TLV_OK;
}

tlv_result_t tlv_reader_set_input(tlv_reader_t* reader, const uint8_t* data, size_t size,
                                  size_t discard, int final_input) {
    size_t base, retained;
    tlv_result_t rc = reader_valid(reader);
    if (rc != TLV_OK) return rc;
    if (!data && size) return TLV_ERR_NULL_ARG;
    if (discard > reader->pos || (final_input != 0 && final_input != 1)) return TLV_ERR_INVALID_ARG;
    retained = reader->size - discard;
    if (size < retained) return TLV_ERR_INVALID_ARG;
    if (reader->final_input && (!final_input || size != retained)) return TLV_ERR_INVALID_STATE;
    base = reader->base_offset + discard; /* Already bounded by the old window end. */
    if (size > SIZE_MAX - base) return TLV_ERR_OVERFLOW;
    reader->data = data;
    reader->size = size;
    reader->pos -= discard;
    reader->base_offset = base;
    reader->final_input = final_input;
    return TLV_OK;
}

size_t tlv_reader_consumed(const tlv_reader_t* reader) {
    return reader ? reader->pos : 0;
}

size_t tlv_reader_offset(const tlv_reader_t* reader) {
    return reader ? reader->base_offset + reader->pos : 0;
}

int tlv_reader_at_end(const tlv_reader_t* reader) {
    return reader && reader->final_input && reader->pos == reader->size;
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
    return tlv_reader_next_diag(reader, out_element, NULL);
}

static tlv_result_t reader_next(tlv_reader_t* reader, tlv_element_t* out_element,
                                tlv_source_t* source, tlv_reader_diagnostic_t* out_diagnostic) {
    size_t consumed, offset;
    tlv_result_t rc = reader_valid(reader);
    if (rc == TLV_OK && !out_element) rc = TLV_ERR_NULL_ARG;
    if (rc != TLV_OK) {
        if (out_diagnostic) {
            diag_start(out_diagnostic, rc, TLV_READER_OP_HEADER, reader ? reader->pos : 0);
            memset(&out_diagnostic->diagnostic.location, 0,
                   sizeof out_diagnostic->diagnostic.location);
        }
        return rc;
    }
    offset = tlv_reader_offset(reader);
    if (reader->pos == reader->size) {
        rc = reader->final_input ? TLV_END : TLV_NEED_MORE_DATA;
        if (out_diagnostic) {
            diag_start(out_diagnostic, rc, TLV_READER_OP_HEADER, offset);
            out_diagnostic->detail.has_available = 1;
            out_diagnostic->detail.has_enclosing_end = 1;
            out_diagnostic->detail.enclosing_end = offset;
        }
        return rc;
    }
    rc = tlv_read_impl(reader->data + reader->pos, reader->size - reader->pos, reader->format,
                       out_element, &consumed, source, out_diagnostic);
    if (rc == TLV_ERR_TRUNCATED && !reader->final_input) rc = TLV_NEED_MORE_DATA;
    if (rc == TLV_OK) {
        reader->pos += consumed;
    } else if (out_diagnostic) {
        const size_t remaining = reader->size - reader->pos;
        /* A callback may not know a bounded failure offset. Do not wrap it. */
        if (out_diagnostic->diagnostic.location.begin > remaining)
            out_diagnostic->diagnostic.location.kind = TLV_LOCATION_UNKNOWN;
        if (out_diagnostic->detail.value_offset > remaining)
            out_diagnostic->detail.has_value_offset = 0;
        tlv_location_translate(&out_diagnostic->diagnostic.location, offset);
        if (out_diagnostic->detail.has_tag_offset) out_diagnostic->detail.tag_offset += offset;
        if (out_diagnostic->detail.has_length_offset)
            out_diagnostic->detail.length_offset += offset;
        if (out_diagnostic->detail.has_value_offset) out_diagnostic->detail.value_offset += offset;
        if (out_diagnostic->detail.has_enclosing_end)
            out_diagnostic->detail.enclosing_end += offset;
        out_diagnostic->diagnostic.code = rc;
        if (rc == TLV_NEED_MORE_DATA)
            out_diagnostic->diagnostic.severity = TLV_DIAGNOSTIC_SEVERITY_INFO;
    }
    return rc;
}

tlv_result_t tlv_reader_next_diag(tlv_reader_t* reader, tlv_element_t* out_element,
                                  tlv_reader_diagnostic_t* out_diagnostic) {
    return reader_next(reader, out_element, NULL, out_diagnostic);
}

tlv_result_t tlv_reader_next_source_diag(tlv_reader_t* reader, tlv_element_t* out_element,
                                         tlv_source_t* source,
                                         tlv_reader_diagnostic_t* out_diagnostic) {
    if (!source) {
        if (out_diagnostic) diag_start(out_diagnostic, TLV_ERR_NULL_ARG, TLV_READER_OP_HEADER, 0);
        return TLV_ERR_NULL_ARG;
    }
    return reader_next(reader, out_element, source, out_diagnostic);
}

tlv_result_t tlv_read_source_diag(const uint8_t* data, size_t size, const tlv_format_t* format,
                                  tlv_element_t* element, size_t* consumed, tlv_source_t* source,
                                  tlv_reader_diagnostic_t* diagnostic) {
    if (!source) return TLV_ERR_NULL_ARG;
    return tlv_read_impl(data, size, format, element, consumed, source, diagnostic);
}
