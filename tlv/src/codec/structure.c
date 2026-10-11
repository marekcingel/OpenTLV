// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#include "tlv/codec/structure.h"
#include "tlv/reader/visitor.h"
#include "result_internal.h"

static tlv_result_t validate(const tlv_structure_codec_t* codec, const uint8_t* data, size_t size,
                             tlv_codec_diagnostic_t* diagnostic) {
    tlv_result_t rc;
    if (codec->schema) {
        tlv_schema_diagnostic_t cause;
        if (diagnostic) tlv_schema_diagnostic_init(&cause);
        rc = tlv_schema_validate(data, size, codec->format, codec->schema, codec->max_depth,
                                 codec->max_elements, diagnostic ? &cause : NULL);
        if (diagnostic && rc != TLV_OK) {
            diagnostic->diagnostic = cause.diagnostic;
            diagnostic->codec.cause = TLV_CODEC_CAUSE_SCHEMA;
            diagnostic->codec.detail.schema = cause.detail;
        }
    } else {
        tlv_tree_reader_t reader;
        tlv_tree_frame_t frames[TLV_STRUCTURE_MAX_DEPTH];
        tlv_reader_diagnostic_t cause;
        if (diagnostic) tlv_reader_diagnostic_init(&cause);
        rc = tlv_tree_reader_init(&reader, data, size, codec->format, frames,
                                  TLV_STRUCTURE_MAX_DEPTH, codec->max_depth, codec->max_elements);
        if (rc == TLV_OK)
            rc = tlv_tree_reader_visit(&reader, NULL, NULL, diagnostic ? &cause : NULL);
        if (diagnostic && rc != TLV_OK) {
            diagnostic->diagnostic = cause.diagnostic;
            diagnostic->codec.cause = TLV_CODEC_CAUSE_READER;
            diagnostic->codec.detail.reader = cause.detail;
        }
    }
    return tlv_codec_diagnostic_result(diagnostic, rc);
}

tlv_result_t tlv_structure_decode(const tlv_structure_codec_t* codec, const uint8_t* data,
                                  size_t size, void* value, size_t capacity,
                                  tlv_codec_diagnostic_t* diagnostic) {
    tlv_result_t rc;
    tlv_codec_diagnostic_init(diagnostic, TLV_CODEC_OP_DECODE);
    if (!codec || !value || (!data && size))
        return tlv_codec_diagnostic_result(diagnostic, TLV_ERR_NULL_ARG);
    if (!codec->format) return tlv_codec_diagnostic_result(diagnostic, TLV_ERR_INVALID_ARG);
    if (!codec->decode || !tlv_format_can_read(codec->format))
        return tlv_codec_diagnostic_result(diagnostic, TLV_ERR_UNSUPPORTED);
    rc = validate(codec, data, size, diagnostic);
    if (rc != TLV_OK) return rc;
    rc = codec->decode(codec->context, codec->format, data, size, value, capacity, diagnostic);
    return tlv_codec_callback_result(diagnostic, rc, TLV_CODEC_OP_DECODE);
}

tlv_result_t tlv_structure_encode(const tlv_structure_codec_t* codec, const void* value,
                                  size_t size, uint8_t* data, size_t capacity, size_t* written,
                                  tlv_codec_diagnostic_t* diagnostic) {
    size_t count = 0;
    tlv_result_t rc;
    tlv_codec_operation_t operation = data ? TLV_CODEC_OP_ENCODE : TLV_CODEC_OP_MEASURE;
    tlv_codec_diagnostic_init(diagnostic, operation);
    if (!written) return tlv_codec_diagnostic_result(diagnostic, TLV_ERR_NULL_ARG);
    *written = 0;
    if (!codec || !value || (!data && capacity))
        return tlv_codec_diagnostic_result(diagnostic, TLV_ERR_NULL_ARG);
    if (!codec->format) return tlv_codec_diagnostic_result(diagnostic, TLV_ERR_INVALID_ARG);
    if (!codec->encode || !tlv_format_can_read(codec->format) ||
        !tlv_format_can_write(codec->format))
        return tlv_codec_diagnostic_result(diagnostic, TLV_ERR_UNSUPPORTED);
    rc = codec->encode(codec->context, codec->format, value, size, data, capacity, &count,
                       diagnostic);
    rc = tlv_codec_callback_result(diagnostic, rc, operation);
    if (rc != TLV_OK) return rc;
    if (data && count > capacity) {
        if (diagnostic) diagnostic->codec.violation = TLV_CODEC_VIOLATION_SIZE;
        return tlv_codec_diagnostic_result(diagnostic, TLV_ERR_CALLBACK);
    }
    if (data) {
        rc = validate(codec, data, count, diagnostic);
        if (diagnostic && diagnostic->diagnostic.location.domain == TLV_LOCATION_INPUT)
            diagnostic->diagnostic.location.domain = TLV_LOCATION_OUTPUT;
        if (rc != TLV_OK) return rc;
    }
    *written = count;
    return tlv_codec_diagnostic_result(diagnostic, TLV_OK);
}
