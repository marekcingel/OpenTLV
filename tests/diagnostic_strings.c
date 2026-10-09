// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/reader/diagnostic.h"
#include "tlv/writer/writer.h"
#include "tlv/query/program.h"
#include "tlv/schema/schema.h"
#include "tlv/codec/diagnostic.h"
#include <stdio.h>
#include <string.h>

#define CHECK_NAME(call, expected)                                                                 \
    do {                                                                                           \
        if (strcmp((call), (expected)) != 0) {                                                     \
            fprintf(stderr, "line %d: %s\n", __LINE__, #call);                                     \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

int main(void) {
    CHECK_NAME(tlv_reader_operation_string(TLV_READER_OP_TAG), "tag");
    CHECK_NAME(tlv_reader_operation_string(TLV_READER_OP_LENGTH), "length");
    CHECK_NAME(tlv_reader_operation_string(TLV_READER_OP_VALUE), "value");
    CHECK_NAME(tlv_reader_operation_string(TLV_READER_OP_TRAILER), "trailer");
    CHECK_NAME(tlv_reader_operation_string(TLV_READER_OP_HEADER), "header");
    CHECK_NAME(tlv_reader_operation_string((tlv_reader_operation_t)127), "unknown");
    CHECK_NAME(tlv_writer_operation_string(TLV_WRITER_OP_TAG), "tag");
    CHECK_NAME(tlv_writer_operation_string(TLV_WRITER_OP_LENGTH), "length");
    CHECK_NAME(tlv_writer_operation_string(TLV_WRITER_OP_VALUE), "value");
    CHECK_NAME(tlv_writer_operation_string(TLV_WRITER_OP_HEADER), "header");
    CHECK_NAME(tlv_writer_operation_string(TLV_WRITER_OP_TRAILER), "trailer");
    CHECK_NAME(tlv_writer_operation_string(TLV_WRITER_OP_COPY), "copy");
    CHECK_NAME(tlv_writer_operation_string(TLV_WRITER_OP_PRESERVE), "preserve");
    CHECK_NAME(tlv_writer_operation_string(TLV_WRITER_OP_BEGIN), "begin");
    CHECK_NAME(tlv_writer_operation_string(TLV_WRITER_OP_END), "end");
    CHECK_NAME(tlv_writer_operation_string((tlv_writer_operation_t)127), "unknown");
    CHECK_NAME(tlv_query_error_kind_string(TLV_QUERY_ERROR_NONE), "none");
    CHECK_NAME(tlv_query_error_kind_string(TLV_QUERY_ERROR_SYNTAX), "syntax");
    CHECK_NAME(tlv_query_error_kind_string(TLV_QUERY_ERROR_CAPABILITY), "capability");
    CHECK_NAME(tlv_query_error_kind_string(TLV_QUERY_ERROR_LIMIT), "limit");
    CHECK_NAME(tlv_query_error_kind_string(TLV_QUERY_ERROR_STORAGE), "storage");
    CHECK_NAME(tlv_query_error_kind_string(TLV_QUERY_ERROR_EVENTS), "events");
    CHECK_NAME(tlv_query_error_kind_string(TLV_QUERY_ERROR_SOURCE), "source");
    CHECK_NAME(tlv_query_error_kind_string(TLV_QUERY_ERROR_READER), "reader");
    CHECK_NAME(tlv_query_error_kind_string(TLV_QUERY_ERROR_BINDING), "binding");
    CHECK_NAME(tlv_query_error_kind_string(TLV_QUERY_ERROR_CARDINALITY), "cardinality");
    CHECK_NAME(tlv_query_error_kind_string(TLV_QUERY_ERROR_CODEC), "codec");
    CHECK_NAME(tlv_query_error_kind_string(TLV_QUERY_ERROR_IMAGE_VERSION), "image_version");
    CHECK_NAME(tlv_query_error_kind_string(TLV_QUERY_ERROR_STATE), "state");
    CHECK_NAME(tlv_query_error_kind_string(TLV_QUERY_ERROR_CALLBACK), "callback");
    CHECK_NAME(tlv_query_error_kind_string(TLV_QUERY_ERROR_TYPE), "type");
    CHECK_NAME(tlv_query_error_kind_string(TLV_QUERY_ERROR_IMAGE), "image");
    CHECK_NAME(tlv_query_error_kind_string((tlv_query_error_kind_t)127), "unknown");
    CHECK_NAME(tlv_schema_definition_kind_string(TLV_SCHEMA_DEFINITION_UNKNOWN), "unknown");
    CHECK_NAME(tlv_schema_definition_kind_string(TLV_SCHEMA_DEFINITION_TABLE), "table");
    CHECK_NAME(tlv_schema_definition_kind_string(TLV_SCHEMA_DEFINITION_RULE), "rule");
    CHECK_NAME(tlv_schema_definition_kind_string(TLV_SCHEMA_DEFINITION_GROUP), "group");
    CHECK_NAME(tlv_schema_definition_kind_string(TLV_SCHEMA_DEFINITION_TYPE), "type");
    CHECK_NAME(tlv_schema_definition_kind_string(TLV_SCHEMA_DEFINITION_COMPONENT), "component");
    CHECK_NAME(tlv_schema_definition_kind_string((tlv_schema_definition_kind_t)127), "unknown");
    CHECK_NAME(tlv_codec_operation_string(TLV_CODEC_OP_DECODE), "decode");
    CHECK_NAME(tlv_codec_operation_string(TLV_CODEC_OP_ENCODE), "encode");
    CHECK_NAME(tlv_codec_operation_string(TLV_CODEC_OP_MEASURE), "measure");
    CHECK_NAME(tlv_codec_operation_string((tlv_codec_operation_t)127), "unknown");
    CHECK_NAME(tlv_codec_cause_string(TLV_CODEC_CAUSE_NONE), "none");
    CHECK_NAME(tlv_codec_cause_string(TLV_CODEC_CAUSE_READER), "reader");
    CHECK_NAME(tlv_codec_cause_string(TLV_CODEC_CAUSE_SCHEMA), "schema");
    CHECK_NAME(tlv_codec_cause_string((tlv_codec_cause_t)127), "unknown");
    CHECK_NAME(tlv_codec_violation_string(TLV_CODEC_VIOLATION_NONE), "none");
    CHECK_NAME(tlv_codec_violation_string(TLV_CODEC_VIOLATION_RESULT), "result");
    CHECK_NAME(tlv_codec_violation_string(TLV_CODEC_VIOLATION_SIZE), "size");
    CHECK_NAME(tlv_codec_violation_string(TLV_CODEC_VIOLATION_TYPE), "type");
    CHECK_NAME(tlv_codec_violation_string(TLV_CODEC_VIOLATION_UTF8), "utf8");
    CHECK_NAME(tlv_codec_violation_string((tlv_codec_violation_t)127), "unknown");
    CHECK_NAME(tlv_schema_issue_kind_string(TLV_SCHEMA_ISSUE_NONE), "none");
    CHECK_NAME(tlv_schema_issue_kind_string(TLV_SCHEMA_ISSUE_MISSING), "missing");
    CHECK_NAME(tlv_schema_issue_kind_string(TLV_SCHEMA_ISSUE_DUPLICATE), "duplicate");
    CHECK_NAME(tlv_schema_issue_kind_string(TLV_SCHEMA_ISSUE_UNEXPECTED), "unexpected");
    CHECK_NAME(tlv_schema_issue_kind_string(TLV_SCHEMA_ISSUE_KIND), "kind");
    CHECK_NAME(tlv_schema_issue_kind_string(TLV_SCHEMA_ISSUE_LENGTH), "length");
    CHECK_NAME(tlv_schema_issue_kind_string(TLV_SCHEMA_ISSUE_ORDER), "order");
    CHECK_NAME(tlv_schema_issue_kind_string(TLV_SCHEMA_ISSUE_ASSERTION), "assertion");
    CHECK_NAME(tlv_schema_issue_kind_string(TLV_SCHEMA_ISSUE_VALUE), "value");
    CHECK_NAME(tlv_schema_issue_kind_string(TLV_SCHEMA_ISSUE_DEFINITION), "definition");
    CHECK_NAME(tlv_schema_issue_kind_string((tlv_schema_issue_kind_t)127), "unknown");
    CHECK_NAME(tlv_diagnostic_severity_string(TLV_DIAGNOSTIC_SEVERITY_ERROR), "error");
    return 0;
}
