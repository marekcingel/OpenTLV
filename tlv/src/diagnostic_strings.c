// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

/* Diagnostic vocabulary is available independently of capability implementations. */
#include "tlv/reader/diagnostic.h"
#include "tlv/writer/writer.h"
#include "tlv/query/program.h"
#include "tlv/schema/schema.h"
#include "tlv/codec/diagnostic.h"

const char* tlv_reader_operation_string(tlv_reader_operation_t value) {
    switch (value) {
        case TLV_READER_OP_TAG: return "tag";
        case TLV_READER_OP_LENGTH: return "length";
        case TLV_READER_OP_VALUE: return "value";
        case TLV_READER_OP_TRAILER: return "trailer";
        case TLV_READER_OP_HEADER: return "header";
    }
    return "unknown";
}

const char* tlv_writer_operation_string(tlv_writer_operation_t value) {
    switch (value) {
        case TLV_WRITER_OP_TAG: return "tag";
        case TLV_WRITER_OP_LENGTH: return "length";
        case TLV_WRITER_OP_VALUE: return "value";
        case TLV_WRITER_OP_HEADER: return "header";
        case TLV_WRITER_OP_TRAILER: return "trailer";
        case TLV_WRITER_OP_COPY: return "copy";
        case TLV_WRITER_OP_PRESERVE: return "preserve";
        case TLV_WRITER_OP_BEGIN: return "begin";
        case TLV_WRITER_OP_END: return "end";
    }
    return "unknown";
}

const char* tlv_query_error_kind_string(tlv_query_error_kind_t value) {
    switch (value) {
        case TLV_QUERY_ERROR_NONE: return "none";
        case TLV_QUERY_ERROR_SYNTAX: return "syntax";
        case TLV_QUERY_ERROR_CAPABILITY: return "capability";
        case TLV_QUERY_ERROR_LIMIT: return "limit";
        case TLV_QUERY_ERROR_STORAGE: return "storage";
        case TLV_QUERY_ERROR_EVENTS: return "events";
        case TLV_QUERY_ERROR_SOURCE: return "source";
        case TLV_QUERY_ERROR_READER: return "reader";
        case TLV_QUERY_ERROR_BINDING: return "binding";
        case TLV_QUERY_ERROR_CARDINALITY: return "cardinality";
        case TLV_QUERY_ERROR_CODEC: return "codec";
        case TLV_QUERY_ERROR_IMAGE_VERSION: return "image_version";
        case TLV_QUERY_ERROR_STATE: return "state";
        case TLV_QUERY_ERROR_CALLBACK: return "callback";
        case TLV_QUERY_ERROR_TYPE: return "type";
        case TLV_QUERY_ERROR_IMAGE: return "image";
        case TLV_QUERY_ERROR_SCHEMA: return "schema";
    }
    return "unknown";
}

const char* tlv_query_cause_string(tlv_query_cause_t value) {
    switch (value) {
        case TLV_QUERY_CAUSE_NONE: return "none";
        case TLV_QUERY_CAUSE_READER: return "reader";
        case TLV_QUERY_CAUSE_CODEC: return "codec";
        case TLV_QUERY_CAUSE_SCHEMA: return "schema";
    }
    return "unknown";
}

const char* tlv_schema_definition_kind_string(tlv_schema_definition_kind_t value) {
    switch (value) {
        case TLV_SCHEMA_DEFINITION_UNKNOWN: return "unknown";
        case TLV_SCHEMA_DEFINITION_TABLE: return "table";
        case TLV_SCHEMA_DEFINITION_RULE: return "rule";
        case TLV_SCHEMA_DEFINITION_GROUP: return "group";
        case TLV_SCHEMA_DEFINITION_TYPE: return "type";
        case TLV_SCHEMA_DEFINITION_COMPONENT: return "component";
    }
    return "unknown";
}

const char* tlv_codec_operation_string(tlv_codec_operation_t value) {
    switch (value) {
        case TLV_CODEC_OP_DECODE: return "decode";
        case TLV_CODEC_OP_ENCODE: return "encode";
        case TLV_CODEC_OP_MEASURE: return "measure";
    }
    return "unknown";
}

const char* tlv_codec_cause_string(tlv_codec_cause_t value) {
    switch (value) {
        case TLV_CODEC_CAUSE_NONE: return "none";
        case TLV_CODEC_CAUSE_READER: return "reader";
        case TLV_CODEC_CAUSE_SCHEMA: return "schema";
    }
    return "unknown";
}

const char* tlv_codec_violation_string(tlv_codec_violation_t value) {
    switch (value) {
        case TLV_CODEC_VIOLATION_NONE: return "none";
        case TLV_CODEC_VIOLATION_RESULT: return "result";
        case TLV_CODEC_VIOLATION_SIZE: return "size";
        case TLV_CODEC_VIOLATION_TYPE: return "type";
        case TLV_CODEC_VIOLATION_UTF8: return "utf8";
    }
    return "unknown";
}

const char* tlv_schema_issue_kind_string(tlv_schema_issue_kind_t kind) {
    switch (kind) {
        case TLV_SCHEMA_ISSUE_NONE: return "none";
        case TLV_SCHEMA_ISSUE_VALUE: return "value";
        case TLV_SCHEMA_ISSUE_DEFINITION: return "definition";
        case TLV_SCHEMA_ISSUE_MISSING: return "missing";
        case TLV_SCHEMA_ISSUE_DUPLICATE: return "duplicate";
        case TLV_SCHEMA_ISSUE_UNEXPECTED: return "unexpected";
        case TLV_SCHEMA_ISSUE_KIND: return "kind";
        case TLV_SCHEMA_ISSUE_LENGTH: return "length";
        case TLV_SCHEMA_ISSUE_ORDER: return "order";
        case TLV_SCHEMA_ISSUE_ASSERTION: return "assertion";
    }
    return "unknown";
}
