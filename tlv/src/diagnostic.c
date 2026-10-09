// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/diagnostic.h"
#include "tlv/codec/diagnostic.h"
#include <stdint.h>
#include <string.h>

void tlv_codec_diagnostic_init(tlv_codec_diagnostic_t* diagnostic,
                               tlv_codec_operation_t operation) {
    if (!diagnostic) return;
    memset(diagnostic, 0, sizeof(*diagnostic));
    diagnostic->diagnostic.severity = TLV_DIAGNOSTIC_SEVERITY_INFO;
    diagnostic->codec.operation = operation;
}

void tlv_diagnostic_init(tlv_diagnostic_t* diagnostic, tlv_result_t code,
                         tlv_diagnostic_severity_t severity) {
    if (diagnostic == NULL) return;
    memset(diagnostic, 0, sizeof(*diagnostic));
    diagnostic->code = code;
    diagnostic->severity = severity;
}

void tlv_location_set(tlv_location_t* location, tlv_location_domain_t domain,
                      tlv_location_kind_t kind, size_t begin, size_t end) {
    if (!location) return;
    memset(location, 0, sizeof *location);
    if (domain < TLV_LOCATION_INPUT || domain > TLV_LOCATION_VALUE || kind < TLV_LOCATION_POINT ||
        kind > TLV_LOCATION_INSERTION || begin > end || (kind != TLV_LOCATION_SPAN && begin != end))
        return;
    location->domain = domain;
    location->kind = kind;
    location->begin = begin;
    location->end = end;
}

void tlv_location_translate(tlv_location_t* location, size_t origin) {
    if (!location || location->kind == TLV_LOCATION_UNKNOWN) return;
    if (location->domain < TLV_LOCATION_INPUT || location->domain > TLV_LOCATION_VALUE ||
        location->kind < TLV_LOCATION_POINT || location->kind > TLV_LOCATION_INSERTION ||
        location->begin > location->end || location->end > SIZE_MAX - origin ||
        (location->kind != TLV_LOCATION_SPAN && location->begin != location->end)) {
        memset(location, 0, sizeof *location);
        return;
    }
    location->begin += origin;
    location->end += origin;
}

void tlv_diagnostic_set_location(tlv_diagnostic_t* diagnostic, tlv_location_domain_t domain,
                                 tlv_location_kind_t kind, size_t begin, size_t end) {
    if (diagnostic) tlv_location_set(&diagnostic->location, domain, kind, begin, end);
}

void tlv_diagnostic_add_context(tlv_diagnostic_t* diagnostic, tlv_diagnostic_context_t* context,
                                const char* layer, const char* key, const char* value) {
    if (diagnostic == NULL || context == NULL) return;
    context->layer = layer;
    context->key = key;
    context->value = value;
    context->next = diagnostic->contexts;
    diagnostic->contexts = context;
}

void tlv_diagnostic_set_path(tlv_diagnostic_t* diagnostic, const tlv_diagnostic_path_t* path) {
    if (diagnostic == NULL) return;
    diagnostic->has_path = path != NULL;
    if (path)
        diagnostic->path = *path;
    else
        memset(&diagnostic->path, 0, sizeof diagnostic->path);
}

const char* tlv_location_domain_string(tlv_location_domain_t domain) {
    switch (domain) {
        case TLV_LOCATION_DOMAIN_UNKNOWN: return "unknown";
        case TLV_LOCATION_INPUT: return "input";
        case TLV_LOCATION_OUTPUT: return "output";
        case TLV_LOCATION_EXPRESSION: return "expression";
        case TLV_LOCATION_DEFINITION: return "definition";
        case TLV_LOCATION_VALUE: return "value";
    }
    return "unknown";
}

const char* tlv_location_kind_string(tlv_location_kind_t kind) {
    switch (kind) {
        case TLV_LOCATION_UNKNOWN: return "unknown";
        case TLV_LOCATION_POINT: return "point";
        case TLV_LOCATION_SPAN: return "span";
        case TLV_LOCATION_SCOPE_END: return "scope_end";
        case TLV_LOCATION_INSERTION: return "insertion";
    }
    return "unknown";
}

void tlv_diagnostic_path_init(tlv_diagnostic_path_t* path) {
    if (path == NULL) return;
    path->length = 0;
    path->omitted = 0;
}

tlv_result_t tlv_diagnostic_path_push(tlv_diagnostic_path_t* path, tlv_tag_t tag) {
    if (path == NULL) return TLV_ERR_NULL_ARG;
    if (path->length > TLV_DIAGNOSTIC_PATH_MAX) return TLV_ERR_INVALID_ARG;
    if (path->length == TLV_DIAGNOSTIC_PATH_MAX || path->omitted) {
        if (path->omitted != SIZE_MAX) ++path->omitted;
        return TLV_ERR_BUFFER_TOO_SHORT;
    }
    path->tags[path->length++] = tag;
    return TLV_OK;
}

void tlv_diagnostic_path_pop(tlv_diagnostic_path_t* path) {
    if (path == NULL) return;
    if (path->omitted)
        --path->omitted;
    else if (path->length)
        --path->length;
}

tlv_result_t tlv_diagnostic_path_string(const tlv_diagnostic_path_t* path, char* out,
                                        size_t capacity, size_t* length) {
    static const char hex[] = "0123456789ABCDEF";
    static const char sep[] = " > ";
    size_t needed = 0;
    if (path == NULL || (out == NULL && capacity)) return TLV_ERR_NULL_ARG;
    if (path->length > TLV_DIAGNOSTIC_PATH_MAX) return TLV_ERR_INVALID_ARG;
    for (size_t i = 0; i < path->length; ++i) {
        const tlv_tag_t* tag = &path->tags[i];
        if (!tag->size || !tag->data) return TLV_ERR_INVALID_ARG;
        for (size_t j = 0; j < tag->size; ++j) {
            if (needed + 2 < capacity) {
                out[needed] = hex[tag->data[j] >> 4];
                out[needed + 1] = hex[tag->data[j] & 0x0F];
            }
            needed += 2;
        }
        if (i + 1 < path->length) {
            for (size_t k = 0; k < 3; ++k) {
                if (needed + k + 1 < capacity) out[needed + k] = sep[k];
            }
            needed += 3;
        }
    }
    if (path->omitted) {
        const char* suffix = path->length ? " > ..." : "...";
        for (size_t i = 0; suffix[i]; ++i) {
            if (needed + 1 < capacity) out[needed] = suffix[i];
            ++needed;
        }
    }
    if (length) *length = needed;
    if (needed + 1 > capacity) {
        if (capacity) out[0] = '\0';
        return TLV_ERR_BUFFER_TOO_SHORT;
    }
    out[needed] = '\0';
    return TLV_OK;
}

const char* tlv_diagnostic_severity_string(tlv_diagnostic_severity_t severity) {
    switch (severity) {
        case TLV_DIAGNOSTIC_SEVERITY_ERROR: return "error";
        case TLV_DIAGNOSTIC_SEVERITY_WARNING: return "warning";
        case TLV_DIAGNOSTIC_SEVERITY_INFO: return "info";
    }
    return "unknown";
}
