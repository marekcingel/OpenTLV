#include "tlv/diagnostic.h"
#include <string.h>

void tlv_diagnostic_init(tlv_diagnostic_t* diagnostic, tlv_result_t code,
                         tlv_diagnostic_severity_t severity) {
    if (diagnostic == NULL) return;
    memset(diagnostic, 0, sizeof(*diagnostic));
    diagnostic->code = code;
    diagnostic->severity = severity;
}

void tlv_diagnostic_set_offset(tlv_diagnostic_t* diagnostic, size_t offset) {
    if (diagnostic == NULL) return;
    diagnostic->has_offset = 1;
    diagnostic->offset = offset;
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
    diagnostic->path = path;
}

void tlv_diagnostic_path_init(tlv_diagnostic_path_t* path) {
    if (path == NULL) return;
    path->length = 0;
}

tlv_result_t tlv_diagnostic_path_push(tlv_diagnostic_path_t* path, tlv_tag_t tag) {
    if (path == NULL) return TLV_ERR_NULL_ARG;
    if (path->length == TLV_DIAGNOSTIC_PATH_MAX) return TLV_ERR_LIMIT;
    path->tags[path->length++] = tag;
    return TLV_OK;
}

void tlv_diagnostic_path_pop(tlv_diagnostic_path_t* path) {
    if (path == NULL || path->length == 0) return;
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
