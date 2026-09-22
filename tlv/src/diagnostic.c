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

const char* tlv_diagnostic_severity_string(tlv_diagnostic_severity_t severity) {
    switch (severity) {
        case TLV_DIAGNOSTIC_SEVERITY_ERROR: return "error";
        case TLV_DIAGNOSTIC_SEVERITY_WARNING: return "warning";
        case TLV_DIAGNOSTIC_SEVERITY_INFO: return "info";
    }
    return "unknown";
}
