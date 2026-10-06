// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/schema/schema.h"
#include <string.h>

const tlv_schema_entry_t* tlv_schema_find(const tlv_schema_t* schema, const tlv_tag_t* tag) {
    size_t i;
    if (!schema || !tag || (!schema->entries && schema->count != 0)) return NULL;
    if (tag->size && !tag->data) return NULL;
    for (i = 0; i < schema->count; ++i) {
        const tlv_schema_entry_t* entry = &schema->entries[i];
        if (entry->tag.size && !entry->tag.data) continue;
        if (tlv_tag_equal(entry->tag, *tag)) return entry;
    }
    return NULL;
}

tlv_result_t tlv_schema_validate_length(const tlv_schema_entry_t* entry, size_t length) {
    if (!entry) return TLV_ERR_NULL_ARG;
    if (entry->min_length > entry->max_length || length < entry->min_length ||
        length > entry->max_length ||
        ((entry->flags & TLV_SCHEMA_LENGTH_ENDPOINTS) && length != entry->min_length &&
         length != entry->max_length) ||
        (entry->length_multiple && length % entry->length_multiple != 0))
        return TLV_ERR_INVALID_LENGTH;
    return TLV_OK;
}

void tlv_schema_diagnostic_init(tlv_schema_diagnostic_t* diagnostic) {
    if (!diagnostic) return;
    memset(diagnostic, 0, sizeof(*diagnostic));
}

const char* tlv_schema_issue_kind_string(tlv_schema_issue_kind_t kind) {
    switch (kind) {
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
