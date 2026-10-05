// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#include "tlv/builtins/emv/query.h"
#include <string.h>
tlv_result_t tlv_emv_query_resolve(const void* context, const char* ns, size_t ns_size,
                                   const char* name, size_t size, tlv_tag_t* tag) {
    if (!name || !tag || (!ns && ns_size)) return TLV_ERR_NULL_ARG;
    if (ns_size && (ns_size != 3 || memcmp(ns, "emv", 3))) return TLV_ERR_INVALID_TAG;
    const tlv_emv_dictionary_t* dictionary =
        context ? context : tlv_emv_dictionary_for(TLV_EMV_CONTEXT_BASE);
    if (!dictionary || (dictionary->count && !dictionary->entries)) return TLV_ERR_INVALID_ARG;
    if (size == 3 && !memcmp(name, "PAN", 3)) name = "pan";
    size_t matches = 0;
    tlv_tag_t found = {0};
    for (size_t i = 0; i < dictionary->count; ++i) {
        const tlv_emv_definition_t* entry = &dictionary->entries[i];
        const char* symbol = tlv_emv_symbol(entry);
        if (symbol && strlen(symbol) == size && !memcmp(name, symbol, size) && entry->definition) {
            found = entry->definition->tag;
            ++matches;
        }
    }
    if (matches != 1) return matches ? TLV_ERR_INVALID_ARG : TLV_ERR_INVALID_TAG;
    *tag = found;
    return TLV_OK;
}
