#include "tlv/builtins/emv/emv.h"
#include <ctype.h>
#include <string.h>

#define EMV_COUNT(array) (sizeof(array) / sizeof((array)[0]))

tlv_emv_context_t tlv_emv_child_context(tlv_emv_context_t context, const tlv_tag_t* tag) {
    unsigned value;
    if (!tag || !tag->data) return TLV_EMV_CONTEXT_COUNT;
    if (tag->size < 1) return TLV_EMV_CONTEXT_COUNT;
    value = tag->data[0];
    if (tag->size == 2)
        value = (value << 8) | tag->data[1];
    else if (tag->size != 1)
        return TLV_EMV_CONTEXT_COUNT;
    if (context == TLV_EMV_CONTEXT_BASE || context == TLV_EMV_CONTEXT_BIT_GROUP) {
        if (value == tlv_emv_tag_biometric_information_template_u64) return TLV_EMV_CONTEXT_BIT;
    }
    if (context == TLV_EMV_CONTEXT_BASE) {
        switch (value) {
            case tlv_emv_tag_offline_bit_group_template_u64:
            case tlv_emv_tag_online_bit_group_template_u64: return TLV_EMV_CONTEXT_BIT_GROUP;
            case tlv_emv_tag_biometric_try_counters_template_u64:
                return TLV_EMV_CONTEXT_BIOMETRIC_COUNTERS;
            case tlv_emv_tag_preferred_attempts_template_u64:
                return TLV_EMV_CONTEXT_BIOMETRIC_ATTEMPTS;
            case tlv_emv_tag_biometric_verification_data_template_u64:
                return TLV_EMV_CONTEXT_BIOMETRIC_VERIFICATION;
            default: break;
        }
        /* Only known templates inherit BASE, avoiding guesses in proprietary containers. */
        if (tlv_emv_find(TLV_EMV_CONTEXT_BASE, tag)) return TLV_EMV_CONTEXT_BASE;
    }
    if (context == TLV_EMV_CONTEXT_BIT && value == tlv_emv_tag_biometric_header_template_u64)
        return TLV_EMV_CONTEXT_BHT;
    if (context == TLV_EMV_CONTEXT_BHT &&
        (value == tlv_emv_tag_bht1_u64 || value == tlv_emv_tag_bht2_u64))
        return TLV_EMV_CONTEXT_BHT_FORMAT;
    return TLV_EMV_CONTEXT_COUNT;
}

tlv_result_t tlv_emv_validate_length(const tlv_emv_definition_t* definition, size_t length) {
    if (!definition) return TLV_ERR_NULL_ARG;
    return tlv_schema_validate_length(definition->schema, length);
}

size_t tlv_emv_length_step(const tlv_emv_definition_t* definition) {
    const tlv_schema_entry_t* schema;
    if (!definition || !definition->schema) return 0;
    schema = definition->schema;
    if (schema->min_length > schema->max_length) return 0;
    if ((schema->flags & TLV_SCHEMA_LENGTH_ENDPOINTS) && schema->min_length != schema->max_length)
        return schema->max_length - schema->min_length;
    return schema->length_multiple ? schema->length_multiple : 1;
}

/* Curated only where a generic title-cased label would be misleading:
 * abbreviations and initialisms that deserve their expansion and acronym. */
static const char* const emv_curated_symbols[] = {
    "pan", "aip",     "afl",      "tvr",          "tsi",
    "atc", "df_name", "adf_name", "fci_template", "fci_proprietary_template",
    "iin", "sfi"};

const char* tlv_emv_display_label(const char* name) {
    size_t i, j;
    const tlv_emv_dictionary_t* dictionary;
    if (!name) return NULL;
    for (i = 0; i < EMV_COUNT(emv_curated_symbols); ++i) {
        if (strcmp(name, emv_curated_symbols[i])) continue;
        dictionary = tlv_emv_dictionary_for(TLV_EMV_CONTEXT_BASE);
        for (j = 0; j < dictionary->count; ++j) {
            const tlv_emv_definition_t* entry = &dictionary->entries[j];
            if (!strcmp(name, tlv_emv_symbol(entry))) return entry->definition->name;
        }
    }
    return NULL;
}

tlv_result_t tlv_emv_titlecase_name(const char* name, char* buffer, size_t capacity) {
    size_t i;
    int initial = 1;
    if (!name || !buffer) return TLV_ERR_NULL_ARG;
    for (i = 0; name[i]; ++i) {
        if (capacity <= i) return TLV_ERR_BUFFER_TOO_SHORT;
        if (name[i] == '_') {
            buffer[i] = ' ';
            initial = 1;
        } else {
            if (initial)
                buffer[i] = (char)toupper((unsigned char)name[i]);
            else
                buffer[i] = name[i];
            initial = 0;
        }
    }
    if (capacity <= i) return TLV_ERR_BUFFER_TOO_SHORT;
    buffer[i] = '\0';
    return TLV_OK;
}
