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
    tlv_result_t result;
    if (!definition) return TLV_ERR_NULL_ARG;
    result = tlv_schema_validate_length(definition->schema, length);
    if (result != TLV_OK) return result;
    if (!definition->length_step ||
        (length - definition->schema->min_length) % definition->length_step)
        return TLV_ERR_INVALID_LENGTH;
    return TLV_OK;
}

/* Curated only where a generic title-cased label would be misleading:
 * abbreviations and initialisms that deserve their expansion and acronym. */
static const struct {
    const char *symbol, *label;
} emv_display_labels[] = {
    {"pan", "Primary Account Number (PAN)"},
    {"aip", "Application Interchange Profile (AIP)"},
    {"afl", "Application File Locator (AFL)"},
    {"tvr", "Terminal Verification Results (TVR)"},
    {"tsi", "Transaction Status Information (TSI)"},
    {"atc", "Application Transaction Counter (ATC)"},
    {"df_name", "Dedicated File (DF) Name"},
    {"adf_name", "Application Dedicated File (ADF) Name"},
    {"fci_template", "File Control Information (FCI) Template"},
    {"fci_proprietary_template", "File Control Information (FCI) Proprietary Template"},
    {"iin", "Issuer Identification Number (IIN)"},
    {"sfi", "Short File Identifier (SFI)"}};

const char* tlv_emv_display_label(const char* name) {
    size_t i;
    if (!name) return NULL;
    for (i = 0; i < EMV_COUNT(emv_display_labels); ++i)
        if (!strcmp(name, emv_display_labels[i].symbol)) return emv_display_labels[i].label;
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
