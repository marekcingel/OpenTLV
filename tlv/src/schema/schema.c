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
        length > entry->max_length)
        return TLV_ERR_INVALID_LENGTH;
    return TLV_OK;
}
