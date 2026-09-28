#include "tlv/definition.h"

const tlv_definition_t* tlv_definition_find(const tlv_definition_registry_t* registry,
                                            const tlv_tag_t* tag) {
    size_t i;
    if (!registry || !tag || (!registry->entries && registry->count != 0)) return NULL;
    if (tag->size && !tag->data) return NULL;
    for (i = 0; i < registry->count; ++i) {
        const tlv_definition_t* entry = &registry->entries[i];
        if (entry->tag.size && !entry->tag.data) continue;
        if (tlv_tag_equal(entry->tag, *tag)) return entry;
    }
    return NULL;
}
