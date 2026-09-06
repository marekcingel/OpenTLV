#include "tlv/scanner.h"
#include "tlv/reader.h"

tlv_result_t tlv_scan(const uint8_t* data, size_t size, size_t start,
                      const tlv_format_t* format, const tlv_schema_t* schema,
                      tlv_view_t* out_entry, size_t* out_offset, size_t* consumed) {
    size_t offset;
    if ((!data && size) || !format || !format->read_tag ||
        !format->read_length || !out_entry || !out_offset || !consumed ||
        (schema && !schema->entries && schema->count))
        return TLV_ERR_NULL_ARG;

    for (offset = start; offset < size; ++offset) {
        tlv_view_t entry;
        size_t encoded_size;
        if (tlv_read(data + offset, size - offset, format, &entry,
                     &encoded_size) != TLV_OK)
            continue;
        if (schema) {
            const tlv_schema_entry_t* rule = tlv_schema_find(schema, &entry.tag);
            if (!rule || tlv_schema_validate_length(rule, entry.value.length) != TLV_OK)
                continue;
        }
        *out_entry = entry;
        *out_offset = offset;
        *consumed = encoded_size;
        return TLV_OK;
    }
    return TLV_ERR_END_OF_BUFFER;
}
