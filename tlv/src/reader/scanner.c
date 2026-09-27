#include "tlv/reader/scanner.h"
#include "tlv/reader/reader.h"
#include "tlv/size.h"

tlv_result_t tlv_scan(const uint8_t* data, size_t size, size_t start, const tlv_format_t* format,
                      const tlv_schema_t* schema, tlv_element_t* out_element, size_t* out_offset,
                      size_t* consumed) {
    size_t offset;
    if ((!data && size) || !tlv_format_can_read(format) || !out_element || !out_offset ||
        !consumed || (schema && !schema->entries && schema->count))
        return TLV_ERR_NULL_ARG;

    for (offset = start; offset < size; ++offset) {
        tlv_element_t element;
        size_t encoded_size;
        if (tlv_read(data + offset, size - offset, format, &element, &encoded_size) != TLV_OK)
            continue;
        if (schema) {
            const tlv_schema_entry_t* rule = tlv_schema_find(schema, &element.tag);
            /* element.value.size always comes from tlv_read(), which derives it
             * from this same build's size_t, so this conversion cannot actually
             * fail here; it is kept to honor the length.h module boundary and
             * to stay correct if element is ever sourced differently. */
            size_t value_length;
            if (!rule || tlv_size_to_native(element.value.size, &value_length) != TLV_OK ||
                tlv_schema_validate_length(rule, value_length) != TLV_OK)
                continue;
        }
        *out_element = element;
        *out_offset = offset;
        *consumed = encoded_size;
        return TLV_OK;
    }
    return TLV_ERR_END_OF_BUFFER;
}
