#include "tlv/formats/fixed.h"
#include "tlv/format.h"
#include "fixed_internal.h"
#include <stdint.h>

/* TLV_ELEMENT_ORDER_TLV: tag, then length, then value. Element order never
 * changes here, so the classic split tag/length callbacks apply directly;
 * only the length<->value-size conversion below depends on length_scope. */

static tlv_result_t read_tag(const void* context, const uint8_t* data, size_t size, tlv_tag_t* tag,
                             size_t* consumed) {
    const tlv_fixed_format_t* config = (const tlv_fixed_format_t*)context;
    if (size < config->tag_size) return TLV_ERR_BUFFER_TOO_SHORT;
    *tag = tlv_tag(data, config->tag_size);
    *consumed = config->tag_size;
    return TLV_OK;
}

static tlv_result_t write_tag(const void* context, uint8_t* data, size_t capacity,
                              const tlv_tag_t* tag, size_t* written) {
    const tlv_fixed_format_t* config = (const tlv_fixed_format_t*)context;
    if (tag->size != config->tag_size) return TLV_ERR_INVALID_TAG_SIZE;
    if (!tag->data) return TLV_ERR_NULL_ARG;
    *written = config->tag_size;
    if (!data) return TLV_OK;
    if (capacity < config->tag_size) return TLV_ERR_BUFFER_TOO_SHORT;
    for (size_t i = 0; i < config->tag_size; ++i) data[i] = tag->data[i];
    return TLV_OK;
}

/* The non-value portion of an encoded length: 0 for TLV_LENGTH_SCOPE_VALUE,
 * config->tag_size for TLV_LENGTH_SCOPE_TAG_AND_VALUE. */
static uint64_t length_scope_offset(const tlv_fixed_format_t* config) {
    return config->length_scope == TLV_LENGTH_SCOPE_TAG_AND_VALUE ? (uint64_t)config->tag_size : 0;
}

static uint64_t length_field_max(const tlv_fixed_format_t* config) {
    return config->length_size >= 8 ? UINT64_MAX : (((uint64_t)1 << (8 * config->length_size)) - 1);
}

static tlv_result_t read_length(const void* context, const uint8_t* data, size_t size,
                                tlv_size_t* length, size_t* consumed) {
    const tlv_fixed_format_t* config = (const tlv_fixed_format_t*)context;
    *consumed = size < config->length_size ? size : config->length_size;
    if (size < config->length_size) return TLV_ERR_BUFFER_TOO_SHORT;
    uint64_t value = 0;
    tlv_result_t rc = tlv_read_uint(data, config->length_size, config->length_order, &value);
    if (rc != TLV_OK) return rc;
    uint64_t offset = length_scope_offset(config);
    if (value < offset) return TLV_ERR_INVALID_LENGTH;
    value -= offset;
    *length = value;
    *consumed = config->length_size;
    return TLV_OK;
}

static tlv_result_t length_size(const void* context, tlv_size_t length, size_t* size) {
    const tlv_fixed_format_t* config = (const tlv_fixed_format_t*)context;
    uint64_t max_length = length_field_max(config);
    uint64_t offset = length_scope_offset(config);
    if (offset > max_length || (uint64_t)length > max_length - offset)
        return TLV_ERR_INVALID_LENGTH;
    *size = config->length_size;
    return TLV_OK;
}

static tlv_result_t write_length(const void* context, uint8_t* data, size_t capacity,
                                 tlv_size_t length, size_t* written) {
    tlv_result_t rc = length_size(context, length, written);
    if (rc != TLV_OK) return rc;
    if (!data) return TLV_OK;
    const tlv_fixed_format_t* config = (const tlv_fixed_format_t*)context;
    if (capacity < config->length_size) return TLV_ERR_BUFFER_TOO_SHORT;
    uint64_t offset = length_scope_offset(config);
    return tlv_write_uint(data, config->length_size, config->length_order,
                          (uint64_t)length + offset);
}

/* TLV_ELEMENT_ORDER_LTV: length, then tag, then value. The length field
 * precedes the tag, so the classic split callbacks cannot express it (a
 * reader always parses tag then length); the whole-element callbacks parse
 * and encode both fields together instead. Exposed internally so the
 * Bluetooth LTV preset can reuse this logic exactly rather than
 * reimplementing it. */

tlv_result_t tlv_fixed_read_element_ltv(const void* context, const uint8_t* data, size_t size,
                                        tlv_tag_t* tag, tlv_length_t* length_field,
                                        size_t* header_size, tlv_size_t* value_size,
                                        size_t* trailer_size) {
    const tlv_fixed_format_t* config = (const tlv_fixed_format_t*)context;
    uint64_t raw_length = 0;
    uint64_t offset = length_scope_offset(config);
    size_t available; /* bytes after the length field: must hold the tag and the value */
    tlv_result_t rc;

    /* Only the length field itself needs to fit before it is decoded and
     * validated: a length too small to cover the non-value portion it must
     * count is TLV_ERR_INVALID_LENGTH even when the buffer has no room left
     * for the tag, matching what a hand-written Bluetooth LTV parser (whose
     * length field is always 1 byte) checks. */
    length_field->data = size ? data : NULL;
    length_field->size = size < config->length_size ? size : config->length_size;
    if (size < config->length_size) return TLV_ERR_BUFFER_TOO_SHORT;
    rc = tlv_read_uint(data, config->length_size, config->length_order, &raw_length);
    if (rc != TLV_OK) return rc;
    if (raw_length < offset) return TLV_ERR_INVALID_LENGTH;
    raw_length -= offset;
    available = size - config->length_size;
    if (config->tag_size > available) return TLV_ERR_BUFFER_TOO_SHORT;

    *tag = tlv_tag(data + config->length_size, config->tag_size);
    length_field->data = data;
    length_field->size = config->length_size;
    *header_size = config->length_size + config->tag_size;
    *value_size = raw_length;
    *trailer_size = 0;
    return TLV_OK;
}

tlv_result_t tlv_fixed_write_header_ltv(const void* context, uint8_t* data, size_t capacity,
                                        const tlv_tag_t* tag, tlv_size_t length, size_t* written) {
    const tlv_fixed_format_t* config = (const tlv_fixed_format_t*)context;
    size_t header = config->length_size + config->tag_size;
    uint64_t max_length = length_field_max(config);
    uint64_t offset = length_scope_offset(config);
    tlv_result_t rc;

    if (tag->size != config->tag_size) return TLV_ERR_INVALID_TAG_SIZE;
    if (!tag->data) return TLV_ERR_NULL_ARG;
    if (offset > max_length || (uint64_t)length > max_length - offset)
        return TLV_ERR_INVALID_LENGTH;

    *written = header;
    if (!data) return TLV_OK;
    if (capacity < header) return TLV_ERR_BUFFER_TOO_SHORT;

    rc = tlv_write_uint(data, config->length_size, config->length_order, (uint64_t)length + offset);
    if (rc != TLV_OK) return rc;
    for (size_t i = 0; i < config->tag_size; ++i) data[config->length_size + i] = tag->data[i];
    return TLV_OK;
}

static int config_is_valid(const tlv_fixed_format_t* config) {
    return config->tag_size >= 1 && config->length_size >= 1 && config->length_size <= 8 &&
           (config->element_order == TLV_ELEMENT_ORDER_TLV ||
            config->element_order == TLV_ELEMENT_ORDER_LTV) &&
           (config->length_scope == TLV_LENGTH_SCOPE_VALUE ||
            config->length_scope == TLV_LENGTH_SCOPE_TAG_AND_VALUE);
}

tlv_result_t tlv_fixed_format_init(tlv_format_t* format, const tlv_fixed_format_t* config) {
    if (!format || !config || !config_is_valid(config)) return TLV_ERR_INVALID_ARG;
    if (config->length_order != TLV_BYTE_ORDER_BIG_ENDIAN &&
        config->length_order != TLV_BYTE_ORDER_LITTLE_ENDIAN)
        return TLV_ERR_INVALID_BYTE_ORDER;
    if (config->element_order == TLV_ELEMENT_ORDER_LTV)
        return tlv_format_init_element(format, config, tlv_fixed_read_element_ltv,
                                       tlv_fixed_write_header_ltv);
    return tlv_format_init(format, config, read_tag, read_length, write_tag, write_length,
                           length_size);
}
