#include "tlv/builtins/fixed/fixed.h"
#include "tlv/format.h"
#include <stdint.h>

static tlv_result_t read_tag(const void* context, const uint8_t* data, size_t size, tlv_tag_t* tag,
                             size_t* consumed) {
    const tlv_fixed_config_t* config = (const tlv_fixed_config_t*)context;
    if (size < config->tag_size) return TLV_ERR_BUFFER_TOO_SHORT;
    *tag = tlv_tag(data, config->tag_size);
    *consumed = config->tag_size;
    return TLV_OK;
}

static tlv_result_t write_tag(const void* context, uint8_t* data, size_t capacity,
                              const tlv_tag_t* tag, size_t* written) {
    const tlv_fixed_config_t* config = (const tlv_fixed_config_t*)context;
    if (tag->size != config->tag_size) return TLV_ERR_INVALID_TAG_SIZE;
    if (!tag->data) return TLV_ERR_NULL_ARG;
    *written = config->tag_size;
    if (!data) return TLV_OK;
    if (capacity < config->tag_size) return TLV_ERR_BUFFER_TOO_SHORT;
    for (size_t i = 0; i < config->tag_size; ++i) data[i] = tag->data[i];
    return TLV_OK;
}

static tlv_result_t read_length(const void* context, const uint8_t* data, size_t size,
                                size_t* length, size_t* consumed) {
    const tlv_fixed_config_t* config = (const tlv_fixed_config_t*)context;
    if (size < config->length_size) return TLV_ERR_BUFFER_TOO_SHORT;
    uint64_t value = 0;
    tlv_result_t rc = tlv_read_uint(data, config->length_size, config->order, &value);
    if (rc != TLV_OK) return rc;
    if (value > (uint64_t)SIZE_MAX) return TLV_ERR_INVALID_LENGTH;
    *length = (size_t)value;
    *consumed = config->length_size;
    return TLV_OK;
}

static tlv_result_t length_size(const void* context, size_t length, size_t* size) {
    const tlv_fixed_config_t* config = (const tlv_fixed_config_t*)context;
    uint64_t max_length =
        config->length_size >= 8 ? UINT64_MAX : (((uint64_t)1 << (8 * config->length_size)) - 1);
    if ((uint64_t)length > max_length) return TLV_ERR_INVALID_LENGTH;
    *size = config->length_size;
    return TLV_OK;
}

static tlv_result_t write_length(const void* context, uint8_t* data, size_t capacity, size_t length,
                                 size_t* written) {
    tlv_result_t rc = length_size(context, length, written);
    if (rc != TLV_OK) return rc;
    if (!data) return TLV_OK;
    const tlv_fixed_config_t* config = (const tlv_fixed_config_t*)context;
    if (capacity < config->length_size) return TLV_ERR_BUFFER_TOO_SHORT;
    return tlv_write_uint(data, config->length_size, config->order, (uint64_t)length);
}

static int config_is_valid(const tlv_fixed_config_t* config) {
    return config->tag_size >= 1 && config->length_size >= 1 && config->length_size <= 8;
}

tlv_result_t tlv_fixed_reader_format_init(tlv_reader_format_t* format,
                                          const tlv_fixed_config_t* config) {
    if (!format || !config || !config_is_valid(config)) return TLV_ERR_INVALID_ARG;
    if (config->order != TLV_BYTE_ORDER_BIG_ENDIAN && config->order != TLV_BYTE_ORDER_LITTLE_ENDIAN)
        return TLV_ERR_INVALID_BYTE_ORDER;
    return tlv_reader_format_init(format, config, read_tag, read_length);
}

tlv_result_t tlv_fixed_writer_format_init(tlv_writer_format_t* format,
                                          const tlv_fixed_config_t* config) {
    if (!format || !config || !config_is_valid(config)) return TLV_ERR_INVALID_ARG;
    if (config->order != TLV_BYTE_ORDER_BIG_ENDIAN && config->order != TLV_BYTE_ORDER_LITTLE_ENDIAN)
        return TLV_ERR_INVALID_BYTE_ORDER;
    return tlv_writer_format_init(format, config, write_tag, write_length, length_size);
}
