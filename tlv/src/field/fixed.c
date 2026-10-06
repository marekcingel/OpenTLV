// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/field/fixed.h"
#include <string.h>

tlv_result_t tlv_fixed_identifier_read(const tlv_fixed_identifier_t* config, const uint8_t* data,
                                       size_t size, tlv_tag_t* tag, size_t* consumed) {
    if (!config || (!data && size) || !tag || !consumed) return TLV_ERR_NULL_ARG;
    if (!config->size) return TLV_ERR_INVALID_ARG;
    if (size < config->size) return TLV_ERR_BUFFER_TOO_SHORT;
    *tag = tlv_tag(data, config->size);
    *consumed = config->size;
    return TLV_OK;
}

tlv_result_t tlv_fixed_identifier_write(const tlv_fixed_identifier_t* config, const tlv_tag_t* tag,
                                        uint8_t* data, size_t capacity, size_t* written) {
    if (!config || !tag || (!tag->data && tag->size) || (!data && capacity) || !written)
        return TLV_ERR_NULL_ARG;
    if (!config->size) return TLV_ERR_INVALID_ARG;
    if (tag->size != config->size) return TLV_ERR_INVALID_TAG_SIZE;
    if (data && capacity < config->size) return TLV_ERR_BUFFER_TOO_SHORT;
    if (data) memcpy(data, tag->data, config->size);
    *written = config->size;
    return TLV_OK;
}

static tlv_result_t length_validate(const tlv_fixed_length_t* config) {
    if (!config->size || config->size > 8) return TLV_ERR_INVALID_ARG;
    if (config->byte_order != TLV_BYTE_ORDER_BIG_ENDIAN &&
        config->byte_order != TLV_BYTE_ORDER_LITTLE_ENDIAN)
        return TLV_ERR_INVALID_BYTE_ORDER;
    return TLV_OK;
}

tlv_result_t tlv_fixed_length_read(const tlv_fixed_length_t* config, const uint8_t* data,
                                   size_t size, tlv_size_t* length, size_t* consumed) {
    tlv_result_t rc;
    if (!config || (!data && size) || !length || !consumed) return TLV_ERR_NULL_ARG;
    rc = length_validate(config);
    if (rc != TLV_OK) return rc;
    *consumed = size < config->size ? size : config->size;
    if (size < config->size) return TLV_ERR_BUFFER_TOO_SHORT;
    return tlv_read_uint(data, config->size, config->byte_order, length);
}

tlv_result_t tlv_fixed_length_write(const tlv_fixed_length_t* config, tlv_size_t length,
                                    uint8_t* data, size_t capacity, size_t* written) {
    tlv_result_t rc;
    if (!config || (!data && capacity) || !written) return TLV_ERR_NULL_ARG;
    rc = length_validate(config);
    if (rc != TLV_OK) return rc;
    if (config->size < 8 && length >= (UINT64_C(1) << (8 * config->size)))
        return TLV_ERR_INVALID_LENGTH;
    if (data) {
        if (capacity < config->size) return TLV_ERR_BUFFER_TOO_SHORT;
        rc = tlv_write_uint(data, config->size, config->byte_order, length);
        if (rc != TLV_OK) return rc;
    }
    *written = config->size;
    return TLV_OK;
}
