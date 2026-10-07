// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "variable_internal.h"
#include <string.h>

/* Prefix payload bits are an unsigned field, independently of their positions. */
static unsigned unpack(uint8_t byte, uint8_t mask) {
    unsigned result = 0, digit = 1;
    for (unsigned bit = 1; bit <= 0x80; bit <<= 1) {
        if (mask & bit) {
            if (byte & bit) result |= digit;
            digit <<= 1;
        }
    }
    return result;
}

static uint8_t pack(unsigned value, uint8_t mask) {
    unsigned result = 0;
    for (unsigned bit = 1; bit <= 0x80; bit <<= 1) {
        if (mask & bit) {
            if (value & 1) result |= bit;
            value >>= 1;
        }
    }
    return (uint8_t)result;
}

tlv_result_t tlv_variable_identifier_read(const tlv_variable_identifier_t* config,
                                          const uint8_t* data, size_t size, tlv_tag_t* tag,
                                          size_t* consumed) {
    size_t count = 1;
    tlv_result_t rc;
    if (!config || (!data && size) || !tag || !consumed) return TLV_ERR_NULL_ARG;
    rc = identifier_validate(config);
    if (rc != TLV_OK) return rc;
    if (!size) {
        *consumed = 0;
        return TLV_ERR_BUFFER_TOO_SHORT;
    }
    if ((data[0] & config->inline_mask) == config->escape) {
        for (;;) {
            uint8_t octet;
            if (count == config->max_size) return TLV_ERR_INVALID_TAG_SIZE;
            if (count == size) {
                *consumed = size;
                return TLV_ERR_BUFFER_TOO_SHORT;
            }
            octet = data[count++];
            if (octet & ~(config->continuation_bit | config->payload_mask))
                return TLV_ERR_INVALID_TAG;
            if (!(octet & config->continuation_bit)) break;
        }
    }
    *tag = tlv_tag(data, count);
    *consumed = count;
    return TLV_OK;
}

tlv_result_t tlv_variable_identifier_write(const tlv_variable_identifier_t* config,
                                           const tlv_tag_t* tag, uint8_t* data, size_t capacity,
                                           size_t* written) {
    tlv_tag_t parsed;
    size_t count;
    tlv_result_t rc;
    if (!config || !tag || (!tag->data && tag->size) || (!data && capacity) || !written)
        return TLV_ERR_NULL_ARG;
    rc = identifier_validate(config);
    if (rc != TLV_OK) return rc;
    if (!tag->size || tag->size > config->max_size) return TLV_ERR_INVALID_TAG_SIZE;
    rc = tlv_variable_identifier_read(config, tag->data, tag->size, &parsed, &count);
    if (rc == TLV_ERR_INVALID_TAG_SIZE) return rc;
    if (rc != TLV_OK || count != tag->size) return TLV_ERR_INVALID_TAG;
    if (data && capacity < count) return TLV_ERR_BUFFER_TOO_SHORT;
    if (data) memmove(data, tag->data, count);
    *written = count;
    return TLV_OK;
}

tlv_result_t tlv_variable_length_read(const tlv_variable_length_t* config, const uint8_t* data,
                                      size_t size, tlv_size_t* length, size_t* consumed) {
    size_t count;
    tlv_size_t value = 0;
    tlv_result_t rc;
    if (!config || (!data && size) || !length || !consumed) return TLV_ERR_NULL_ARG;
    rc = length_validate(config);
    if (rc != TLV_OK) return rc;
    *consumed = size ? 1 : 0;
    if (!size) return TLV_ERR_BUFFER_TOO_SHORT;
    if (data[0] & ~(config->long_form_bit | config->payload_mask)) return TLV_ERR_INVALID_LENGTH;
    count = unpack(data[0], config->payload_mask);
    if (!(data[0] & config->long_form_bit)) {
        *length = count;
        return TLV_OK;
    }
    if (!count) return TLV_ERR_INVALID_LENGTH;
    *consumed = count < size ? count + 1 : size;
    if (count >= size) return TLV_ERR_BUFFER_TOO_SHORT;
    /* Fold most significant octets first, permitting any number of zero
     * padding octets while checking every arithmetic step before shifting. */
    for (size_t i = 0; i < count; ++i) {
        size_t index = config->byte_order == TLV_BYTE_ORDER_BIG_ENDIAN ? i + 1 : count - i;
        if (value > (UINT64_MAX >> 8)) return TLV_ERR_OVERFLOW;
        value = (value << 8) | data[index];
    }
    *length = value;
    return TLV_OK;
}

tlv_result_t tlv_variable_length_write(const tlv_variable_length_t* config, tlv_size_t length,
                                       uint8_t* data, size_t capacity, size_t* written) {
    size_t count = 0, width;
    unsigned maximum;
    tlv_result_t rc;
    if (!config || (!data && capacity) || !written) return TLV_ERR_NULL_ARG;
    rc = length_validate(config);
    if (rc != TLV_OK) return rc;
    maximum = unpack(config->payload_mask, config->payload_mask);
    if (length > maximum) {
        tlv_size_t remaining = length;
        do {
            ++count;
            remaining >>= 8;
        } while (remaining);
        if (count > maximum) return TLV_ERR_INVALID_LENGTH;
    }
    width = count + 1;
    if (data) {
        if (capacity < width) return TLV_ERR_BUFFER_TOO_SHORT;
        if (!count)
            data[0] = pack((unsigned)length, config->payload_mask);
        else {
            data[0] =
                (uint8_t)(config->long_form_bit | pack((unsigned)count, config->payload_mask));
            /* The validated count is 1..8 and the byte order is explicit. */
            (void)tlv_write_uint(data + 1, count, config->byte_order, length);
        }
    }
    *written = width;
    return TLV_OK;
}
