#include "tlv/format.h"
#include <string.h>

static tlv_result_t read_tag(const void* context, const uint8_t* data, size_t size,
                             tlv_tag_t* tag, size_t* consumed) {
    size_t count = 1;
    (void)context;
    if (!size) return TLV_ERR_BUFFER_TOO_SHORT;
    if ((data[0] & 0x1F) == 0x1F) {
        for (;;) {
            if (count == TLV_TAG_MAX_SIZE) return TLV_ERR_INVALID_TAG;
            if (count == size) return TLV_ERR_BUFFER_TOO_SHORT;
            /* The first base-128 digit must be nonzero. Keep raw tag bytes,
             * including BER-TLV identifiers such as 9F 1C. */
            if (count == 1 && !(data[count] & 0x7F)) return TLV_ERR_INVALID_TAG;
            if (!(data[count++] & 0x80)) break;
        }
    }
    *tag = (tlv_tag_t){{0}, 0};
    memcpy(tag->data, data, count);
    tag->size = (uint8_t)count;
    *consumed = count;
    return TLV_OK;
}

static tlv_result_t write_tag(const void* context, uint8_t* data, size_t capacity,
                              const tlv_tag_t* tag, size_t* written) {
    tlv_tag_t parsed;
    size_t count;
    tlv_result_t rc;
    if (!tag->size || tag->size > TLV_TAG_MAX_SIZE) return TLV_ERR_INVALID_TAG;
    rc = read_tag(context, tag->data, tag->size, &parsed, &count);
    if (rc != TLV_OK || count != tag->size) return TLV_ERR_INVALID_TAG;
    *written = count;
    if (!data) return TLV_OK;
    if (capacity < count) return TLV_ERR_BUFFER_TOO_SHORT;
    memcpy(data, tag->data, count);
    return TLV_OK;
}

static tlv_result_t read_length(const void* context, const uint8_t* data, size_t size,
                                size_t* length, size_t* consumed) {
    size_t count, value = 0;
    (void)context;
    if (!size) return TLV_ERR_BUFFER_TOO_SHORT;
    if (data[0] < 0x80) {
        *length = data[0];
        *consumed = 1;
        return TLV_OK;
    }
    /* Indefinite lengths and the reserved FF prefix are unsupported. */
    if (data[0] == 0x80 || data[0] == 0xFF) return TLV_ERR_INVALID_LENGTH;
    count = data[0] & 0x7F;
    if (size - 1 < count) return TLV_ERR_BUFFER_TOO_SHORT;
    for (size_t i = 1; i <= count; ++i) {
        if (value > (SIZE_MAX >> 8)) return TLV_ERR_INVALID_LENGTH;
        value = (value << 8) | data[i];
    }
    *length = value;
    *consumed = count + 1;
    return TLV_OK;
}

static tlv_result_t length_size(const void* context, size_t length, size_t* size) {
    size_t count = 1;
    (void)context;
    if (length >= 0x80) {
        do { ++count; length >>= 8; } while (length);
    }
    *size = count;
    return TLV_OK;
}

static tlv_result_t write_length(const void* context, uint8_t* data, size_t capacity,
                                 size_t length, size_t* written) {
    length_size(context, length, written);
    if (capacity < *written) return TLV_ERR_BUFFER_TOO_SHORT;
    if (*written == 1) data[0] = (uint8_t)length;
    else {
        data[0] = (uint8_t)(0x80 | (*written - 1));
        for (size_t i = *written - 1; i; --i) {
            data[i] = (uint8_t)length;
            length >>= 8;
        }
    }
    return TLV_OK;
}

const tlv_format_t tlv_format_ber = {
    NULL, read_tag, write_tag, read_length, write_length, length_size
};
