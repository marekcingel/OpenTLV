#include "tlv/formats/default.h"
#include "tlv/formats/format.h"

static tlv_result_t read_tag(const void* ctx, const uint8_t* data, size_t size,
                              tlv_tag_t* tag, size_t* used) {
    (void)ctx;
    if (!size) return TLV_ERR_BUFFER_TOO_SHORT;
    *tag = (tlv_tag_t){{0}, 1};
    tag->data[0] = data[0];
    *used = 1;
    return TLV_OK;
}

static tlv_result_t write_tag(const void* ctx, uint8_t* data, size_t capacity,
                               const tlv_tag_t* tag, size_t* used) {
    (void)ctx;
    if (tag->size != 1) return TLV_ERR_INVALID_TAG;
    *used = 1;
    if (!data) return TLV_OK;
    if (!capacity) return TLV_ERR_BUFFER_TOO_SHORT;
    data[0] = tag->data[0];
    return TLV_OK;
}

static tlv_result_t read_length(const void* ctx, const uint8_t* data, size_t size,
                                 size_t* length, size_t* used) {
    (void)ctx;
    if (!size) return TLV_ERR_BUFFER_TOO_SHORT;
    if (data[0] < 0x80) {
        *length = data[0];
        *used = 1;
    } else if (data[0] == 0x81) {
        if (size < 2) return TLV_ERR_BUFFER_TOO_SHORT;
        *length = data[1];
        *used = 2;
    } else if (data[0] == 0x82) {
        if (size < 3) return TLV_ERR_BUFFER_TOO_SHORT;
        *length = ((size_t)data[1] << 8) | data[2];
        *used = 3;
    } else return TLV_ERR_INVALID_LENGTH;
    return TLV_OK;
}

static tlv_result_t length_size(const void* ctx, size_t length, size_t* size) {
    (void)ctx;
    if (length > 0xFFFF) return TLV_ERR_INVALID_LENGTH;
    *size = length < 0x80 ? 1 : (length <= 0xFF ? 2 : 3);
    return TLV_OK;
}

static tlv_result_t write_length(const void* ctx, uint8_t* data, size_t capacity,
                                  size_t length, size_t* used) {
    tlv_result_t rc = length_size(ctx, length, used);
    if (rc != TLV_OK) return rc;
    if (capacity < *used) return TLV_ERR_BUFFER_TOO_SHORT;
    if (*used == 1) data[0] = (uint8_t)length;
    else if (*used == 2) {
        data[0] = 0x81;
        data[1] = (uint8_t)length;
    } else {
        data[0] = 0x82;
        data[1] = (uint8_t)(length >> 8);
        data[2] = (uint8_t)length;
    }
    return TLV_OK;
}

const tlv_format_t tlv_format_default = {
    NULL, read_tag, write_tag, read_length, write_length, length_size, NULL
};

