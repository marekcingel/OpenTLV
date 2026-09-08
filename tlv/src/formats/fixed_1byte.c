#include "tlv/formats/fixed_1byte.h"
#include "tlv/formats/format.h"

static tlv_result_t read_tag(const void* context, const uint8_t* data, size_t size,
                             tlv_tag_t* tag, size_t* consumed) {
    (void)context;
    if (!size) return TLV_ERR_BUFFER_TOO_SHORT;
    *tag = (tlv_tag_t){{0}, 1};
    tag->data[0] = data[0];
    *consumed = 1;
    return TLV_OK;
}

static tlv_result_t write_tag(const void* context, uint8_t* data, size_t capacity,
                              const tlv_tag_t* tag, size_t* written) {
    (void)context;
    if (tag->size != 1) return TLV_ERR_INVALID_TAG;
    *written = 1;
    if (!data) return TLV_OK;
    if (!capacity) return TLV_ERR_BUFFER_TOO_SHORT;
    data[0] = tag->data[0];
    return TLV_OK;
}

static tlv_result_t read_length(const void* context, const uint8_t* data, size_t size,
                                size_t* length, size_t* consumed) {
    (void)context;
    if (!size) return TLV_ERR_BUFFER_TOO_SHORT;
    *length = data[0];
    *consumed = 1;
    return TLV_OK;
}

static tlv_result_t length_size(const void* context, size_t length, size_t* size) {
    (void)context;
    if (length > 255) return TLV_ERR_INVALID_LENGTH;
    *size = 1;
    return TLV_OK;
}

static tlv_result_t write_length(const void* context, uint8_t* data, size_t capacity,
                                 size_t length, size_t* written) {
    tlv_result_t rc = length_size(context, length, written);
    if (rc != TLV_OK) return rc;
    if (!capacity) return TLV_ERR_BUFFER_TOO_SHORT;
    data[0] = (uint8_t)length;
    return TLV_OK;
}

const tlv_format_t tlv_format_fixed_1byte = {
    NULL, read_tag, write_tag, read_length, write_length, length_size, NULL
};
