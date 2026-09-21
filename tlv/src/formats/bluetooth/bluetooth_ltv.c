#include "tlv/formats/bluetooth/bluetooth_ltv.h"
#include "tlv/formats/format.h"
#include <stdint.h>

/* The length byte counts the type byte and the value: a structure is length + 1 bytes. */
#define LTV_MAX_VALUE ((size_t)UINT8_MAX - 1)

static tlv_result_t read_element(const void* context, const uint8_t* data, size_t size,
                                 tlv_tag_t* tag, size_t* header_size, size_t* value_size,
                                 size_t* trailer_size) {
    size_t length;
    (void)context;
    if (!size) return TLV_ERR_BUFFER_TOO_SHORT;
    length = data[0];
    if (!length) return TLV_ERR_INVALID_LENGTH;
    if (length > size - 1) return TLV_ERR_BUFFER_TOO_SHORT;
    *tag = tlv_tag(data + 1, 1);
    *header_size = 2;
    *value_size = length - 1;
    *trailer_size = 0;
    return TLV_OK;
}

static tlv_result_t write_header(const void* context, uint8_t* data, size_t capacity,
                                 const tlv_tag_t* tag, size_t length, size_t* written) {
    (void)context;
    if (tag->size != 1) return TLV_ERR_INVALID_TAG_SIZE;
    if (!tag->data) return TLV_ERR_NULL_ARG;
    if (length > LTV_MAX_VALUE) return TLV_ERR_INVALID_LENGTH;
    *written = 2;
    if (!data) return TLV_OK;
    if (capacity < 2) return TLV_ERR_BUFFER_TOO_SHORT;
    data[0] = (uint8_t)(length + 1);
    data[1] = tag->data[0];
    return TLV_OK;
}

const tlv_reader_format_t tlv_reader_format_bluetooth_ltv = {.context = NULL,
                                                             .read_element = read_element};

const tlv_writer_format_t tlv_writer_format_bluetooth_ltv = {.context = NULL,
                                                             .write_header = write_header};
