#include "tlv/formats/default/default.h"
#include "tlv/formats/format.h"
#include "tlv/endian.h"
#include <stdint.h>

/* This format's own length-field encoding (not an ASN.1/BER rule): values
 * below 0x80 fit in the single length octet; 0x81/0x82 flag that 1 or 2
 * extra length octets follow. */
enum {
    TLV_DEFAULT_LENGTH_LONG_FORM_BIT = 0x80,
    TLV_DEFAULT_LENGTH_FORM_1BYTE = 0x81,
    TLV_DEFAULT_LENGTH_FORM_2BYTE = 0x82
};

static tlv_result_t read_tag(const void* ctx, const uint8_t* data, size_t size, tlv_tag_t* tag,
                             size_t* used) {
    (void)ctx;
    if (!size) return TLV_ERR_BUFFER_TOO_SHORT;
    *tag = (tlv_tag_t){{0}, 1};
    tag->data[0] = data[0];
    *used = 1;
    return TLV_OK;
}

static tlv_result_t write_tag(const void* ctx, uint8_t* data, size_t capacity, const tlv_tag_t* tag,
                              size_t* used) {
    (void)ctx;
    if (tag->size != 1) return TLV_ERR_INVALID_TAG_SIZE;
    *used = 1;
    if (!data) return TLV_OK;
    if (!capacity) return TLV_ERR_BUFFER_TOO_SHORT;
    data[0] = tag->data[0];
    return TLV_OK;
}

static tlv_result_t read_length(const void* ctx, const uint8_t* data, size_t size, size_t* length,
                                size_t* used) {
    (void)ctx;
    if (!size) return TLV_ERR_BUFFER_TOO_SHORT;
    if (data[0] < TLV_DEFAULT_LENGTH_LONG_FORM_BIT) {
        *length = data[0];
        *used = 1;
    } else if (data[0] == TLV_DEFAULT_LENGTH_FORM_1BYTE) {
        if (size < 2) return TLV_ERR_BUFFER_TOO_SHORT;
        *length = data[1];
        *used = 2;
    } else if (data[0] == TLV_DEFAULT_LENGTH_FORM_2BYTE) {
        if (size < 3) return TLV_ERR_BUFFER_TOO_SHORT;
        *length = tlv_read_u16_be(data + 1);
        *used = 3;
    } else
        return TLV_ERR_INVALID_LENGTH;
    return TLV_OK;
}

static tlv_result_t length_size(const void* ctx, size_t length, size_t* size) {
    (void)ctx;
    if (length > UINT16_MAX) return TLV_ERR_INVALID_LENGTH;
    *size = length < TLV_DEFAULT_LENGTH_LONG_FORM_BIT ? 1 : (length <= UINT8_MAX ? 2 : 3);
    return TLV_OK;
}

static tlv_result_t write_length(const void* ctx, uint8_t* data, size_t capacity, size_t length,
                                 size_t* used) {
    tlv_result_t rc = length_size(ctx, length, used);
    if (rc != TLV_OK) return rc;
    if (capacity < *used) return TLV_ERR_BUFFER_TOO_SHORT;
    if (*used == 1)
        data[0] = (uint8_t)length;
    else if (*used == 2) {
        data[0] = TLV_DEFAULT_LENGTH_FORM_1BYTE;
        data[1] = (uint8_t)length;
    } else {
        data[0] = TLV_DEFAULT_LENGTH_FORM_2BYTE;
        tlv_write_u16_be(data + 1, (uint16_t)length);
    }
    return TLV_OK;
}

const tlv_reader_format_t tlv_reader_format_default = {
    .context = NULL, .read_tag = read_tag, .read_length = read_length};

const tlv_writer_format_t tlv_writer_format_default = {.context = NULL,
                                                       .write_tag = write_tag,
                                                       .write_length = write_length,
                                                       .length_size = length_size};
