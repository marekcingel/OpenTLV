#include "tlv/writer.h"
#include <string.h>

tlv_result_t tlv_writer_init(tlv_writer_t* writer, uint8_t* buf, size_t capacity) {
    if (writer == NULL) {
        return TLV_ERR_NULL_ARG;
    }
    if (buf == NULL && capacity != 0) {
        return TLV_ERR_NULL_ARG;
    }
    writer->buf = buf;
    writer->capacity = capacity;
    writer->pos = 0;
    return TLV_OK;
}

/* Returns the number of bytes required to BER-encode the given length. */
static size_t length_header_size(size_t length) {
    if (length < 0x80) {
        return 1;
    }
    if (length <= 0xFF) {
        return 2;
    }
    if (length <= 0xFFFF) {
        return 3;
    }
    return 0; /* unsupported; too large */
}

static void encode_length(uint8_t* out, size_t length, size_t header_size) {
    if (header_size == 1) {
        out[0] = (uint8_t)length;
    } else if (header_size == 2) {
        out[0] = 0x81;
        out[1] = (uint8_t)length;
    } else if (header_size == 3) {
        out[0] = 0x82;
        out[1] = (uint8_t)((length >> 8) & 0xFF);
        out[2] = (uint8_t)(length & 0xFF);
    }
}

tlv_result_t tlv_writer_write(tlv_writer_t* writer, tlv_tag_t tag,
                               const uint8_t* value, size_t length) {
    if (writer == NULL) {
        return TLV_ERR_NULL_ARG;
    }
    if (value == NULL && length != 0) {
        return TLV_ERR_NULL_ARG;
    }

    size_t len_hdr = length_header_size(length);
    if (len_hdr == 0) {
        return TLV_ERR_INVALID_LENGTH;
    }

    size_t total = 1 + len_hdr + length; /* tag + length + value */
    if (writer->pos + total > writer->capacity) {
        return TLV_ERR_BUFFER_TOO_SHORT;
    }

    writer->buf[writer->pos] = tag;
    encode_length(writer->buf + writer->pos + 1, length, len_hdr);
    if (length > 0) {
        memcpy(writer->buf + writer->pos + 1 + len_hdr, value, length);
    }

    writer->pos += total;
    return TLV_OK;
}

size_t tlv_writer_size(const tlv_writer_t* writer) {
    if (writer == NULL) {
        return 0;
    }
    return writer->pos;
}
