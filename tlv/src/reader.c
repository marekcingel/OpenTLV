#include "tlv/reader.h"

tlv_result_t tlv_reader_init(tlv_reader_t* reader, const uint8_t* data, size_t size) {
    if (reader == NULL) {
        return TLV_ERR_NULL_ARG;
    }
    if (data == NULL && size != 0) {
        return TLV_ERR_NULL_ARG;
    }
    reader->data = data;
    reader->size = size;
    reader->pos = 0;
    return TLV_OK;
}

int tlv_reader_at_end(const tlv_reader_t* reader) {
    if (reader == NULL) {
        return 1;
    }
    return reader->pos >= reader->size;
}

/*
 * Decodes a BER-style length beginning at reader->data[reader->pos].
 * Sets *out_length and *out_header_len (the number of bytes used by the length).
 */
static tlv_result_t decode_length(const tlv_reader_t* reader, size_t pos,
                                   size_t* out_length, size_t* out_header_len) {
    if (pos >= reader->size) {
        return TLV_ERR_BUFFER_TOO_SHORT;
    }

    uint8_t first = reader->data[pos];

    if (first < 0x80) {
        /* short form: length directly in one byte */
        *out_length = first;
        *out_header_len = 1;
        return TLV_OK;
    }

    if (first == 0x81) {
        if (pos + 1 >= reader->size) {
            return TLV_ERR_BUFFER_TOO_SHORT;
        }
        *out_length = reader->data[pos + 1];
        *out_header_len = 2;
        return TLV_OK;
    }

    if (first == 0x82) {
        if (pos + 2 >= reader->size) {
            return TLV_ERR_BUFFER_TOO_SHORT;
        }
        *out_length = ((size_t)reader->data[pos + 1] << 8) | (size_t)reader->data[pos + 2];
        *out_header_len = 3;
        return TLV_OK;
    }

    /* longer forms (0x83+) are not supported yet */
    return TLV_ERR_INVALID_LENGTH;
}

tlv_result_t tlv_reader_next(tlv_reader_t* reader, tlv_entry_t* out_entry) {
    if (reader == NULL || out_entry == NULL) {
        return TLV_ERR_NULL_ARG;
    }
    if (tlv_reader_at_end(reader)) {
        return TLV_ERR_END_OF_BUFFER;
    }

    /* at least a 1B tag and a 1B length must be available */
    if (reader->pos + 2 > reader->size) {
        return TLV_ERR_BUFFER_TOO_SHORT;
    }

    size_t length_pos = reader->pos + 1;

    size_t value_length = 0;
    size_t length_header_len = 0;
    tlv_result_t rc = decode_length(reader, length_pos, &value_length, &length_header_len);
    if (rc != TLV_OK) {
        return rc;
    }

    size_t header_len = 1 + length_header_len; /* tag + length */
    if (reader->pos + header_len + value_length > reader->size) {
        return TLV_ERR_BUFFER_TOO_SHORT;
    }

    out_entry->tag.data = reader->data + reader->pos;
    out_entry->tag.length = 1;
    out_entry->value.data = reader->data + reader->pos + header_len;
    out_entry->value.length = value_length;

    reader->pos += header_len + value_length;
    return TLV_OK;
}
