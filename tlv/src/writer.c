#include "tlv/writer.h"
#include <string.h>

tlv_result_t tlv_writer_init(tlv_writer_t* writer, uint8_t* buf,
                                        size_t capacity, const tlv_format_t* format) {
    if (!writer || (!buf && capacity) || !format || !format->write_tag ||
        !format->write_length || !format->length_size) return TLV_ERR_NULL_ARG;
    writer->buf = buf;
    writer->capacity = capacity;
    writer->pos = 0;
    writer->format = format;
    return TLV_OK;
}

tlv_result_t tlv_writer_write(tlv_writer_t* writer, tlv_tag_t tag,
                               const uint8_t* value, size_t length) {
    size_t tag_size = 0, length_size = 0, written = 0, remaining;
    uint8_t* data;
    const tlv_format_t* format;
    tlv_result_t rc;
    if (!writer || (!value && length)) return TLV_ERR_NULL_ARG;
    format = writer->format;
    if (!format || !format->write_tag || !format->write_length || !format->length_size)
        return TLV_ERR_NULL_ARG;
    if (!tag.size || tag.size > TLV_TAG_MAX_SIZE) return TLV_ERR_INVALID_TAG;
    rc = format->write_tag(format->context, NULL, 0, &tag, &tag_size);
    if (rc != TLV_OK) return rc;
    if (!tag_size) return TLV_ERR_INVALID_TAG;
    rc = format->length_size(format->context, length, &length_size);
    if (rc != TLV_OK) return rc;
    if (writer->pos > writer->capacity) return TLV_ERR_BUFFER_TOO_SHORT;
    remaining = writer->capacity - writer->pos;
    if (tag_size > remaining) return TLV_ERR_BUFFER_TOO_SHORT;
    remaining -= tag_size;
    if (length_size > remaining) return TLV_ERR_BUFFER_TOO_SHORT;
    remaining -= length_size;
    if (length > remaining) return TLV_ERR_BUFFER_TOO_SHORT;
    if (!writer->buf) return TLV_ERR_NULL_ARG;
    data = writer->buf + writer->pos;
    rc = format->write_tag(format->context, data, tag_size, &tag, &written);
    if (rc != TLV_OK) return rc;
    if (written != tag_size) return TLV_ERR_INVALID_TAG;
    written = 0;
    rc = format->write_length(format->context, data + tag_size, length_size, length, &written);
    if (rc != TLV_OK) return rc;
    if (written != length_size) return TLV_ERR_INVALID_LENGTH;
    if (length) memcpy(data + tag_size + length_size, value, length);
    writer->pos += tag_size + length_size + length;
    return TLV_OK;
}

size_t tlv_writer_size(const tlv_writer_t* writer) {
    return writer ? writer->pos : 0;
}
