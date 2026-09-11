#include "tlv/reader/reader.h"

tlv_result_t tlv_reader_init(tlv_reader_t* reader, const uint8_t* data,
                                        size_t size, const tlv_reader_format_t* format) {
    if (!reader || (!data && size) || !format ||
        !format->read_tag || !format->read_length) return TLV_ERR_NULL_ARG;
    reader->data = data;
    reader->size = size;
    reader->pos = 0;
    reader->format = format;
    return TLV_OK;
}

int tlv_reader_at_end(const tlv_reader_t* reader) {
    return !reader || reader->pos >= reader->size;
}

tlv_result_t tlv_read(const uint8_t* data, size_t size,
                      const tlv_reader_format_t* format, tlv_view_t* out_entry,
                      size_t* consumed) {
    tlv_view_t entry = {0};
    size_t tag_size = 0, length_size = 0, trailer_size = 0, remaining;
    tlv_result_t rc;
    if ((!data && size) || !out_entry || !consumed || !format ||
        !format->read_tag || !format->read_length)
        return TLV_ERR_NULL_ARG;
    if (!size) return TLV_ERR_END_OF_BUFFER;
    remaining = size;
    rc = format->read_tag(format->context, data, remaining, &entry.tag, &tag_size);
    if (rc != TLV_OK) return rc;
    if (!tag_size || tag_size > remaining || !entry.tag.size ||
        entry.tag.size > TLV_TAG_MAX_SIZE) return TLV_ERR_INVALID_TAG;
    remaining -= tag_size;
    if (format->read_value_bounds)
        rc = format->read_value_bounds(format->context, &entry.tag,
            data + tag_size, remaining, &length_size, &entry.value.length, &trailer_size);
    else
        rc = format->read_length(format->context, data + tag_size, remaining,
                                 &entry.value.length, &length_size);
    if (rc != TLV_OK) return rc;
    if (length_size > remaining) return TLV_ERR_INVALID_LENGTH;
    remaining -= length_size;
    if (entry.value.length > remaining) return TLV_ERR_BUFFER_TOO_SHORT;
    remaining -= entry.value.length;
    if (trailer_size > remaining) return TLV_ERR_BUFFER_TOO_SHORT;
    entry.value.data = data + tag_size + length_size;
    *consumed = tag_size + length_size + entry.value.length + trailer_size;
    *out_entry = entry;
    return TLV_OK;
}

tlv_result_t tlv_reader_next(tlv_reader_t* reader, tlv_view_t* out_entry) {
    size_t consumed;
    tlv_result_t rc;
    if (!reader || !out_entry) return TLV_ERR_NULL_ARG;
    if (tlv_reader_at_end(reader)) return TLV_ERR_END_OF_BUFFER;
    if (!reader->data) return TLV_ERR_NULL_ARG;
    rc = tlv_read(reader->data + reader->pos, reader->size - reader->pos,
                  reader->format, out_entry, &consumed);
    if (rc == TLV_OK) reader->pos += consumed;
    return rc;
}
