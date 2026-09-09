#include "tlv/formats/asn1/ber.h"
#include "ber_internal.h"
#include <string.h>
static tlv_result_t read_tag(const void* context, const uint8_t* data, size_t size, tlv_tag_t* tag, size_t* used) {
    /* Universal tag zero is reserved for EOC, never an ordinary element. */
    if (size && (data[0] == 0 || data[0] == 0x20)) return TLV_ERR_INVALID_TAG;
    return tlv_ber_reader_wire.read_tag(context, data, size, tag, used);
}
static tlv_result_t write_tag(const void* context, uint8_t* data, size_t capacity, const tlv_tag_t* tag, size_t* used) {
    if (tag->size && (tag->data[0] == 0 || tag->data[0] == 0x20)) return TLV_ERR_INVALID_TAG;
    return tlv_ber_writer_wire.write_tag(context, data, capacity, tag, used);
}
static tlv_result_t read_length(const void* context, const uint8_t* data, size_t size, size_t* length, size_t* used) {
    return tlv_ber_reader_wire.read_length(context, data, size, length, used);
}
static tlv_result_t write_length(const void* context, uint8_t* data, size_t capacity, size_t length, size_t* used) {
    return tlv_ber_writer_wire.write_length(context, data, capacity, length, used);
}
static tlv_result_t length_size(const void* context, size_t length, size_t* size) {
    return tlv_ber_writer_wire.length_size(context, length, size);
}
int tlv_ber_is_constructed(const void* context, const tlv_tag_t* tag) {
    (void)context;
    return (tag->data[0] & 0x20) != 0;
}

/* Walk only framing, skipping primitive contents in one step. Each frame's
 * end is a hard bound inherited from the closest definite enclosing scope.
 * In particular an EOC outside that bound cannot terminate a nested value.
 */
static tlv_result_t scan_contents(const uint8_t* data, size_t size, int indefinite,
                                  size_t* value_size, size_t* consumed) {
    size_t ends[TLV_BER_MAX_DEPTH];
    int terminated[TLV_BER_MAX_DEPTH];
    size_t depth = 1, pos = 0;
    ends[0] = size;
    terminated[0] = indefinite;
    for (;;) {
        size_t limit = ends[depth - 1], tag_size, length_size, length;
        tlv_tag_t tag;
        tlv_result_t rc;
        int child_indefinite, constructed;
        if (pos == limit) {
            if (terminated[depth - 1]) return TLV_ERR_BUFFER_TOO_SHORT;
            if (--depth == 0) {
                *value_size = pos; *consumed = pos; return TLV_OK;
            }
            continue;
        }
        if (data[pos] == 0) {
            if (limit - pos < 2) return TLV_ERR_BUFFER_TOO_SHORT;
            if (data[pos + 1] != 0) return TLV_ERR_INVALID_LENGTH;
            if (!terminated[depth - 1]) return TLV_ERR_INVALID_TAG;
            if (--depth == 0) {
                *value_size = pos; *consumed = pos + 2; return TLV_OK;
            }
            pos += 2;
            continue;
        }
        rc = read_tag(NULL, data + pos, limit - pos, &tag, &tag_size);
        if (rc != TLV_OK) return rc;
        pos += tag_size;
        if (pos == limit) return TLV_ERR_BUFFER_TOO_SHORT;
        constructed = tlv_ber_is_constructed(NULL, &tag);
        child_indefinite = data[pos] == 0x80;
        if (child_indefinite) {
            if (!constructed) return TLV_ERR_INVALID_LENGTH;
            ++pos;
            length = limit - pos;
        } else {
            rc = read_length(NULL, data + pos, limit - pos, &length, &length_size);
            if (rc != TLV_OK) return rc;
            pos += length_size;
            if (length > limit - pos) return TLV_ERR_BUFFER_TOO_SHORT;
        }
        if (constructed) {
            if (depth == TLV_BER_MAX_DEPTH) return TLV_ERR_LIMIT;
            ends[depth] = pos + length;
            terminated[depth++] = child_indefinite;
        } else pos += length;
    }
}

static tlv_result_t read_value_bounds(const void* context, const tlv_tag_t* tag,
    const uint8_t* data, size_t size, size_t* length_size,
    size_t* value_size, size_t* trailer_size) {
    size_t length, used;
    tlv_result_t rc;
    if (!size) return TLV_ERR_BUFFER_TOO_SHORT;
    if (data[0] != 0x80) {
        rc = read_length(context, data, size, &length, &used);
        if (rc != TLV_OK) return rc;
        if (length > size - used) return TLV_ERR_BUFFER_TOO_SHORT;
        *length_size = used; *value_size = length; *trailer_size = 0;
        return TLV_OK;
    }
    if (!tlv_ber_is_constructed(context, tag)) return TLV_ERR_INVALID_LENGTH;
    rc = scan_contents(data + 1, size - 1, 1, &length, &used);
    if (rc != TLV_OK) return rc;
    *length_size = 1; *value_size = length; *trailer_size = 2;
    return TLV_OK;
}

const tlv_reader_format_t tlv_reader_format_ber = {
    .context = NULL,
    .read_tag = read_tag,
    .read_length = read_length,
    .read_value_bounds = read_value_bounds
};

tlv_result_t tlv_ber_indefinite_encoded_size(tlv_tag_t tag, size_t length, size_t* size) {
    size_t tag_size;
    tlv_result_t rc;
    if (!size) return TLV_ERR_NULL_ARG;
    rc = write_tag(NULL, NULL, 0, &tag, &tag_size);
    if (rc != TLV_OK) return rc;
    if (!tlv_ber_is_constructed(NULL, &tag)) return TLV_ERR_INVALID_LENGTH;
    if (length > SIZE_MAX - tag_size - 3) return TLV_ERR_INVALID_LENGTH;
    *size = tag_size + 1 + length + 2;
    return TLV_OK;
}

tlv_result_t tlv_ber_write_indefinite(uint8_t* data, size_t capacity,
    tlv_tag_t tag, const uint8_t* value, size_t length, size_t* written) {
    size_t total, checked_length, used;
    tlv_result_t rc;
    if ((!data && capacity) || (!value && length) || !written) return TLV_ERR_NULL_ARG;
    rc = tlv_ber_indefinite_encoded_size(tag, length, &total);
    if (rc != TLV_OK) return rc;
    if (capacity < total) return TLV_ERR_BUFFER_TOO_SHORT;
    rc = scan_contents(value, length, 0, &checked_length, &used);
    if (rc != TLV_OK) return rc;
    memcpy(data, tag.data, tag.size);
    data[tag.size] = 0x80;
    if (length) memcpy(data + tag.size + 1, value, length);
    data[total - 2] = 0; data[total - 1] = 0;
    *written = total;
    return TLV_OK;
}

tlv_result_t tlv_ber_writer_write_indefinite(tlv_writer_t* writer,
    tlv_tag_t tag, const uint8_t* value, size_t length) {
    size_t written;
    tlv_result_t rc;
    if (!writer) return TLV_ERR_NULL_ARG;
    if (writer->format != &tlv_writer_format_ber) return TLV_ERR_INVALID_ARG;
    if (writer->pos > writer->capacity) return TLV_ERR_BUFFER_TOO_SHORT;
    rc = tlv_ber_write_indefinite(writer->buf ? writer->buf + writer->pos : NULL,
        writer->capacity - writer->pos, tag, value, length, &written);
    if (rc == TLV_OK) writer->pos += written;
    return rc;
}

const tlv_writer_format_t tlv_writer_format_ber = {
    .context = NULL,
    .write_tag = write_tag,
    .write_length = write_length,
    .length_size = length_size
};
