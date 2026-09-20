#include "tlv/writer/writer.h"
#include "tlv/length.h"
#include "../formats/format_internal.h"
#include <string.h>

tlv_result_t tlv_writer_init(tlv_writer_t* writer, uint8_t* buf, size_t capacity,
                             const tlv_writer_format_t* format) {
    if (!writer || (!buf && capacity) || !tlv_writer_format_usable(format)) return TLV_ERR_NULL_ARG;
    writer->buf = buf;
    writer->capacity = capacity;
    writer->pos = 0;
    writer->format = format;
    return TLV_OK;
}

static tlv_result_t encoded_sizes(tlv_tag_t tag, size_t length, const tlv_writer_format_t* format,
                                  size_t* tag_size, size_t* length_size, size_t* total) {
    tlv_result_t rc;
    if (!tlv_writer_format_usable(format)) return TLV_ERR_NULL_ARG;
    if (!tag.size || tag.size > TLV_TAG_CAPACITY) return TLV_ERR_INVALID_TAG_SIZE;
    if (format->write_header) {
        /* The header is everything before the value, whatever order its fields use. */
        *tag_size = 0;
        rc = format->write_header(format->context, NULL, 0, &tag, length, length_size);
        if (rc != TLV_OK) return rc;
        if (!*length_size) return TLV_ERR_INVALID_LENGTH;
        if (length > SIZE_MAX - *length_size) return TLV_ERR_INVALID_LENGTH;
        *total = *length_size + length;
        return TLV_OK;
    }
    rc = format->write_tag(format->context, NULL, 0, &tag, tag_size);
    if (rc != TLV_OK) return rc;
    if (!*tag_size) return TLV_ERR_INVALID_TAG;
    rc = format->length_size(format->context, length, length_size);
    if (rc != TLV_OK) return rc;
    if (*length_size > SIZE_MAX - *tag_size || length > SIZE_MAX - *tag_size - *length_size)
        return TLV_ERR_INVALID_LENGTH;
    *total = *tag_size + *length_size + length;
    return TLV_OK;
}

tlv_result_t tlv_encoded_size(tlv_tag_t tag, size_t length, const tlv_writer_format_t* format,
                              size_t* size) {
    size_t tag_size = 0, length_size = 0, total = 0;
    tlv_result_t rc;
    if (!size) return TLV_ERR_NULL_ARG;
    rc = encoded_sizes(tag, length, format, &tag_size, &length_size, &total);
    if (rc == TLV_OK) *size = total;
    return rc;
}

tlv_result_t tlv_write(uint8_t* data, size_t capacity, const tlv_writer_format_t* format,
                       tlv_tag_t tag, const uint8_t* value, size_t length, size_t* out_written) {
    size_t tag_size = 0, length_size = 0, total = 0, written = 0;
    tlv_result_t rc;
    if ((!data && capacity) || (!value && length) || !out_written) return TLV_ERR_NULL_ARG;
    rc = encoded_sizes(tag, length, format, &tag_size, &length_size, &total);
    if (rc != TLV_OK) return rc;
    if (capacity < total) {
        *out_written = total;
        return TLV_ERR_BUFFER_TOO_SHORT;
    }
    if (format->write_header) {
        rc = format->write_header(format->context, data, length_size, &tag, length, &written);
        if (rc != TLV_OK) return rc;
        if (written != length_size) return TLV_ERR_INVALID_LENGTH;
    } else {
        rc = format->write_tag(format->context, data, tag_size, &tag, &written);
        if (rc != TLV_OK) return rc;
        if (written != tag_size) return TLV_ERR_INVALID_TAG;
        written = 0;
        rc = format->write_length(format->context, data + tag_size, length_size, length, &written);
        if (rc != TLV_OK) return rc;
        if (written != length_size) return TLV_ERR_INVALID_LENGTH;
    }
    // data is non-NULL here: tag_size is always > 0 for a valid tag (checked in
    // encoded_sizes()), so total >= 1, and the earlier "capacity < total" check forces
    // capacity > 0, ruling out data == NULL (guarded at function entry). The analyzer can't
    // fold this across the format->write_tag() indirect call. Which specific analyzer check
    // fires here (unix.cstring.NullArg vs. core.NonNullParamChecker, depending on whether the
    // platform's <string.h> declares memcpy's parameters nonnull) varies by libc/clang-tidy
    // version, so this is left unnamed rather than pinned to one that may not match in CI.
    // NOLINTNEXTLINE
    if (length) memcpy(data + tag_size + length_size, value, length);
    *out_written = total;
    return TLV_OK;
}

tlv_result_t tlv_writer_write(tlv_writer_t* writer, tlv_tag_t tag, const uint8_t* value,
                              size_t length) {
    size_t written;
    tlv_result_t rc;
    if (!writer) return TLV_ERR_NULL_ARG;
    if (writer->pos > writer->capacity) return TLV_ERR_BUFFER_TOO_SHORT;
    rc = tlv_write(writer->buf ? writer->buf + writer->pos : NULL, writer->capacity - writer->pos,
                   writer->format, tag, value, length, &written);
    if (rc == TLV_OK) writer->pos += written;
    return rc;
}

tlv_result_t tlv_writer_copy_view(tlv_writer_t* writer, const tlv_view_t* view) {
    size_t length = 0, written = 0;
    tlv_result_t rc;
    if (!writer) return TLV_ERR_NULL_ARG;
    if (writer->pos > writer->capacity) return TLV_ERR_BUFFER_TOO_SHORT;
    if (!view || (!view->value.data && view->value.length)) return TLV_ERR_NULL_ARG;
    rc = tlv_length_to_size(view->value.length, &length);
    if (rc != TLV_OK) return rc;
    rc = tlv_write(writer->buf ? writer->buf + writer->pos : NULL, writer->capacity - writer->pos,
                   writer->format, view->tag, view->value.data, length, &written);
    if (rc == TLV_OK) writer->pos += written;
    return rc;
}

tlv_result_t tlv_writer_copy_encoded(tlv_writer_t* writer, const uint8_t* encoded_data,
                                     size_t encoded_length) {
    uint8_t* dest;
    if (!writer) return TLV_ERR_NULL_ARG;
    if (writer->pos > writer->capacity) return TLV_ERR_BUFFER_TOO_SHORT;
    if (!encoded_data && encoded_length) return TLV_ERR_NULL_ARG;
    if (writer->capacity - writer->pos < encoded_length) return TLV_ERR_BUFFER_TOO_SHORT;
    dest = writer->buf ? writer->buf + writer->pos : NULL;
    if (encoded_length) {
        if (!dest) return TLV_ERR_BUFFER_TOO_SHORT;
        memmove(dest, encoded_data, encoded_length);
    }
    writer->pos += encoded_length;
    return TLV_OK;
}

size_t tlv_writer_size(const tlv_writer_t* writer) {
    return writer ? writer->pos : 0;
}
