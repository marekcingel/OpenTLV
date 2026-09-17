#ifndef OPENTLV_WRITER_H
#define OPENTLV_WRITER_H

#include "tlv/formats/format.h"
#include "tlv/export.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Computes tag + length + value size without accessing value bytes.
 * Requires format->write_tag/write_length/length_size and a non-NULL output.
 * Empty tags or unsupported tag sizes return TLV_ERR_INVALID_TAG_SIZE.
 * On failure the output is unchanged; size_t overflow is INVALID_LENGTH.
 */
TLV_API tlv_result_t tlv_encoded_size(tlv_tag_t tag, size_t length,
                                      const tlv_writer_format_t* format, size_t* size);

/* Encodes one element directly into caller-owned memory, without allocation
 * or value interpretation. Value must not overlap the destination element.
 * value may be NULL only for an empty value; data may be NULL only if capacity
 * is zero. written is required. Capacity is checked before writing, against
 * the complete required encoded size (tag + length + value), computed the
 * same way as tlv_encoded_size for the same tag, length, and format.
 * On success written receives that size and data holds the encoded element.
 * On insufficient capacity, written also receives that same required size
 * (matching tlv_encoded_size), data is left unchanged, and the result is
 * TLV_ERR_BUFFER_TOO_SHORT. Every other failure, including a callback
 * returning TLV_ERR_BUFFER_TOO_SHORT, leaves written unchanged; such
 * callback errors may still modify data. Callback errors otherwise
 * propagate unchanged. Requires the same callbacks as sizing.
 */
TLV_API tlv_result_t tlv_write(uint8_t* data, size_t capacity, const tlv_writer_format_t* format,
                               tlv_tag_t tag, const uint8_t* value, size_t length, size_t* written);

typedef struct tlv_writer {
    const tlv_writer_format_t* format; /* borrowed */
    uint8_t* buf; /* buffer provided by the caller (no allocation in the core) */
    size_t capacity;
    size_t pos; /* bytes currently written */
} tlv_writer_t;

/* Uses a caller-provided format; NULL or missing required callbacks is an error. */
TLV_API tlv_result_t tlv_writer_init(tlv_writer_t* writer, uint8_t* buf, size_t capacity,
                                     const tlv_writer_format_t* format);

/* Writes one TLV item using the selected format.
 * On error the position is unchanged; callbacks may have modified buffer bytes.
 * Does not expose the required size on insufficient capacity; use tlv_write
 * or tlv_encoded_size directly for that feedback.
 */
TLV_API tlv_result_t tlv_writer_write(tlv_writer_t* writer, tlv_tag_t tag, const uint8_t* value,
                                      size_t length);

/* Appends a view at the writer's current position, serialized with
 * writer->format, following the same argument, overlap, and callback-error
 * contracts as tlv_copy_view. Unlike tlv_copy_view, a NULL writer buffer with
 * zero remaining capacity is treated as a real, possibly insufficient,
 * destination rather than a size query: writing a nonzero-size element then
 * returns TLV_ERR_BUFFER_TOO_SHORT, while copying an empty value may succeed.
 * pos advances by the encoded size only on success; on any failure, including
 * insufficient capacity, pos is unchanged and the required size is not
 * exposed (use tlv_encoded_size for that). NULL writer returns
 * TLV_ERR_NULL_ARG; pos > capacity returns TLV_ERR_BUFFER_TOO_SHORT.
 */
TLV_API tlv_result_t tlv_writer_copy_view(tlv_writer_t* writer, const tlv_view_t* view);

/* Appends an exact encoded byte range at the writer's current position,
 * without framing validation or format conversion, preserving the original
 * wire bytes as tlv_copy_encoded does. Overlapping byte ranges are supported.
 * As with tlv_writer_copy_view, a NULL writer buffer with zero remaining
 * capacity is a real destination, not a size query: copying a nonzero-length
 * range then returns TLV_ERR_BUFFER_TOO_SHORT, while copying an empty range
 * may succeed without advancing pos. pos advances by encoded_length only on
 * success; on failure pos is unchanged. NULL writer returns TLV_ERR_NULL_ARG;
 * pos > capacity returns TLV_ERR_BUFFER_TOO_SHORT.
 */
TLV_API tlv_result_t tlv_writer_copy_encoded(tlv_writer_t* writer, const uint8_t* encoded_data,
                                             size_t encoded_length);

/* Number of bytes currently written to the buffer. */
TLV_API size_t tlv_writer_size(const tlv_writer_t* writer);

#ifdef __cplusplus
}
#endif

#endif /* OPENTLV_WRITER_H */
