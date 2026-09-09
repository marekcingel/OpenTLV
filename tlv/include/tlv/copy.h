#ifndef OPENTLV_COPY_H
#define OPENTLV_COPY_H

#include "tlv/types.h"
#include "tlv/formats/format.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Explicit copies into caller-owned storage; no allocation or ownership
 * transfer. With data == NULL and capacity == 0, report the required size
 * without copying. Otherwise report bytes written on success. written is
 * required and must not alias source or destination storage. Source descriptors
 * must not overlap destination storage. On failure written is unchanged.
 * Insufficient capacity returns BUFFER_TOO_SHORT without modifying data.
 * NULL data with nonzero capacity or NULL source bytes with nonzero length
 * returns NULL_ARG. Empty byte ranges may have NULL source bytes.
 */

/* Copies only the value, without interpreting or validating the tag.
 * Overlapping source and destination byte ranges are supported.
 */
tlv_result_t tlv_copy_value(const tlv_view_t* view, uint8_t* data,
                            size_t capacity, size_t* written);

/* Copies an exact encoded byte range, preserving the original wire bytes.
 * The caller identifies the range (e.g. input + offset and consumed from
 * tlv_read/tlv_scan). No framing validation is performed. Overlap is supported.
 */
tlv_result_t tlv_copy_encoded(tlv_buffer_t encoded, uint8_t* data,
                              size_t capacity, size_t* written);

/* Serializes tag, length and value using format, as tlv_write does.
 * A view does not retain the original header: use tlv_copy_encoded to preserve
 * it exactly. Requires format write_tag/write_length/length_size callbacks.
 * Source value bytes must not overlap the destination element. Callback errors
 * propagate unchanged and may modify data; size queries do not write data.
 */
tlv_result_t tlv_copy_view(const tlv_view_t* view, const tlv_writer_format_t* format,
                           uint8_t* data, size_t capacity, size_t* written);

#ifdef __cplusplus
}
#endif

#endif /* OPENTLV_COPY_H */
