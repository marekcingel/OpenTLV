#ifndef OPENTLV_WRITER_H
#define OPENTLV_WRITER_H

#include "tlv/formats/format.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Computes tag + length + value size without accessing value bytes.
 * Requires format->write_tag/write_length/length_size and a non-NULL output.
 * On failure the output is unchanged; size_t overflow is INVALID_LENGTH.
 */
tlv_result_t tlv_encoded_size(tlv_tag_t tag, size_t length,
                              const tlv_format_t* format, size_t* size);

/* Encodes one element directly into caller-owned memory, without allocation
 * or value interpretation. Value must not overlap the destination element.
 * value may be NULL only for an empty value; data may be NULL only if capacity
 * is zero. written is required and receives the complete encoded size.
 * Capacity is checked before writing; insufficient capacity leaves data intact.
 * On failure written is unchanged; encoding callback errors may modify data.
 * Callback errors propagate unchanged. Requires the same callbacks as sizing.
 */
tlv_result_t tlv_write(uint8_t* data, size_t capacity, const tlv_format_t* format,
                       tlv_tag_t tag, const uint8_t* value, size_t length,
                       size_t* written);

typedef struct tlv_writer {
    const tlv_format_t* format; /* borrowed */
    uint8_t* buf;      /* buffer provided by the caller (no allocation in the core) */
    size_t   capacity;
    size_t   pos;       /* bytes currently written */
} tlv_writer_t;

/* Uses a caller-provided format; NULL or missing required callbacks is an error. */
tlv_result_t tlv_writer_init(tlv_writer_t* writer, uint8_t* buf,
                                        size_t capacity, const tlv_format_t* format);

/* Writes one TLV item using the selected format.
 * On error the position is unchanged; callbacks may have modified buffer bytes.
 */
tlv_result_t tlv_writer_write(tlv_writer_t* writer, tlv_tag_t tag,
                               const uint8_t* value, size_t length);

/* Number of bytes currently written to the buffer. */
size_t tlv_writer_size(const tlv_writer_t* writer);

#ifdef __cplusplus
}
#endif

#endif /* OPENTLV_WRITER_H */
