#ifndef OPENTLV_READER_H
#define OPENTLV_READER_H

#include "tlv/tlv.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Parses one element from the beginning of data; trailing bytes are ignored.
 * Requires format->read_tag/read_length and non-NULL output pointers.
 * data may be NULL only when size is zero (TLV_ERR_END_OF_BUFFER).
 * On success, out_entry borrows the input value and consumed receives the
 * complete encoded size (tag + length + value). Keep the input alive while
 * using the view. No allocation, value copying, or schema validation occurs.
 * On failure, both outputs remain unchanged; callback errors propagate.
 */
tlv_result_t tlv_read(const uint8_t* data, size_t size,
                      const tlv_format_t* format, tlv_view_t* out_entry,
                      size_t* consumed);

typedef struct tlv_reader {
    const tlv_format_t* format; /* borrowed */
    const uint8_t* data;
    size_t         size;
    size_t         pos;
} tlv_reader_t;

/* Uses a caller-provided format; NULL or missing required callbacks is an error. */
tlv_result_t tlv_reader_init(tlv_reader_t* reader, const uint8_t* data,
                                        size_t size, const tlv_format_t* format);

/* Returns 1 if there are no further TLV items, otherwise 0. */
int tlv_reader_at_end(const tlv_reader_t* reader);

/*
 * Reads the next TLV item. On success sets *out_entry and advances the position.
 * On error both remain unchanged.
 * Copies the decoded tag into the view. The value points directly into
 * the original buffer (zero-copy); the caller must keep that buffer alive.
 */
tlv_result_t tlv_reader_next(tlv_reader_t* reader, tlv_view_t* out_entry);

#ifdef __cplusplus
}
#endif

#endif /* OPENTLV_READER_H */
