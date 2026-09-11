#ifndef OPENTLV_FORMAT_H
#define OPENTLV_FORMAT_H

#include "tlv/types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef tlv_result_t (*tlv_read_tag_fn)(const void* context, const uint8_t* data,
                                      size_t size, tlv_tag_t* tag, size_t* consumed);
typedef tlv_result_t (*tlv_read_length_fn)(const void* context, const uint8_t* data,
                                         size_t size, size_t* length, size_t* consumed);

/* Optional replacement for read_length during element reading. data starts
 * after the tag. Return the length-field size, borrowed value size, and trailing
 * framing size separately. All three ranges must fit size, in that order.
 * The callback may inspect nested framing to resolve a terminated value.
 * It follows the same allocation and buffer-lifetime rules as read_length.
 */
typedef tlv_result_t (*tlv_read_value_bounds_fn)(const void* context,
    const tlv_tag_t* tag, const uint8_t* data, size_t size,
    size_t* length_size, size_t* value_size, size_t* trailer_size);
typedef tlv_result_t (*tlv_write_tag_fn)(const void* context, uint8_t* data,
                                       size_t capacity, const tlv_tag_t* tag, size_t* written);
typedef tlv_result_t (*tlv_write_length_fn)(const void* context, uint8_t* data,
                                          size_t capacity, size_t length, size_t* written);
typedef tlv_result_t (*tlv_length_size_fn)(const void* context, size_t length, size_t* size);

/* Stateless reading with optional borrowed, immutable configuration.
 * The descriptor and context must outlive readers and operations using them.
 * read_tag and read_length are required; read_value_bounds is optional and
 * replaces read_length in element parsing when non-NULL. Callbacks must not
 * allocate, retain buffers, or access beyond size. On success they initialize
 * their outputs and report
 * consumed bytes (at least one for tags). Tags must fit TLV_TAG_MAX_SIZE.
 * All sizes are in bytes. Callback errors propagate unchanged.
 * Reading borrows input bytes; value decoding and tree visits are separate concerns.
 */
typedef struct tlv_reader_format {
    const void* context;
    tlv_read_tag_fn read_tag;
    tlv_read_length_fn read_length;
    tlv_read_value_bounds_fn read_value_bounds;
} tlv_reader_format_t;

/* Stateless writing with optional borrowed, immutable configuration.
 * The descriptor and context must outlive writers and operations using them.
 * All three callbacks are required. They must not allocate, retain buffers,
 * or access beyond capacity. Tags must fit TLV_TAG_MAX_SIZE.
 * write_tag(context, NULL, 0, tag, &size) validates the tag and reports its
 * encoded size without writing. Actual writes report that same size.
 * length_size validates the length and reports the exact write_length size.
 * Successful write callbacks initialize written. All sizes are in bytes.
 * Callback errors propagate unchanged. Value encoding is a separate concern.
 */
typedef struct tlv_writer_format {
    const void* context;
    tlv_write_tag_fn write_tag;
    tlv_write_length_fn write_length;
    tlv_length_size_fn length_size;
} tlv_writer_format_t;

/* Initializes caller-owned storage without allocation. context is borrowed
 * and may be NULL. Returns TLV_ERR_INVALID_ARG if format or either callback
 * is NULL, leaving the descriptor unchanged. Otherwise sets every field and
 * returns TLV_OK. read_value_bounds is initialized to NULL; callers can assign
 * it after initialization. The descriptor and context follow the reading
 * lifetime and callback contracts above; no input or configuration is copied or retained
 * except the supplied pointers.
 */
tlv_result_t tlv_reader_format_init(tlv_reader_format_t* format, const void* context,
                                     tlv_read_tag_fn read_tag, tlv_read_length_fn read_length);

/* Initializes caller-owned storage without allocation. context is borrowed
 * and may be NULL. Returns TLV_ERR_INVALID_ARG if format or any callback is
 * NULL, leaving the descriptor unchanged. Otherwise sets every field and
 * returns TLV_OK. The descriptor and context follow the writing lifetime and
 * callback contracts above; only the supplied pointers are stored.
 */
tlv_result_t tlv_writer_format_init(tlv_writer_format_t* format, const void* context,
                                     tlv_write_tag_fn write_tag, tlv_write_length_fn write_length,
                                     tlv_length_size_fn length_size);

/* Optional nesting predicate used by tree traversal and structure validation.
 * Called only with successfully parsed tags, using the reader format context.
 * Nonzero means a sequence in the same reader format.
 * NULL at a call site means all values are opaque. No value decoding occurs.
 */
typedef int (*tlv_is_constructed_fn)(const void* context, const tlv_tag_t* tag);

#ifdef __cplusplus
}
#endif

#endif /* OPENTLV_FORMAT_H */
