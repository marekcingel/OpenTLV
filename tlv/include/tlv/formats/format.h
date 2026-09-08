#ifndef OPENTLV_FORMAT_H
#define OPENTLV_FORMAT_H

#include "tlv/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Stateless operations with optional borrowed, immutable configuration.
 * The descriptor and context must outlive readers/writers using them.
 * Callbacks must not allocate, retain buffers, or access beyond size/capacity.
 * On success, read callbacks report consumed bytes (at least one for tags)
 * and initialize their output. Tags must fit TLV_TAG_MAX_SIZE.
 * write_tag(context, NULL, 0, tag, &size) validates the tag and reports its encoded size;
 * this query must not write. Actual writes report the same size as the query.
 * length_size validates the length and reports the exact write_length size.
 * All sizes are in bytes. Callback errors propagate unchanged.
 */
typedef struct tlv_format {
    const void* context;
    tlv_result_t (*read_tag)(const void* context, const uint8_t* data,
                             size_t size, tlv_tag_t* tag, size_t* consumed);
    tlv_result_t (*write_tag)(const void* context, uint8_t* data,
                              size_t capacity, const tlv_tag_t* tag, size_t* written);
    tlv_result_t (*read_length)(const void* context, const uint8_t* data,
                                size_t size, size_t* length, size_t* consumed);
    tlv_result_t (*write_length)(const void* context, uint8_t* data,
                                 size_t capacity, size_t length, size_t* written);
    tlv_result_t (*length_size)(const void* context, size_t length, size_t* size);
    /* Optional nesting rule. NULL means all values are opaque. A nonzero
     * result identifies a value containing a sequence in this same format.
     * Called only with a successfully parsed tag. No value decoding occurs.
     * This contract currently supports definite-length containers only. */
    int (*is_constructed)(const void* context, const tlv_tag_t* tag);
} tlv_format_t;

#ifdef __cplusplus
}
#endif

#endif /* OPENTLV_FORMAT_H */
