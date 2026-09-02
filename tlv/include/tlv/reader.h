#ifndef OPENTLV_READER_H
#define OPENTLV_READER_H

#include "tlv/tlv.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tlv_reader {
    const uint8_t* data;
    size_t         size;
    size_t         pos;
} tlv_reader_t;

/* Initializes a reader over an existing buffer (no allocation or copying). */
tlv_result_t tlv_reader_init(tlv_reader_t* reader, const uint8_t* data, size_t size);

/* Returns 1 if there are no further TLV items, otherwise 0. */
int tlv_reader_at_end(const tlv_reader_t* reader);

/*
 * Reads the next TLV item. Sets *out_entry and advances the internal position.
 * The tag and value byte spans point directly into the original buffer
 * (zero-copy).
 */
tlv_result_t tlv_reader_next(tlv_reader_t* reader, tlv_entry_t* out_entry);

#ifdef __cplusplus
}
#endif

#endif /* OPENTLV_READER_H */
