#ifndef OPENTLV_WRITER_H
#define OPENTLV_WRITER_H

#include "tlv/tlv.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tlv_writer {
    uint8_t* buf;      /* buffer provided by the caller (no allocation in the core) */
    size_t   capacity;
    size_t   pos;       /* bytes currently written */
} tlv_writer_t;

/* Initializes a writer over an external buffer with the given capacity. */
tlv_result_t tlv_writer_init(tlv_writer_t* writer, uint8_t* buf, size_t capacity);

/* Writes one TLV item (tag + BER length + value). */
tlv_result_t tlv_writer_write(tlv_writer_t* writer, tlv_tag_t tag,
                               const uint8_t* value, size_t length);

/* Number of bytes currently written to the buffer. */
size_t tlv_writer_size(const tlv_writer_t* writer);

#ifdef __cplusplus
}
#endif

#endif /* OPENTLV_WRITER_H */
