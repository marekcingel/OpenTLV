#ifndef OPENTLV_TLV_H
#define OPENTLV_TLV_H

#include <stddef.h>
#include <stdint.h>
#include "tlv/error.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Format: 1B tag, BER-style length.
 *   length 0-127:     directly in one byte
 *   length 128-255:   0x81 followed by one length byte
 *   length 256-65535: 0x82 followed by two length bytes (big-endian)
 * (the long form can be extended to more bytes later; for now, 65535 is enough)
 */

typedef uint8_t tlv_tag_t;

typedef struct tlv_entry {
    tlv_tag_t      tag;
    const uint8_t* value;
    size_t         length;
} tlv_entry_t;

#ifdef __cplusplus
}
#endif

#endif /* OPENTLV_TLV_H */
