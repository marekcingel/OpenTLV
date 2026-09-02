#ifndef OPENTLV_TLV_H
#define OPENTLV_TLV_H

#include "tlv/error.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Currently supported wire format:
 *   - tag: exactly one byte
 *   - BER-style length:
 *       0-127:     encoded directly in one byte
 *       128-255:   0x81 followed by one length byte
 *       256-65535: 0x82 followed by two length bytes (big-endian)
 *
 * tlv_entry_t exposes the tag as a byte span so a future implementation can
 * support multi-byte tags without changing its public representation.
 */

typedef uint8_t tlv_tag_t;

typedef struct {
  const uint8_t *data;
  size_t length;
} tlv_bytes_t;

typedef struct {
  tlv_bytes_t tag;
  tlv_bytes_t value;
} tlv_entry_t;

#ifdef __cplusplus
}
#endif

#endif /* OPENTLV_TLV_H */
