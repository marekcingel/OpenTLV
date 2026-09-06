#ifndef OPENTLV_ENDIAN_H
#define OPENTLV_ENDIAN_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Convert raw value bytes independently of host byte order and TLV profile.
 * be means big-endian (most significant byte first); le means little-endian.
 * Pointers must be non-NULL and provide at least 2 bytes for u16 or 4 for u32,
 * readable for reads and writable for writes. No bounds checks are performed.
 * No alignment is required. Only the specified bytes are read or written.
 */
uint16_t tlv_read_u16_be(const uint8_t* data);
uint16_t tlv_read_u16_le(const uint8_t* data);
uint32_t tlv_read_u32_be(const uint8_t* data);
uint32_t tlv_read_u32_le(const uint8_t* data);

void tlv_write_u16_be(uint8_t* data, uint16_t value);
void tlv_write_u16_le(uint8_t* data, uint16_t value);
void tlv_write_u32_be(uint8_t* data, uint32_t value);
void tlv_write_u32_le(uint8_t* data, uint32_t value);

#ifdef __cplusplus
}
#endif

#endif /* OPENTLV_ENDIAN_H */
