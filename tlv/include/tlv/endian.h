#ifndef OPENTLV_ENDIAN_H
#define OPENTLV_ENDIAN_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum tlv_byte_order {
    TLV_BYTE_ORDER_UNKNOWN = 0,
    TLV_BYTE_ORDER_BIG_ENDIAN,
    TLV_BYTE_ORDER_LITTLE_ENDIAN
} tlv_byte_order_t;

/* Native uint32_t byte order; UNKNOWN for an unsupported mixed byte order.
 * Describes the executing platform, not the format of incoming data. */
tlv_byte_order_t tlv_endian_native(void);

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
