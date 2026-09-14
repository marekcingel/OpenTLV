#ifndef OPENTLV_ENDIAN_H
#define OPENTLV_ENDIAN_H

#include <stddef.h>
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
 * Pointers must be non-NULL and provide at least 2 bytes for u16, 4 for u32,
 * or 8 for u64,
 * readable for reads and writable for writes. No bounds checks are performed.
 * No alignment is required. Only the specified bytes are read or written.
 * Every value of the declared integer type fits; no overflow is possible.
 */
uint16_t tlv_read_u16_be(const uint8_t* data);
uint16_t tlv_read_u16_le(const uint8_t* data);
uint32_t tlv_read_u32_be(const uint8_t* data);
uint32_t tlv_read_u32_le(const uint8_t* data);
uint64_t tlv_read_u64_be(const uint8_t* data);
uint64_t tlv_read_u64_le(const uint8_t* data);

void tlv_write_u16_be(uint8_t* data, uint16_t value);
void tlv_write_u16_le(uint8_t* data, uint16_t value);
void tlv_write_u32_be(uint8_t* data, uint32_t value);
void tlv_write_u32_le(uint8_t* data, uint32_t value);

void tlv_write_u64_be(uint8_t* data, uint64_t value);
void tlv_write_u64_le(uint8_t* data, uint64_t value);

/* Checked unsigned serialization: return 1 on success, 0 on failure.
 * Width must be 1..8; order must be BIG_ENDIAN or LITTLE_ENDIAN.
 * NULL pointers, invalid width/order, and write overflow are rejected without
 * modifying any output. Reads accept zero padding; writes zero-pad to width
 * and reject values that do not fit (never truncate).
 * data must provide width readable/writable bytes; allocation bounds are the
 * caller's responsibility. Byte buffers need no alignment. value must point
 * to a writable uint64_t. Reads finish before storing *value.
 * No allocation, host byte-order dependence, or protocol validation.
 */
int tlv_read_uint(const uint8_t* data, size_t width, tlv_byte_order_t order,
                  uint64_t* value);
int tlv_write_uint(uint8_t* data, size_t width, tlv_byte_order_t order,
                   uint64_t value);

#ifdef __cplusplus
}
#endif

#endif /* OPENTLV_ENDIAN_H */
