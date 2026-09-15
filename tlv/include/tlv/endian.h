#ifndef OPENTLV_ENDIAN_H
#define OPENTLV_ENDIAN_H

#include "tlv/export.h"
#include "tlv/error.h"
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
TLV_API tlv_byte_order_t tlv_endian_native(void);

/* Convert raw value bytes independently of host byte order and TLV profile.
 * be means big-endian (most significant byte first); le means little-endian.
 * Pointers must be non-NULL and provide at least 2 bytes for u16, 4 for u32,
 * or 8 for u64,
 * readable for reads and writable for writes. No bounds checks are performed.
 * No alignment is required. Only the specified bytes are read or written.
 * Every value of the declared integer type fits; no overflow is possible.
 */
TLV_API uint16_t tlv_read_u16_be(const uint8_t* data);
TLV_API uint16_t tlv_read_u16_le(const uint8_t* data);
TLV_API uint32_t tlv_read_u32_be(const uint8_t* data);
TLV_API uint32_t tlv_read_u32_le(const uint8_t* data);
TLV_API uint64_t tlv_read_u64_be(const uint8_t* data);
TLV_API uint64_t tlv_read_u64_le(const uint8_t* data);

TLV_API void tlv_write_u16_be(uint8_t* data, uint16_t value);
TLV_API void tlv_write_u16_le(uint8_t* data, uint16_t value);
TLV_API void tlv_write_u32_be(uint8_t* data, uint32_t value);
TLV_API void tlv_write_u32_le(uint8_t* data, uint32_t value);

TLV_API void tlv_write_u64_be(uint8_t* data, uint64_t value);
TLV_API void tlv_write_u64_le(uint8_t* data, uint64_t value);

/* Checked unsigned serialization; width must be 1..8.
 * Return TLV_OK on success. Validation order: required NULL pointers return
 * TLV_ERR_NULL_ARG; unsupported width returns TLV_ERR_INVALID_LENGTH;
 * unknown/unsupported order returns TLV_ERR_INVALID_BYTE_ORDER; write values
 * that do not fit return TLV_ERR_OVERFLOW. Failures leave outputs unchanged.
 * Reads accept zero padding; writes zero-pad to width and never truncate.
 * The caller provides width readable/writable bytes; allocation bounds are
 * not checked. Byte buffers need no alignment. value must point to a writable
 * uint64_t. Reads finish before storing *value. No allocation, implicit native
 * byte order, or protocol validation.
 */
TLV_API tlv_result_t tlv_read_uint(const uint8_t* data, size_t width, tlv_byte_order_t order,
                                   uint64_t* value);
TLV_API tlv_result_t tlv_write_uint(uint8_t* data, size_t width, tlv_byte_order_t order,
                                    uint64_t value);

#ifdef __cplusplus
}
#endif

#endif /* OPENTLV_ENDIAN_H */
