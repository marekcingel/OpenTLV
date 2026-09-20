#ifndef OPENTLV_ENDIAN_H
#define OPENTLV_ENDIAN_H

#include "tlv/export.h"
#include "tlv/error.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup core
 * @brief Byte-order helpers for reading and writing fixed-width unsigned integers.
 */

/** @addtogroup core
 * @{
 */

/** @brief Byte order of a multi-byte integer. */
typedef enum tlv_byte_order {
    /** Unknown or unsupported byte order; rejected by every function taking an order. */
    TLV_BYTE_ORDER_UNKNOWN = 0,
    /** Big-endian: most significant byte first. */
    TLV_BYTE_ORDER_BIG_ENDIAN,
    /** Little-endian: least significant byte first. */
    TLV_BYTE_ORDER_LITTLE_ENDIAN
} tlv_byte_order_t;

/**
 * @brief Returns the native `uint32_t` byte order of the executing platform.
 *
 * @return The native byte order, or #TLV_BYTE_ORDER_UNKNOWN for an
 *         unsupported mixed byte order.
 *
 * @note This describes the executing platform, not the format of incoming data.
 */
TLV_API tlv_byte_order_t tlv_endian_native(void);

/**
 * @brief Reads a 16-bit unsigned integer from raw bytes, big-endian.
 *
 * Converts raw value bytes independently of host byte order and TLV profile.
 * No bounds checks are performed and no alignment is required; only the
 * specified bytes are read. Every value of the declared integer type fits, so
 * no overflow is possible.
 *
 * @param[in] data Source bytes; must be non-`NULL` and provide at least as many
 *                 readable bytes as the integer's width (2 for u16, 4 for u32, 8 for u64).
 *
 * @return The decoded value.
 *
 * @warning Passing `NULL` or a shorter buffer is undefined behavior.
 */
TLV_API uint16_t tlv_read_u16_be(const uint8_t* data);
/** @brief Reads a 16-bit unsigned integer from raw bytes, little-endian.
 *  @copydetails tlv_read_u16_be */
TLV_API uint16_t tlv_read_u16_le(const uint8_t* data);
/** @brief Reads a 32-bit unsigned integer from raw bytes, big-endian.
 *  @copydetails tlv_read_u16_be */
TLV_API uint32_t tlv_read_u32_be(const uint8_t* data);
/** @brief Reads a 32-bit unsigned integer from raw bytes, little-endian.
 *  @copydetails tlv_read_u16_be */
TLV_API uint32_t tlv_read_u32_le(const uint8_t* data);
/** @brief Reads a 64-bit unsigned integer from raw bytes, big-endian.
 *  @copydetails tlv_read_u16_be */
TLV_API uint64_t tlv_read_u64_be(const uint8_t* data);
/** @brief Reads a 64-bit unsigned integer from raw bytes, little-endian.
 *  @copydetails tlv_read_u16_be */
TLV_API uint64_t tlv_read_u64_le(const uint8_t* data);

/**
 * @brief Writes a 16-bit unsigned integer to raw bytes, big-endian.
 *
 * Converts independently of host byte order and TLV profile. No bounds checks
 * are performed and no alignment is required; only the specified bytes are
 * written.
 *
 * @param[out] data  Destination; must be non-`NULL` and provide at least as many
 *                   writable bytes as the integer's width (2 for u16, 4 for u32, 8 for u64).
 * @param[in]  value Value to write.
 *
 * @warning Passing `NULL` or a shorter buffer is undefined behavior.
 */
TLV_API void tlv_write_u16_be(uint8_t* data, uint16_t value);
/** @brief Writes a 16-bit unsigned integer to raw bytes, little-endian.
 *  @copydetails tlv_write_u16_be */
TLV_API void tlv_write_u16_le(uint8_t* data, uint16_t value);
/** @brief Writes a 32-bit unsigned integer to raw bytes, big-endian.
 *  @copydetails tlv_write_u16_be */
TLV_API void tlv_write_u32_be(uint8_t* data, uint32_t value);
/** @brief Writes a 32-bit unsigned integer to raw bytes, little-endian.
 *  @copydetails tlv_write_u16_be */
TLV_API void tlv_write_u32_le(uint8_t* data, uint32_t value);

/** @brief Writes a 64-bit unsigned integer to raw bytes, big-endian.
 *  @copydetails tlv_write_u16_be */
TLV_API void tlv_write_u64_be(uint8_t* data, uint64_t value);
/** @brief Writes a 64-bit unsigned integer to raw bytes, little-endian.
 *  @copydetails tlv_write_u16_be */
TLV_API void tlv_write_u64_le(uint8_t* data, uint64_t value);

/**
 * @brief Reads an unsigned integer of 1..8 bytes with an explicit byte order.
 *
 * Accepts zero padding. The read finishes before `*value` is stored. There is
 * no allocation, implicit native byte order, or protocol validation. Byte
 * buffers need no alignment.
 *
 * Validation order: required `NULL` pointers, then the width, then the byte
 * order.
 *
 * @param[in]  data  Source bytes; `width` readable bytes. Allocation bounds
 *                   are not checked.
 * @param[in]  width Number of bytes, 1..8.
 * @param[in]  order Byte order of the bytes.
 * @param[out] value Receives the value; must point to a writable `uint64_t`.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG if a required pointer is `NULL`.
 * @return #TLV_ERR_INVALID_LENGTH if `width` is unsupported.
 * @return #TLV_ERR_INVALID_BYTE_ORDER if `order` is unknown or unsupported.
 *
 * @note On failure `*value` is unchanged.
 */
TLV_API tlv_result_t tlv_read_uint(const uint8_t* data, size_t width, tlv_byte_order_t order,
                                   uint64_t* value);

/**
 * @brief Writes an unsigned integer as 1..8 bytes with an explicit byte order.
 *
 * Zero-pads to `width` and never truncates. Byte buffers need no alignment.
 * There is no allocation, implicit native byte order, or protocol
 * validation. Validation order: required `NULL` pointers, then the width,
 * then the byte order, then whether the value fits.
 *
 * @param[out] data  Destination; `width` writable bytes. Allocation bounds
 *                   are not checked.
 * @param[in]  width Number of bytes, 1..8.
 * @param[in]  order Byte order to write.
 * @param[in]  value Value to write.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG if `data` is `NULL`.
 * @return #TLV_ERR_INVALID_LENGTH if `width` is unsupported.
 * @return #TLV_ERR_INVALID_BYTE_ORDER if `order` is unknown or unsupported.
 * @return #TLV_ERR_OVERFLOW if `value` does not fit in `width` bytes.
 *
 * @note On failure the destination is unchanged.
 */
TLV_API tlv_result_t tlv_write_uint(uint8_t* data, size_t width, tlv_byte_order_t order,
                                    uint64_t value);

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* OPENTLV_ENDIAN_H */
