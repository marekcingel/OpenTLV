#ifndef OPENTLV_TAG_H
#define OPENTLV_TAG_H

#include "tlv/error.h"
#include "tlv/endian.h"
#include "tlv/export.h"
#include <stdint.h>
#include <stddef.h>

/**
 * @file
 * @ingroup core
 * @brief Raw TLV tag type with checked construction, comparison and numeric conversion.
 */

/** @addtogroup core
 * @{
 */

#ifdef TLV_TAG_MAX_SUPPORTED_SIZE
#error "TLV_TAG_MAX_SUPPORTED_SIZE is fixed and must not be configured"
#endif

/**
 * @brief Fixed `uint8_t` representation limit for tag sizes.
 *
 * This is not a configurable or protocol limit; defining it before including
 * this header is a compile-time error.
 */
#define TLV_TAG_MAX_SUPPORTED_SIZE UINT8_MAX

#ifndef TLV_TAG_CAPACITY
/**
 * @brief Inline storage capacity of a #tlv_tag_t, in bytes (default 8).
 *
 * Must be between 1 and #TLV_TAG_MAX_SUPPORTED_SIZE.
 *
 * @warning This affects the layout of #tlv_tag_t and everything containing
 *          it, so it is part of the ABI. Override it consistently when
 *          building the library and every consumer.
 */
#define TLV_TAG_CAPACITY 8
#endif

#if TLV_TAG_CAPACITY < 1 || TLV_TAG_CAPACITY > TLV_TAG_MAX_SUPPORTED_SIZE
#error "TLV_TAG_CAPACITY must be between 1 and TLV_TAG_MAX_SUPPORTED_SIZE (UINT8_MAX)"
#endif

/**
 * @brief A TLV tag stored as raw bytes, independent of host endianness or TLV profile.
 *
 * The tag is a self-contained value with inline storage; it never points to
 * external memory. Empty tags support raw construction and comparison, but
 * operations that require a nonempty tag reject them.
 *
 * @note Assigning `size` directly may truncate before validation; use the
 *       tlv_tag_from_* construction helpers for checked `size_t` lengths.
 */
typedef struct {
    /** Inline storage for up to #TLV_TAG_CAPACITY raw bytes in wire order. */
    uint8_t data[TLV_TAG_CAPACITY];
    /**
     * Number of valid bytes in `data`, `0..TLV_TAG_CAPACITY`.
     *
     * Zero is an empty tag. Whether the bytes form a valid tag is a separate,
     * format- or profile-specific question. `uint8_t` limits the supported
     * capacity to #TLV_TAG_MAX_SUPPORTED_SIZE.
     */
    uint8_t size;
} tlv_tag_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Compares two tags by size and bytes.
 *
 * Compares the full valid range of both tags and ignores unused storage.
 * Two empty tags compare equal.
 *
 * @param[in]  a     First tag.
 * @param[in]  b     Second tag.
 * @param[out] equal Receives 1 if the tags are equal, 0 otherwise. Must point
 *                   to a writable `int`.
 *
 * @return #TLV_OK for a valid comparison.
 * @return #TLV_ERR_NULL_ARG if a required pointer is `NULL`.
 * @return #TLV_ERR_INVALID_TAG_SIZE if either size exceeds #TLV_TAG_CAPACITY.
 *
 * @note On every failure `*equal` is unchanged.
 */
TLV_API tlv_result_t tlv_tag_equal(const tlv_tag_t* a, const tlv_tag_t* b, int* equal);

/**
 * @brief Compares a tag against raw bytes, including length and leading zeros.
 *
 * The same result, output, and capacity rules as tlv_tag_equal() apply.
 *
 * @param[in]  tag   Tag to compare.
 * @param[in]  data  Bytes to compare against; `size` readable bytes. May be
 *                   `NULL` only when `size` is zero.
 * @param[in]  size  Number of bytes in `data`.
 * @param[out] equal Receives 1 if the tag equals the bytes, 0 otherwise.
 *
 * @return #TLV_OK for a valid comparison.
 * @return #TLV_ERR_NULL_ARG if a required pointer is `NULL`.
 * @return #TLV_ERR_INVALID_TAG_SIZE if the tag size exceeds #TLV_TAG_CAPACITY.
 *
 * @note On every failure `*equal` is unchanged.
 * @see tlv_tag_equal
 */
TLV_API tlv_result_t tlv_tag_equal_bytes(const tlv_tag_t* tag, const uint8_t* data, size_t size,
                                         int* equal);

/**
 * @brief Compares a tag numerically against an 8-bit value.
 *
 * Interprets the tag as an unsigned integer as tlv_tag_to_u64() does, with
 * the same input errors, and compares it to `value`. Zero padding at the
 * most significant end does not affect equality. The tag value is never
 * truncated to the argument type.
 *
 * Required pointers are checked before the tag size, then the byte order.
 *
 * @param[in]  tag   Tag to compare.
 * @param[in]  value Value to compare against.
 * @param[in]  order Byte order of the tag bytes.
 * @param[out] equal Receives 1 for equality, 0 for mismatch. Must point to a
 *                   writable `int`.
 *
 * @return #TLV_OK for a valid comparison.
 * @return #TLV_ERR_NULL_ARG if `tag` or `equal` is `NULL`.
 * @return #TLV_ERR_INVALID_TAG_SIZE for an empty tag or one longer than 8 bytes.
 * @return #TLV_ERR_INVALID_BYTE_ORDER if `order` is unknown or invalid.
 *
 * @note On every failure `*equal` is unchanged.
 * @see tlv_tag_to_u64
 */
TLV_API tlv_result_t tlv_tag_equal_u8(const tlv_tag_t* tag, uint8_t value, tlv_byte_order_t order,
                                      int* equal);
/** @brief Compares a tag numerically against a 16-bit value.
 *  @copydetails tlv_tag_equal_u8 */
TLV_API tlv_result_t tlv_tag_equal_u16(const tlv_tag_t* tag, uint16_t value, tlv_byte_order_t order,
                                       int* equal);
/** @brief Compares a tag numerically against a 32-bit value.
 *  @copydetails tlv_tag_equal_u8 */
TLV_API tlv_result_t tlv_tag_equal_u32(const tlv_tag_t* tag, uint32_t value, tlv_byte_order_t order,
                                       int* equal);
/** @brief Compares a tag numerically against a 64-bit value.
 *  @copydetails tlv_tag_equal_u8 */
TLV_API tlv_result_t tlv_tag_equal_u64(const tlv_tag_t* tag, uint64_t value, tlv_byte_order_t order,
                                       int* equal);

/**
 * @brief Converts a tag to an unsigned 8-bit integer.
 *
 * Follows the same input rules as tlv_tag_to_u64(). Zero padding is accepted
 * within the 8-byte input limit. The result must fit the destination type.
 *
 * @param[in]  tag   Tag to convert.
 * @param[in]  order Byte order of the tag bytes.
 * @param[out] value Receives the numeric value.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_OVERFLOW if the value exceeds the destination type's maximum.
 * @return Any error of tlv_tag_to_u64() for invalid arguments.
 *
 * @note `*value` is unchanged on every failure.
 */
TLV_API tlv_result_t tlv_tag_to_u8(const tlv_tag_t* tag, tlv_byte_order_t order, uint8_t* value);
/** @brief Converts a tag to an unsigned 16-bit integer.
 *  @copydetails tlv_tag_to_u8 */
TLV_API tlv_result_t tlv_tag_to_u16(const tlv_tag_t* tag, tlv_byte_order_t order, uint16_t* value);
/** @brief Converts a tag to an unsigned 32-bit integer.
 *  @copydetails tlv_tag_to_u8 */
TLV_API tlv_result_t tlv_tag_to_u32(const tlv_tag_t* tag, tlv_byte_order_t order, uint32_t* value);

/**
 * @brief Converts a tag to an unsigned 64-bit integer.
 *
 * Interprets 1..8 raw bytes using the explicit input byte order, including
 * zero padding at the most significant end. This is not a BER tag-number
 * decode.
 *
 * @param[in]  tag   Tag to convert.
 * @param[in]  order Byte order of the tag bytes.
 * @param[out] value Receives the numeric value.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG if a required pointer is `NULL`.
 * @return #TLV_ERR_INVALID_TAG_SIZE for an empty tag, a size exceeding
 *         #TLV_TAG_CAPACITY, or a size above 8.
 * @return #TLV_ERR_INVALID_BYTE_ORDER if `order` is unknown or invalid.
 *
 * @note `*value` is unchanged on failure.
 */
TLV_API tlv_result_t tlv_tag_to_u64(const tlv_tag_t* tag, tlv_byte_order_t order, uint64_t* value);

/**
 * @brief Constructs a tag from raw bytes.
 *
 * The bytes are copied into the tag; no profile-specific validity is checked.
 * The length is checked before narrowing to `uint8_t`. On success unused
 * tag bytes are zeroed.
 *
 * @param[in]  data Source bytes; `size` readable bytes. May be `NULL` only
 *                  when `size` is zero. May overlap the destination.
 * @param[in]  size Number of bytes, `0..TLV_TAG_CAPACITY`.
 * @param[out] tag  Destination tag.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG if a required pointer is `NULL`.
 * @return #TLV_ERR_INVALID_TAG_SIZE if `size` exceeds #TLV_TAG_CAPACITY.
 *
 * @note On failure the destination is unchanged.
 */
TLV_API tlv_result_t tlv_tag_from_bytes(const uint8_t* data, size_t size, tlv_tag_t* tag);

/**
 * @brief Constructs an explicitly sized raw tag from an 8-bit value.
 *
 * Builds a tag of `size` bytes (1..8, within #TLV_TAG_CAPACITY). Zero padding
 * is written at the most significant end in the selected byte order. The
 * same destination guarantees as tlv_tag_from_bytes() apply.
 *
 * @param[in]  value Numeric tag value.
 * @param[in]  size  Tag size in bytes.
 * @param[in]  order Byte order used to lay out the bytes.
 * @param[out] tag   Destination tag.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG if `tag` is `NULL`.
 * @return #TLV_ERR_INVALID_TAG_SIZE if `size` is invalid.
 * @return #TLV_ERR_OVERFLOW if `value` does not fit in `size` bytes.
 * @return #TLV_ERR_INVALID_BYTE_ORDER if `order` is unsupported.
 *
 * @note On failure the destination is unchanged.
 */
TLV_API tlv_result_t tlv_tag_from_u8(uint8_t value, size_t size, tlv_byte_order_t order,
                                     tlv_tag_t* tag);
/** @brief Constructs an explicitly sized raw tag from a 16-bit value.
 *  @copydetails tlv_tag_from_u8 */
TLV_API tlv_result_t tlv_tag_from_u16(uint16_t value, size_t size, tlv_byte_order_t order,
                                      tlv_tag_t* tag);
/** @brief Constructs an explicitly sized raw tag from a 32-bit value.
 *  @copydetails tlv_tag_from_u8 */
TLV_API tlv_result_t tlv_tag_from_u32(uint32_t value, size_t size, tlv_byte_order_t order,
                                      tlv_tag_t* tag);
/** @brief Constructs an explicitly sized raw tag from a 64-bit value.
 *  @copydetails tlv_tag_from_u8 */
TLV_API tlv_result_t tlv_tag_from_u64(uint64_t value, size_t size, tlv_byte_order_t order,
                                      tlv_tag_t* tag);

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* OPENTLV_TAG_H */
