#ifndef OPENTLV_VALUE_H
#define OPENTLV_VALUE_H

#include "tlv/error.h"
#include "tlv/length.h"
#include "tlv/export.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup core
 * @brief Non-owning, read-only TLV value type.
 */

/** @addtogroup core
 * @{
 */

/**
 * @brief Non-owning, read-only view of a TLV value.
 *
 * The caller owns the storage and must keep it alive for as long as the
 * value is used; no allocation, copying, or ownership transfer occurs.
 *
 * @warning `length` may exceed what the current build's `size_t` can
 *          address. Validate it with tlv_length_validate_native() or convert
 *          it with tlv_length_to_size() before pointer arithmetic, memory
 *          access, or narrowing.
 */
typedef struct {
    /** Borrowed value bytes. May be `NULL` only when `length` is zero. */
    const uint8_t* data;
    /** Value length in bytes; may exceed the native `size_t` range. */
    tlv_length_t length;
} tlv_value_t;

/**
 * @brief Initializes a value view into caller-owned storage.
 *
 * The view borrows `data`; nothing is copied and no memory is accessed.
 * Nothing is read from the previous contents of `*value`.
 *
 * @param[in]  data   Value bytes to borrow. May be `NULL` only when `length`
 *                    is zero. Must stay valid while the view is used.
 * @param[in]  length Value length in bytes.
 * @param[out] value  Destination view. Required.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG if `value` is `NULL`, or `data` is `NULL` with a
 *         nonzero `length`; checked before the native-length range.
 * @return #TLV_ERR_INVALID_LENGTH if `length` cannot be represented by the
 *         current build's `size_t`.
 *
 * @note `*value` is unchanged on every failure. Allocation bounds of `data`
 *       remain the caller's responsibility.
 */
TLV_API tlv_result_t tlv_value_init(const uint8_t* data, tlv_length_t length, tlv_value_t* value);

/**
 * @brief Validates a value view's representation and pointer requirements.
 *
 * Checks only that `data` is non-`NULL` unless the length is zero and that
 * the length is representable by the current build's `size_t`. Does not
 * access memory and does not prove sufficient allocation bounds.
 *
 * @param[in] value View to validate.
 *
 * @return #TLV_OK if the view is well formed.
 * @return #TLV_ERR_NULL_ARG if `value` is `NULL`.
 * @return #TLV_ERR_NULL_ARG if its `data` is `NULL` with a nonzero length.
 * @return #TLV_ERR_INVALID_LENGTH if the length is not representable as `size_t`.
 */
TLV_API tlv_result_t tlv_value_validate(const tlv_value_t* value);

/**
 * @brief Tests whether two values have the same length and bytes.
 *
 * Compares contents, not pointer identity, so values backed by different
 * memory are equal when their bytes match. Two empty values are equal.
 *
 * @pre Both values are valid: tlv_value_validate() returns #TLV_OK. An
 *      invalid value is a contract violation, not a comparable value.
 *
 * @note `tlv_value_equal(a, b)` is true exactly when `tlv_value_compare(a, b) == 0`.
 *
 * @param[in] lhs First value.
 * @param[in] rhs Second value.
 *
 * @return `true` if both values have the same length and bytes.
 */
TLV_API bool tlv_value_equal(tlv_value_t lhs, tlv_value_t rhs);

/**
 * @brief Orders two values lexicographically by their bytes.
 *
 * Compares byte by byte as unsigned values; if one value is a prefix of the
 * other, the shorter value orders first.
 *
 * @pre Both values are valid: tlv_value_validate() returns #TLV_OK.
 *
 * @param[in] lhs First value.
 * @param[in] rhs Second value.
 *
 * @return A negative value if `lhs` orders before `rhs`, zero if the values
 *         are equal, and a positive value if `lhs` orders after `rhs`.
 */
TLV_API int tlv_value_compare(tlv_value_t lhs, tlv_value_t rhs);

/**
 * @brief Tests whether a value has zero length.
 *
 * @param[in] value Value to test.
 *
 * @return `true` if `value.length` is zero.
 */
TLV_API bool tlv_value_is_empty(tlv_value_t value);

/**
 * @brief Builds a sub-view over part of a value, without copying.
 *
 * The result borrows the same storage as `value`.
 *
 * @param[in]  value  Value to slice.
 * @param[in]  offset Start of the sub-range, in bytes from `value.data`.
 * @param[in]  length Length of the sub-range in bytes.
 * @param[out] out    Receives the sliced sub-view. Required.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG if `out` is `NULL`.
 * @return #TLV_ERR_INVALID_LENGTH if `value` is not representable by the
 *         current build's `size_t`, or if `offset + length` exceeds
 *         `value.length`.
 * @return #TLV_ERR_OVERFLOW if `offset + length` overflows #tlv_length_t.
 *
 * @note `*out` is unchanged on every failure.
 */
TLV_API tlv_result_t tlv_value_slice(tlv_value_t value, tlv_length_t offset, tlv_length_t length,
                                     tlv_value_t* out);

/**
 * @brief Copies a value's bytes into caller-owned storage.
 *
 * With `data == NULL` and `capacity == 0`, reports the required size in
 * `*written` without copying. Overlapping source and destination byte ranges
 * are supported.
 *
 * @param[in]  value    Value whose bytes are copied.
 * @param[out] data     Destination buffer. `NULL` with zero `capacity`
 *                      queries the required size.
 * @param[in]  capacity Destination capacity in bytes.
 * @param[out] written  Receives the value size (the required size for a
 *                      query). Required.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG if `written` is `NULL`, if `data` is `NULL` with
 *         a nonzero `capacity`, or if `value.data` is `NULL` with a nonzero
 *         `value.length`.
 * @return #TLV_ERR_INVALID_LENGTH if `value.length` exceeds the native size range.
 * @return #TLV_ERR_BUFFER_TOO_SHORT if `capacity` is insufficient; `*written`
 *         is unchanged.
 */
TLV_API tlv_result_t tlv_value_copy(tlv_value_t value, uint8_t* data, size_t capacity,
                                    size_t* written);

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* OPENTLV_VALUE_H */
