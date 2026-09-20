#ifndef OPENTLV_VALUE_H
#define OPENTLV_VALUE_H

#include "tlv/error.h"
#include "tlv/length.h"
#include "tlv/export.h"
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

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* OPENTLV_VALUE_H */
