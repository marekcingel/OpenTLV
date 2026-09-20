#ifndef OPENTLV_LENGTH_H
#define OPENTLV_LENGTH_H

#include "tlv/error.h"
#include "tlv/export.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup core
 * @brief Build-independent 64-bit TLV length type and checked conversions to `size_t`.
 */

/** @addtogroup core
 * @{
 */

/**
 * @brief Logical TLV value length.
 *
 * Always a 64-bit unsigned range, independent of build configuration, the
 * current build's `size_t` width, or wire format.
 *
 * @warning A value may not be usable as an in-memory buffer length in the
 *          current build. Convert with tlv_length_to_size() or check with
 *          tlv_length_validate_native() before native-size use.
 */
typedef uint64_t tlv_length_t;

/**
 * @brief Converts a native size to a #tlv_length_t.
 *
 * The conversion is lossless: every `size_t` value fits #tlv_length_t, so it
 * cannot fail for its numeric domain.
 *
 * @param[in]  size   Native size to convert.
 * @param[out] length Receives the length. Required.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG if `length` is `NULL`; nothing is written.
 */
TLV_API tlv_result_t tlv_length_from_size(size_t size, tlv_length_t* length);

/**
 * @brief Narrows a #tlv_length_t to the current build's native size.
 *
 * @param[in]  length Length to convert.
 * @param[out] size   Receives the native size. Required; checked before the
 *                    range comparison.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG if `size` is `NULL`.
 * @return #TLV_ERR_INVALID_LENGTH if `length` exceeds `SIZE_MAX`; `*size` is
 *         left unchanged.
 *
 * @note Success does not prove that a buffer of that size exists, is
 *       accessible, or has sufficient capacity; actual bounds remain the
 *       caller's responsibility.
 */
TLV_API tlv_result_t tlv_length_to_size(tlv_length_t length, size_t* size);

/**
 * @brief Checks whether a length fits the current build's `size_t` range.
 *
 * Neither converts the length nor accesses any memory.
 *
 * @param length Length to check.
 *
 * @return #TLV_OK if it fits.
 * @return #TLV_ERR_INVALID_LENGTH otherwise.
 *
 * @note Success does not prove that a buffer exists, is accessible, or has
 *       sufficient capacity.
 */
TLV_API tlv_result_t tlv_length_validate_native(tlv_length_t length);

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* OPENTLV_LENGTH_H */
