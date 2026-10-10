// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_SIZE_H
#define OPENTLV_SIZE_H

#include "tlv/result.h"
#include "tlv/export.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup core
 * @brief Build-independent 64-bit TLV size type and checked conversions to `size_t`.
 */

/** @addtogroup core
 * @{
 */

/**
 * @brief Logical TLV value size.
 *
 * Always a 64-bit unsigned range, independent of build configuration, the
 * current build's `size_t` width, or wire format.
 *
 * @warning A value may not be usable as an in-memory buffer size in the
 *          current build. Convert with tlv_size_to_native() or check with
 *          tlv_size_validate_native() before native-size use.
 */
typedef uint64_t tlv_size_t;

/**
 * @def TLV_SIZE_MAX
 * @brief The largest value a #tlv_size_t can hold.
 *
 * Always `UINT64_MAX`, independent of build configuration or the current
 * build's `size_t` width. Distinct from `SIZE_MAX`, which bounds what
 * tlv_size_to_native() accepts in the current build.
 */
#define TLV_SIZE_MAX UINT64_MAX

/**
 * @brief Converts a native size to a #tlv_size_t.
 *
 * The conversion is lossless: every `size_t` value fits #tlv_size_t, so it
 * cannot fail for its numeric domain.
 *
 * @param[in]  size   Native size to convert.
 * @param[out] logical_size Receives the logical size. Required.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG if `logical_size` is `NULL`; nothing is written.
 */
TLV_API tlv_result_t tlv_size_from_native(size_t size, tlv_size_t* logical_size);

/**
 * @brief Narrows a #tlv_size_t to the current build's native size.
 *
 * @param[in]  logical_size Logical size to convert.
 * @param[out] size   Receives the native size. Required; checked before the
 *                    range comparison.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG if `size` is `NULL`.
 * @return #TLV_ERR_NATIVE_SIZE if `logical_size` exceeds `SIZE_MAX`; `*size` is
 *         left unchanged.
 *
 * @note Success does not prove that a buffer of that size exists, is
 *       accessible, or has sufficient capacity; actual bounds remain the
 *       caller's responsibility.
 */
TLV_API tlv_result_t tlv_size_to_native(tlv_size_t logical_size, size_t* size);

/**
 * @brief Checks whether a logical size fits the current build's `size_t` range.
 *
 * Neither converts the logical size nor accesses any memory.
 *
 * @param logical_size Logical size to check.
 *
 * @return #TLV_OK if it fits.
 * @return #TLV_ERR_NATIVE_SIZE otherwise.
 *
 * @note Success does not prove that a buffer exists, is accessible, or has
 *       sufficient capacity.
 */
TLV_API tlv_result_t tlv_size_validate_native(tlv_size_t logical_size);

/**
 * @brief Adds two logical sizes, detecting overflow.
 *
 * Neither operand is range-checked against `size_t`; this only guards the
 * #tlv_size_t addition itself, for example when composing a header size
 * and a value size before a native-size conversion.
 *
 * @param[in]  a   First addend.
 * @param[in]  b   Second addend.
 * @param[out] sum Receives `a + b`. Required.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG if `sum` is `NULL`.
 * @return #TLV_ERR_OVERFLOW if `a + b` exceeds #TLV_SIZE_MAX; `*sum` is
 *         unchanged.
 */
TLV_API tlv_result_t tlv_size_add(tlv_size_t a, tlv_size_t b, tlv_size_t* sum);

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* OPENTLV_SIZE_H */
