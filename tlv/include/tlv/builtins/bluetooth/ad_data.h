// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_BUILTINS_BLUETOOTH_AD_DATA_H
#define OPENTLV_BUILTINS_BLUETOOTH_AD_DATA_H

#include "tlv/error.h"
#include "tlv/reader/diagnostic.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @brief Bluetooth Advertising Data container framing and zero padding.
 *
 * @note Requires `OPENTLV_BLUETOOTH=ON`.
 */

/**
 * @brief Validates AD structures and trailing zero padding.
 *
 * Uses the generic reader with the strict Bluetooth LTV format. A zero byte
 * at a structure boundary starts padding; every remaining byte must be zero.
 * Zero bytes inside a structure remain part of that structure. Unknown types
 * and empty values are accepted. No schema or value-codec validation occurs.
 * Empty input and all-zero input succeed with a zero significant size.
 *
 * The significant prefix can be passed to a generic reader, visitor or schema
 * validator with the original input pointer, preserving source offsets.
 * This function never allocates, copies or retains input bytes.
 * Available when `OPENTLV_BLUETOOTH` is enabled.
 *
 * @param[in] data Caller-owned input, unchanged during the call. May be
 *                 `NULL` only when `size` is zero.
 * @param[in] size Input size in bytes, including padding.
 * @param[out] significant_size Required. Receives the prefix size in bytes,
 *                              excluding padding, only on success.
 * @param[out] diagnostic Optional. On failure receives the failing field's
 *                         offset relative to `data`, or the first nonzero
 *                         padding byte, in the INPUT domain. Argument errors
 *                         have unknown location.
 *                         Unchanged on success.
 *
 * @return #TLV_OK if all structures and padding are valid.
 * @return #TLV_ERR_NULL_ARG for a missing required pointer.
 * @return #TLV_ERR_INVALID_VALUE for a nonzero byte after padding starts.
 * @return #TLV_ERR_TRUNCATED for a truncated structure.
 * @return Any other generic reader error, propagated unchanged.
 *
 * @note `significant_size` remains unchanged on failure. Output storage must
 *       not overlap the input or each other.
 */
TLV_API tlv_result_t tlv_bluetooth_ad_data_validate(const uint8_t* data, size_t size,
                                                    size_t* significant_size,
                                                    tlv_reader_diagnostic_t* diagnostic);

#ifdef __cplusplus
}
#endif

#endif /* OPENTLV_BUILTINS_BLUETOOTH_AD_DATA_H */
