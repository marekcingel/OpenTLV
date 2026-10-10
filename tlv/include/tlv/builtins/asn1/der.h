// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_BUILTINS_ASN1_DER_H
#define OPENTLV_BUILTINS_ASN1_DER_H

#include "tlv/result.h"
#include "tlv/format.h"
#include "tlv/builtins/asn1/ber.h"
#include "tlv/export.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup formats
 * @brief ASN.1 DER format and validated tag helpers.
 *
 * Shared identifier accessors are declared in tlv/builtins/asn1/identifier.h.
 */

/** @addtogroup formats
 * @{
 */

/**
 * @brief Constructs a canonical DER tag.
 *
 * Raw parsing supports tags up to #TLV_ASN1_TAG_MAX_SIZE bytes.
 *
 * @param[in]  tag_class   ASN.1 class.
 * @param[in]  constructed One for constructed form, zero for primitive.
 * @param[in]  number      Tag number.
 * @param[out] storage     Destination for the tag bytes; #TLV_ASN1_TAG_MAX_SIZE
 *                         writable bytes. Must outlive every use of the tag.
 * @param[out] tag         Receives a tag that borrows `storage`.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG if `storage` or `tag` is `NULL`.
 * @return #TLV_ERR_INVALID_TAG if the encoding is invalid or the number
 *         exceeds `uint64_t`.
 * @return #TLV_ERR_INVALID_TAG_SIZE if the tag would exceed #TLV_ASN1_TAG_MAX_SIZE.
 *
 * @note The destination is unchanged on failure.
 */
TLV_API tlv_result_t tlv_der_tag_make(tlv_asn1_class_t tag_class, int constructed, uint64_t number,
                                      uint8_t* storage, tlv_tag_t* tag);
/**
 * @brief Extracts the numeric tag number from a DER tag.
 *
 * @param[in]  tag    DER tag.
 * @param[out] number Receives the tag number.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG if a required pointer is `NULL`.
 * @return #TLV_ERR_INVALID_TAG if the encoding is invalid or the number
 *         exceeds `uint64_t`.
 * @return #TLV_ERR_INVALID_TAG_SIZE for an empty tag or one exceeding
 *         #TLV_ASN1_TAG_MAX_SIZE.
 *
 * @note `*number` is unchanged on failure.
 */
TLV_API tlv_result_t tlv_der_tag_number(const tlv_tag_t* tag, uint64_t* number);

/**
 * @brief Format for canonical ASN.1 DER identifiers and definite lengths.
 *
 * Validates universal primitive/constructed bits, but does not inspect values
 * or nested headers. Use tlv/builtins/asn1/der_validation.h for bounded recursive validation
 * and error offsets.
 */
extern TLV_API const tlv_format_t tlv_format_der;

#ifdef __cplusplus
}
#endif
/** @} */

#endif
