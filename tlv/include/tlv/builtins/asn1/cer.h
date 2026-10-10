// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_BUILTINS_ASN1_CER_H
#define OPENTLV_BUILTINS_ASN1_CER_H

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
 * @brief ASN.1 CER format and validated tag helpers.
 *
 * Shared identifier accessors are declared in tlv/builtins/asn1/identifier.h.
 */

/** @addtogroup formats
 * @{
 */

/**
 * @brief Constructs a canonical CER tag.
 *
 * Applies the identifier restrictions of #tlv_format_cer, including reserved
 * universal numbers and the always-constructed types. Unlike DER, string
 * tags may be constructed; segmentation is validated by the CER validation.
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
TLV_API tlv_result_t tlv_cer_tag_make(tlv_asn1_class_t tag_class, int constructed, uint64_t number,
                                      uint8_t* storage, tlv_tag_t* tag);
/**
 * @brief Extracts the numeric tag number from a CER tag.
 *
 * Validates the identifier according to #tlv_format_cer before extraction.
 * Constructed string tags are accepted, unlike DER.
 *
 * @param[in]  tag    CER tag.
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
TLV_API tlv_result_t tlv_cer_tag_number(const tlv_tag_t* tag, uint64_t* number);

/**
 * @brief Format for canonical ASN.1 CER identifiers and lengths of a single element.
 *
 * SEQUENCE/SEQUENCE OF, SET/SET OF, EXTERNAL, EMBEDDED PDV and CHARACTER
 * STRING must be constructed; universal tags 0 (EOC) and 15 are rejected;
 * high-tag-number form must be minimal. Unlike DER, this descriptor does not
 * require every other UNIVERSAL primitive tag number to stay primitive: CER
 * permits either form for the segmentable string types (BIT STRING, OCTET
 * STRING and the restricted character string types), chosen by content
 * length rather than fixed by the tag alone, so that decision is left to
 * tlv/builtins/asn1/cer_validation.h. A constructed value's length must be indefinite
 * (0x80); a primitive value's length must be definite and minimally encoded
 * (short form below 128, long form only at or above 128, no leading zero
 * padding octet).
 *
 * This is a TLV-layer descriptor: it validates the current element's
 * identifier and length, using the shared BER scanner to locate matching
 * EOC boundaries. Descendants are checked for BER framing, not recursive
 * CER canonicality or string segmentation.
 *
 * @warning Generic writing through #tlv_format_cer is therefore not by itself
 *          a complete CER encoder for constructed or segmentable values. Use
 *          tlv/builtins/asn1/cer_validation.h for bounded recursive validation,
 *          canonical constructed/segmented encoding, and error offsets.
 */
extern TLV_API const tlv_format_t tlv_format_cer;

#ifdef __cplusplus
}
#endif
/** @} */

#endif /* OPENTLV_BUILTINS_ASN1_CER_H */
