#ifndef OPENTLV_FORMATS_DER_H
#define OPENTLV_FORMATS_DER_H

#include "tlv/error.h"
#include "tlv/formats/format.h"
#include "tlv/formats/asn1/ber.h"
#include "tlv/export.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup formats
 * @brief ASN.1 DER reader and writer formats with tag accessors.
 *
 * #tlv_asn1_class_t is declared in tlv/formats/asn1/ber.h: identifier-octet
 * class bits are shared by every ASN.1 encoding-rule profile, not specific to
 * DER.
 */

/** @addtogroup formats
 * @{
 */

/**
 * @brief Returns the ASN.1 class of a DER tag.
 *
 * @param tag A successfully parsed or created DER tag; must be non-`NULL`
 *            and nonempty.
 *
 * @return The identifier-octet class.
 */
static inline tlv_asn1_class_t tlv_der_tag_class(const tlv_tag_t* tag) {
    return (tlv_asn1_class_t)(tag->data[0] >> TLV_ASN1_CLASS_SHIFT);
}
/**
 * @brief Reports whether a DER tag has the constructed bit set.
 *
 * @param tag A successfully parsed or created DER tag; must be non-`NULL`
 *            and nonempty.
 *
 * @return Nonzero if constructed, zero if primitive.
 */
static inline int tlv_der_tag_is_constructed(const tlv_tag_t* tag) {
    return (tag->data[0] & TLV_ASN1_CONSTRUCTED_BIT) != 0;
}

/**
 * @brief Constructs a canonical DER tag.
 *
 * Raw parsing supports tags up to #TLV_ASN1_TAG_MAX_SIZE bytes.
 *
 * @param[in]  tag_class   ASN.1 class.
 * @param[in]  constructed Nonzero for constructed form, zero for primitive.
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
 * @brief Reader format for canonical ASN.1 DER identifiers and definite lengths.
 *
 * Validates universal primitive/constructed bits, but does not inspect values
 * or nested headers. Use tlv/profiles/der.h for bounded recursive validation
 * and error offsets.
 */
extern TLV_API const tlv_reader_format_t tlv_reader_format_der;
/** @brief Writer format for canonical ASN.1 DER identifiers and definite lengths.
 *  @copydetails tlv_reader_format_der */
extern TLV_API const tlv_writer_format_t tlv_writer_format_der;

/**
 * @brief Nesting predicate for tree traversal of DER data.
 *
 * Matches #tlv_is_constructed_fn.
 *
 * @param context Unused; may be `NULL`.
 * @param tag     A successfully parsed DER tag.
 *
 * @return Nonzero if the tag is constructed, zero otherwise.
 */
TLV_API int tlv_der_is_constructed(const void* context, const tlv_tag_t* tag);

#ifdef __cplusplus
}
#endif
/** @} */

#endif
