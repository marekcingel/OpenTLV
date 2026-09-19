#ifndef OPENTLV_FORMATS_CER_H
#define OPENTLV_FORMATS_CER_H

#include "tlv/formats/format.h"
#include "tlv/formats/asn1/ber.h"
#include "tlv/export.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file cer.h
 * @brief ASN.1 CER reader and writer formats with tag accessors.
 *
 * The tag accessors here have identical semantics to the DER accessors in
 * tlv/formats/asn1/der.h (#tlv_asn1_class_t is shared, declared in
 * tlv/formats/asn1/ber.h). They are duplicated rather than reused from
 * der.h so CER never depends on the DER component being enabled.
 */

/**
 * @brief Returns the ASN.1 class of a CER tag.
 *
 * @param tag A successfully parsed or created CER tag; must be non-`NULL`
 *            and nonempty.
 *
 * @return The identifier-octet class.
 */
static inline tlv_asn1_class_t tlv_cer_tag_class(const tlv_tag_t* tag) {
    return (tlv_asn1_class_t)(tag->data[0] >> TLV_ASN1_CLASS_SHIFT);
}
/**
 * @brief Reports whether a CER tag has the constructed bit set.
 *
 * @param tag A successfully parsed or created CER tag; must be non-`NULL`
 *            and nonempty.
 *
 * @return Nonzero if constructed, zero if primitive.
 */
static inline int tlv_cer_tag_is_constructed(const tlv_tag_t* tag) {
    return (tag->data[0] & TLV_ASN1_CONSTRUCTED_BIT) != 0;
}

/**
 * @brief Constructs a canonical CER tag.
 *
 * Identical rules and error conventions to tlv_der_tag_make(): ASN.1
 * identifier octets (X.690 section 8.1) are not specific to any single
 * encoding-rule profile.
 *
 * @param[in]  tag_class   ASN.1 class.
 * @param[in]  constructed Nonzero for constructed form, zero for primitive.
 * @param[in]  number      Tag number.
 * @param[out] tag         Destination tag.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG if `tag` is `NULL`.
 * @return #TLV_ERR_INVALID_TAG if the encoding is invalid or the number
 *         exceeds `uint64_t`.
 * @return #TLV_ERR_INVALID_TAG_SIZE if the tag would be empty or exceed
 *         #TLV_TAG_CAPACITY.
 *
 * @note The destination is unchanged on failure.
 */
TLV_API tlv_result_t tlv_cer_tag_make(tlv_asn1_class_t tag_class, int constructed, uint64_t number,
                                      tlv_tag_t* tag);
/**
 * @brief Extracts the numeric tag number from a CER tag.
 *
 * Same rules and errors as tlv_der_tag_number().
 *
 * @param[in]  tag    CER tag.
 * @param[out] number Receives the tag number.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG if a required pointer is `NULL`.
 * @return #TLV_ERR_INVALID_TAG if the encoding is invalid or the number
 *         exceeds `uint64_t`.
 * @return #TLV_ERR_INVALID_TAG_SIZE for an empty tag or one exceeding
 *         #TLV_TAG_CAPACITY.
 *
 * @note `*number` is unchanged on failure.
 */
TLV_API tlv_result_t tlv_cer_tag_number(const tlv_tag_t* tag, uint64_t* number);

/**
 * @brief Reader format for canonical ASN.1 CER identifiers and lengths of a single element.
 *
 * SEQUENCE/SEQUENCE OF, SET/SET OF, EXTERNAL, EMBEDDED PDV and CHARACTER
 * STRING must be constructed; universal tags 0 (EOC) and 15 are rejected;
 * high-tag-number form must be minimal. Unlike DER, this descriptor does not
 * require every other UNIVERSAL primitive tag number to stay primitive: CER
 * permits either form for the segmentable string types (BIT STRING, OCTET
 * STRING and the restricted character string types), chosen by content
 * length rather than fixed by the tag alone, so that decision is left to
 * tlv/profiles/cer.h. A constructed value's length must be indefinite
 * (0x80); a primitive value's length must be definite and minimally encoded
 * (short form below 128, long form only at or above 128, no leading zero
 * padding octet).
 *
 * This is a TLV-layer descriptor: it validates the current element's
 * identifier and length only, not nested framing, EOC placement, or
 * canonical segmentation across descendants.
 *
 * @warning Generic writing through #tlv_writer_format_cer is therefore not by
 *          itself a complete CER encoder for constructed or segmentable
 *          values. Use tlv/profiles/cer.h for bounded recursive validation,
 *          canonical constructed/segmented encoding, and error offsets.
 */
extern TLV_API const tlv_reader_format_t tlv_reader_format_cer;
/** @brief Writer format for canonical ASN.1 CER identifiers and lengths of a single element.
 *  @copydetails tlv_reader_format_cer */
extern TLV_API const tlv_writer_format_t tlv_writer_format_cer;

/**
 * @brief Nesting predicate for tree traversal of CER data.
 *
 * Matches #tlv_is_constructed_fn.
 *
 * @param context Unused; may be `NULL`.
 * @param tag     A successfully parsed CER tag.
 *
 * @return Nonzero if the tag is constructed, zero otherwise.
 */
TLV_API int tlv_cer_is_constructed(const void* context, const tlv_tag_t* tag);

#ifdef __cplusplus
}
#endif
#endif /* OPENTLV_FORMATS_CER_H */
