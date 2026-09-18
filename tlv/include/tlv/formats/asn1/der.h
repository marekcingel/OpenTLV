#ifndef OPENTLV_FORMATS_DER_H
#define OPENTLV_FORMATS_DER_H

#include "tlv/formats/format.h"
#include "tlv/formats/asn1/ber.h"
#include "tlv/export.h"

#ifdef __cplusplus
extern "C" {
#endif

/* tlv_asn1_class_t is declared in tlv/formats/asn1/ber.h: identifier-octet
 * class bits are shared by every ASN.1 encoding-rule profile, not specific
 * to DER. Accessors below require a successfully parsed or created DER tag. */
static inline tlv_asn1_class_t tlv_der_tag_class(const tlv_tag_t* tag) {
    return (tlv_asn1_class_t)(tag->data[0] >> TLV_ASN1_CLASS_SHIFT);
}
static inline int tlv_der_tag_is_constructed(const tlv_tag_t* tag) {
    return (tag->data[0] & TLV_ASN1_CONSTRUCTED_BIT) != 0;
}

/* Canonical tag construction and numeric extraction. Numbers exceeding uint64_t
 * return TLV_ERR_INVALID_TAG. Empty tags or tags exceeding TLV_TAG_CAPACITY
 * return TLV_ERR_INVALID_TAG_SIZE. Invalid encodings return TLV_ERR_INVALID_TAG.
 * Outputs are unchanged
 * on failure. Raw parsing supports the full configured tag capacity.
 */
TLV_API tlv_result_t tlv_der_tag_make(tlv_asn1_class_t tag_class, int constructed, uint64_t number,
                                      tlv_tag_t* tag);
TLV_API tlv_result_t tlv_der_tag_number(const tlv_tag_t* tag, uint64_t* number);

/* Canonical ASN.1 DER identifiers and definite lengths. Validates universal
 * primitive/constructed bits, but does not inspect values or nested headers.
 * Use tlv/profiles/der.h for bounded recursive validation and error offsets.
 */
extern TLV_API const tlv_reader_format_t tlv_reader_format_der;
extern TLV_API const tlv_writer_format_t tlv_writer_format_der;

/* Nesting predicate for tree traversal; context is unused. */
TLV_API int tlv_der_is_constructed(const void* context, const tlv_tag_t* tag);

#ifdef __cplusplus
}
#endif
#endif
