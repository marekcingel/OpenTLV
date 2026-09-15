#ifndef OPENTLV_FORMATS_CER_H
#define OPENTLV_FORMATS_CER_H

#include "tlv/formats/format.h"
#include "tlv/formats/asn1/ber.h"
#include "tlv/export.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Accessors require a successfully parsed or created CER tag; identical
 * semantics to the DER accessors in tlv/formats/asn1/der.h (tlv_asn1_class_t
 * is shared, declared in tlv/formats/asn1/ber.h). Duplicated here, rather
 * than reused from der.h, so CER never depends on the DER component being
 * enabled. */
static inline tlv_asn1_class_t tlv_cer_tag_class(const tlv_tag_t* tag) {
    return (tlv_asn1_class_t)(tag->data[0] >> 6);
}
static inline int tlv_cer_tag_is_constructed(const tlv_tag_t* tag) {
    return (tag->data[0] & 0x20) != 0;
}

/* Canonical tag construction and numeric extraction; identical rules and
 * error conventions to tlv_der_tag_make/tlv_der_tag_number (ASN.1 identifier
 * octets, X.690 §8.1, are not specific to any single encoding-rule profile).
 * Numbers exceeding uint64_t return TLV_ERR_INVALID_TAG. Empty tags or tags
 * exceeding TLV_TAG_CAPACITY return TLV_ERR_INVALID_TAG_SIZE. Invalid
 * encodings return TLV_ERR_INVALID_TAG. Outputs are unchanged on failure.
 */
TLV_API tlv_result_t tlv_cer_tag_make(tlv_asn1_class_t tag_class, int constructed,
                              uint64_t number, tlv_tag_t* tag);
TLV_API tlv_result_t tlv_cer_tag_number(const tlv_tag_t* tag, uint64_t* number);

/* Canonical ASN.1 CER identifiers and lengths for a single element: SEQUENCE/
 * SEQUENCE OF, SET/SET OF, EXTERNAL, EMBEDDED PDV and CHARACTER STRING must
 * be constructed; universal tags 0 (EOC) and 15 are rejected; high-tag-number
 * form must be minimal. Unlike DER, this descriptor does not require every
 * other UNIVERSAL primitive tag number to stay primitive: CER permits either
 * form for the segmentable string types (BIT STRING, OCTET STRING and the
 * restricted character string types), chosen by content length rather than
 * fixed by the tag alone, so that decision is left to tlv/profiles/cer.h. A
 * constructed value's length must be indefinite (0x80); a primitive value's
 * length must be definite and minimally encoded (short form below 128, long
 * form only at or above 128, no leading zero padding octet).
 *
 * This is a TLV-layer descriptor: it validates the current element's
 * identifier and length only, not nested framing, EOC placement, or
 * canonical segmentation across descendants. Generic writing through
 * tlv_writer_format_cer is therefore not by itself a complete CER encoder
 * for constructed or segmentable values -- use tlv/profiles/cer.h for
 * bounded recursive validation, canonical constructed/segmented encoding,
 * and error offsets.
 */
extern TLV_API const tlv_reader_format_t tlv_reader_format_cer;
extern TLV_API const tlv_writer_format_t tlv_writer_format_cer;

/* Nesting predicate for tree traversal; context is unused. */
TLV_API int tlv_cer_is_constructed(const void* context, const tlv_tag_t* tag);

#ifdef __cplusplus
}
#endif
#endif /* OPENTLV_FORMATS_CER_H */
