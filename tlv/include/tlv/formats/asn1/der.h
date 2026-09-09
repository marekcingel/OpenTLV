#ifndef OPENTLV_FORMATS_DER_H
#define OPENTLV_FORMATS_DER_H

#include "tlv/formats/format.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum tlv_asn1_class {
    TLV_ASN1_UNIVERSAL = 0,
    TLV_ASN1_APPLICATION = 1,
    TLV_ASN1_CONTEXT_SPECIFIC = 2,
    TLV_ASN1_PRIVATE = 3
} tlv_asn1_class_t;

/* Accessors require a successfully parsed or created DER tag. */
static inline tlv_asn1_class_t tlv_der_tag_class(const tlv_tag_t* tag) {
    return (tlv_asn1_class_t)(tag->data[0] >> 6);
}
static inline int tlv_der_tag_is_constructed(const tlv_tag_t* tag) {
    return (tag->data[0] & 0x20) != 0;
}

/* Canonical tag construction and numeric extraction. Numbers exceeding uint64_t
 * or tags exceeding TLV_TAG_MAX_SIZE return INVALID_TAG. Outputs are unchanged
 * on failure. Raw parsing supports the full configured tag capacity.
 */
tlv_result_t tlv_der_tag_make(tlv_asn1_class_t tag_class, int constructed,
                              uint64_t number, tlv_tag_t* tag);
tlv_result_t tlv_der_tag_number(const tlv_tag_t* tag, uint64_t* number);

/* Canonical ASN.1 DER identifiers and definite lengths. Validates universal
 * primitive/constructed bits, but does not inspect values or nested headers.
 * Use tlv/profiles/der.h for bounded recursive validation and error offsets.
 */
extern const tlv_reader_format_t tlv_reader_format_der;
extern const tlv_writer_format_t tlv_writer_format_der;

/* Nesting predicate for tree traversal; context is unused. */
int tlv_der_is_constructed(const void* context, const tlv_tag_t* tag);

#ifdef __cplusplus
}
#endif
#endif
