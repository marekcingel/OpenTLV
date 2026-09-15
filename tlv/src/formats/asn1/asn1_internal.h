#ifndef OPENTLV_ASN1_INTERNAL_H
#define OPENTLV_ASN1_INTERNAL_H
#include "tlv/formats/format.h"

/* Parses one BER identifier via tlv_ber_reader_wire.read_tag, then applies the
 * canonical identifier restrictions shared by DER and CER (ITU-T X.690 §8.1,
 * applied by both the canonical (§9) and distinguished (§10) encoding rules):
 * the second high-tag-number digit must not encode a number below 31 (minimal
 * high-tag-number form), and for an assigned UNIVERSAL class number through
 * 36, universal tag 0 (reserved for EOC) and 15 (reserved) are rejected, and
 * SEQUENCE/SEQUENCE OF (16), SET/SET OF (17), EXTERNAL (8), EMBEDDED PDV (11)
 * and CHARACTER STRING (29) must be constructed. Numbers above 36 remain
 * opaque (no further check). This does not enforce a primitive-only
 * requirement for the remaining universal numbers: DER always requires it,
 * while CER requires it only for non-segmentable types, so each caller
 * applies that narrower rule itself. */
tlv_result_t tlv_asn1_read_identifier(const void* context, const uint8_t* data, size_t size,
                                      tlv_tag_t* tag, size_t* consumed);

/* Re-parses tag->data (a caller-owned raw tag) with tlv_asn1_read_identifier
 * and requires the parse to consume exactly tag->size bytes, matching the
 * write_tag contract (validate, and optionally emit, canonical identifier
 * bytes). data may be NULL only when capacity is 0 (size query). */
tlv_result_t tlv_asn1_write_identifier(const void* context, uint8_t* data, size_t capacity,
                                       const tlv_tag_t* tag, size_t* written);

/* Parses one BER definite length via tlv_ber_reader_wire.read_length, then
 * rejects non-minimal long-form encodings (a long form below 128, or a
 * leading zero padding octet), the canonical minimal-definite-length
 * restriction DER and CER both require of every definite length they encode.
 * Indefinite (0x80) and the reserved 0xFF prefix are already rejected by the
 * underlying reader. */
tlv_result_t tlv_asn1_read_minimal_length(const void* context, const uint8_t* data, size_t size,
                                          size_t* length, size_t* consumed);
#endif
