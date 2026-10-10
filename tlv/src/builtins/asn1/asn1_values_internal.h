// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_ASN1_VALUES_INTERNAL_H
#define OPENTLV_ASN1_VALUES_INTERNAL_H
#include "tlv/result.h"
#include "../../utf8_internal.h"
#include <stdint.h>
#include <stddef.h>

/* Shared ASN.1 canonical content validators (ITU-T X.690 §11, the canonical
 * value restrictions common to both CER and DER), reused by
 * the DER/CER validators and ASN.1 value codecs
 * without requiring the other component to be enabled. Each validator
 * receives one primitive element's complete content in isolation; value is
 * never NULL when length is nonzero. Returns TLV_OK or TLV_ERR_INVALID_VALUE.
 * No allocation, no recursion, a single bounded pass over the content. */
tlv_result_t tlv_asn1_validate_boolean(const uint8_t* value, size_t length);
tlv_result_t tlv_asn1_validate_integer(const uint8_t* value, size_t length);
tlv_result_t tlv_asn1_validate_null(const uint8_t* value, size_t length);
/* Whole-value BIT STRING content: unused-bits octet (0-7) plus trailing zero
 * padding. For CER, applies to an unsegmented primitive value or to a
 * constructed value's final segment; non-final segments follow a narrower
 * rule (unused-bits octet must be exactly 0) validated separately. */
tlv_result_t tlv_asn1_validate_bit_string(const uint8_t* value, size_t length);
tlv_result_t tlv_asn1_validate_octet_string(const uint8_t* value, size_t length);
tlv_result_t tlv_asn1_validate_oid(const uint8_t* value, size_t length);
tlv_result_t tlv_asn1_validate_real(const uint8_t* value, size_t length);
tlv_result_t tlv_asn1_validate_numeric_string(const uint8_t* value, size_t length);
tlv_result_t tlv_asn1_validate_printable_string(const uint8_t* value, size_t length);
tlv_result_t tlv_asn1_validate_ia5_string(const uint8_t* value, size_t length);
tlv_result_t tlv_asn1_validate_visible_string(const uint8_t* value, size_t length);
tlv_result_t tlv_asn1_validate_utf8(const uint8_t* value, size_t length);
tlv_result_t tlv_asn1_validate_universal_string(const uint8_t* value, size_t length);
tlv_result_t tlv_asn1_validate_bmp_string(const uint8_t* value, size_t length);
tlv_result_t tlv_asn1_validate_utc_time(const uint8_t* value, size_t length);
tlv_result_t tlv_asn1_validate_generalized_time(const uint8_t* value, size_t length);
/* Generic TIME (14): the ISO-8601-based abstract time type X.680 §38 defines.
 * Its concrete syntax varies far more than DATE/TIME-OF-DAY/DATE-TIME/
 * DURATION below (week dates, ordinal dates, fractional seconds, UTC
 * offsets, intervals), so this checks only its VisibleString character-set
 * restriction (X.690 §11), not the fuller ISO 8601 canonical-form grammar. */
tlv_result_t tlv_asn1_validate_time(const uint8_t* value, size_t length);
/* DATE/TIME-OF-DAY/DATE-TIME (31/32/33): "useful" fixed-form time types
 * X.680 §38 derives from TIME with SETTINGS pinning down one concrete
 * syntax; canonical content is a plain digit string in ISO 8601 basic form
 * with no separators ("YYYYMMDD"/"HHMMSS"/"YYYYMMDDHHMMSS"). Calendar
 * validity is range-checked only, as with UTCTime/GeneralizedTime. */
tlv_result_t tlv_asn1_validate_date(const uint8_t* value, size_t length);
tlv_result_t tlv_asn1_validate_time_of_day(const uint8_t* value, size_t length);
tlv_result_t tlv_asn1_validate_date_time(const uint8_t* value, size_t length);
/* DURATION (34): content is the ISO 8601 duration string without its
 * leading 'P' designator, e.g. "2Y10M15DT10H20M30S". Validates designator/
 * digit structure and component order (Y, M, D, then optionally T followed
 * by H, M, S); does not enforce ISO 8601's omission of zero-valued
 * components, and accepts a fractional value only on the seconds component
 * (not on M or H when they are the lowest-order component present), since
 * neither canonical-minimality nuance is independently confirmed here. */
tlv_result_t tlv_asn1_validate_duration(const uint8_t* value, size_t length);
/* OID-IRI/RELATIVE-OID-IRI (35/36): valid UTF-8 content (X.690 §8.21/8.22),
 * '/'-separated non-empty arcs with no leading, trailing or doubled '/';
 * OID-IRI additionally requires the leading '/' marking an absolute path,
 * RELATIVE-OID-IRI requires its absence. Checks arc-separator structure
 * only, not each arc's characters against the fuller RFC 3987 IRI-label
 * restrictions X.680's IRI value notation defines. */
tlv_result_t tlv_asn1_validate_oid_iri(const uint8_t* value, size_t length);
tlv_result_t tlv_asn1_validate_relative_oid_iri(const uint8_t* value, size_t length);

/* Dispatches a UNIVERSAL tag number to the validator above for one complete
 * primitive element's content, shared by DER and CER so both report identical results
 * for the value rules ITU-T X.690 §11 documents as common to both encodings.
 * Returns TLV_ERR_UNSUPPORTED for a UNIVERSAL number with no
 * implemented canonical content rule. */
tlv_result_t tlv_asn1_validate_universal_value(uint64_t number, const uint8_t* value,
                                               size_t length);

#endif /* OPENTLV_ASN1_VALUES_INTERNAL_H */
