#ifndef OPENTLV_CER_VALUES_INTERNAL_H
#define OPENTLV_CER_VALUES_INTERNAL_H
#include "tlv/error.h"
#include "tlv/tag.h"
#include "asn1_values_internal.h"
#include <stdint.h>
#include <stddef.h>

/* Maximum content octets of a single CER string segment (ITU-T X.690 §9.2);
 * also the primitive/constructed threshold for the segmentable UNIVERSAL
 * types below: a value with this many content octets or fewer must be
 * primitive, more must be constructed and segmented. */
#define TLV_CER_MAX_SEGMENT_OCTETS 1000

typedef enum tlv_cer_form {
    /* Not eligible for CER segmentation: must always stay primitive, unless
     * the number is in the always-constructed set (SEQUENCE/SET/EXTERNAL/
     * EMBEDDED PDV/CHARACTER STRING), which callers check separately -- the
     * wire layer (tlv_asn1_read_identifier) already requires that set to be
     * constructed, and no segmentation rule applies to it. */
    TLV_CER_FORM_PRIMITIVE_ONLY = 0,
    /* OCTET STRING: no content constraint on segments beyond size/form. */
    TLV_CER_FORM_OCTETS = 1,
    /* BIT STRING: segments carry a leading unused-bits octet. */
    TLV_CER_FORM_BIT_STRING = 2,
    /* A supported or recognized-but-unsupported restricted character string
     * type (or UTF8String); code_unit_width/is_utf8 refine the rule. */
    TLV_CER_FORM_CHARACTERS = 3
} tlv_cer_form_t;

typedef struct tlv_cer_type_info {
    tlv_cer_form_t form;
    unsigned code_unit_width; /* 1, 2 or 4; meaningful only for TLV_CER_FORM_CHARACTERS */
    int is_utf8;              /* nonzero: content may legally split a character across segments */
} tlv_cer_type_info_t;

/* Classifies a UNIVERSAL tag number for CER's segmentation rules. Numbers
 * outside the segmentable set (including the always-constructed set, and
 * any unassigned or unsupported non-string number) report
 * TLV_CER_FORM_PRIMITIVE_ONLY. */
tlv_cer_type_info_t tlv_cer_type_info(uint64_t number);

/* Strict-mode content validator for one complete, unsegmented primitive
 * value of any UNIVERSAL tag number -- identical dispatch to
 * tlv_der_validate_universal_value, sharing tlv_asn1_validate_universal_value
 * so DER and CER agree on every rule ITU-T X.690 §11 documents as common to
 * both. Returns TLV_OK, TLV_ERR_INVALID_VALUE, or TLV_ERR_UNSUPPORTED_TYPE. */
tlv_result_t tlv_cer_validate_universal_value(uint64_t number, const uint8_t* value, size_t length);

/* Accumulates and validates a segmentable constructed value's primitive
 * children as canonical CER string segments, one at a time in encounter
 * order, without ever concatenating their content. Segment tag/form and
 * non-emptiness are checked immediately; the exact-1000-octet non-final size
 * rule is checked one segment in arrears (once a further segment proves the
 * previous one was not last); the final segment's size/content rule is
 * checked by tlv_cer_segment_state_finish(). UTF8String content is streamed
 * through the fixed-state cross-segment validator as each segment arrives.
 * Bounded O(1) state; no allocation. */
typedef struct tlv_cer_segment_state {
    uint64_t number;
    tlv_cer_type_info_t info;
    int strict;
    size_t segment_count;
    size_t total_octets;
    int has_pending;
    const uint8_t* pending_value; /* borrows the input; zero-copy */
    size_t pending_length;
    size_t pending_offset;
    tlv_asn1_utf8_stream_t utf8;
} tlv_cer_segment_state_t;

/* element_tag is the enclosing constructed element's own tag (UNIVERSAL,
 * number, constructed bit set); every segment's tag must match it except
 * for the constructed bit, which must be clear. strict enables content
 * validation in addition to structural tag/form/size checks. */
void tlv_cer_segment_state_init(tlv_cer_segment_state_t* state, uint64_t number,
                                tlv_cer_type_info_t info, int strict);

/* Call for every primitive child of the segmentable constructed value, in
 * order. tag/value/length describe the segment as read; offset is its
 * absolute tag offset, used for error reporting via *error_offset. */
tlv_result_t tlv_cer_segment_state_add(tlv_cer_segment_state_t* state,
    const tlv_tag_t* tag, const uint8_t* value, size_t length, size_t offset,
    size_t* error_offset);

/* Call exactly once, when the enclosing element's matching EOC is found (so
 * every segment has already been fed to tlv_cer_segment_state_add()).
 * Validates that at least one segment was present (an empty constructed
 * string is not canonical), the final segment's size (1..1000 octets) and,
 * in strict mode, its content, and that constructed encoding was actually
 * justified (total content exceeded TLV_CER_MAX_SEGMENT_OCTETS).
 * element_offset is the constructed element's own tag offset, used when
 * segmentation was unjustified or no segment was present. */
tlv_result_t tlv_cer_segment_state_finish(tlv_cer_segment_state_t* state,
    size_t element_offset, size_t* error_offset);

#endif /* OPENTLV_CER_VALUES_INTERNAL_H */
