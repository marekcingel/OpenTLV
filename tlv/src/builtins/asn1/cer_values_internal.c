#include "cer_values_internal.h"

tlv_cer_type_info_t tlv_cer_type_info(uint64_t number) {
    tlv_cer_type_info_t info;
    info.form = TLV_CER_FORM_PRIMITIVE_ONLY;
    info.code_unit_width = 1;
    info.is_utf8 = 0;
    switch (number) {
        case 3: info.form = TLV_CER_FORM_BIT_STRING; break;
        case 4: info.form = TLV_CER_FORM_OCTETS; break;
        case 12:
            info.form = TLV_CER_FORM_CHARACTERS;
            info.is_utf8 = 1;
            break;
        /* ObjectDescriptor(7), NumericString(18), PrintableString(19),
         * TeletexString(20), VideotexString(21), IA5String(22),
         * GraphicString(25), VisibleString(26), GeneralString(27): all
         * 1-octet restricted character string types. 7/20/21/25/27 accept
         * any byte sequence per-segment (matching DER's unconstrained
         * content rule for them); see validate_character_segment() below. */
        case 7:
        case 18:
        case 19:
        case 20:
        case 21:
        case 22:
        case 25:
        case 26:
        case 27: info.form = TLV_CER_FORM_CHARACTERS; break;
        case 28:
            info.form = TLV_CER_FORM_CHARACTERS;
            info.code_unit_width = 4;
            break; /* UniversalString */
        case 30:
            info.form = TLV_CER_FORM_CHARACTERS;
            info.code_unit_width = 2;
            break; /* BMPString */
        default: break;
    }
    return info;
}

tlv_result_t tlv_cer_validate_universal_value(uint64_t number, const uint8_t* value,
                                              size_t length) {
    return tlv_asn1_validate_universal_value(number, value, length);
}

/* All currently classified segmentable/character numbers are <=30, so every
 * legally-parsed element carrying one uses the single-byte low-tag-number
 * form (tlv_asn1_read_identifier already rejects a non-minimal high-tag-
 * number encoding of a number below 31). A segment must repeat that same
 * UNIVERSAL, primitive-form byte. */
static int tag_matches_primitive(const tlv_tag_t* tag, uint64_t number) {
    if (tag->size != 1) return 0;
    if ((tag->data[0] & 0xC0) != 0) return 0;
    if (tag->data[0] & 0x20) return 0;
    return (uint64_t)(tag->data[0] & 0x1F) == number;
}

/* Position-independent character-string segment content: charset checks are
 * unaffected by whether a segment is final, and UniversalString/BMPString's
 * fixed code-unit width evenly divides TLV_CER_MAX_SEGMENT_OCTETS (1000),
 * so only the (possibly short) final segment's alignment needs checking. */
static tlv_result_t validate_character_segment(uint64_t number, unsigned width,
                                               const uint8_t* value, size_t length) {
    if (width == 4) {
        if (length % 4) return TLV_ERR_INVALID_VALUE;
        return tlv_asn1_validate_universal_string(value, length);
    }
    if (width == 2) {
        if (length % 2) return TLV_ERR_INVALID_VALUE;
        return tlv_asn1_validate_bmp_string(value, length);
    }
    switch (number) {
        case 18: return tlv_asn1_validate_numeric_string(value, length);
        case 19: return tlv_asn1_validate_printable_string(value, length);
        case 22: return tlv_asn1_validate_ia5_string(value, length);
        case 26: return tlv_asn1_validate_visible_string(value, length);
        /* ObjectDescriptor, TeletexString, VideotexString, GraphicString,
         * GeneralString: unconstrained, like OCTET STRING. */
        case 7:
        case 20:
        case 21:
        case 25:
        case 27: return tlv_asn1_validate_octet_string(value, length);
        default: return TLV_ERR_UNSUPPORTED_TYPE; /* unreachable: no other number reaches here */
    }
}

void tlv_cer_segment_state_init(tlv_cer_segment_state_t* state, uint64_t number,
                                tlv_cer_type_info_t info, int strict) {
    state->number = number;
    state->info = info;
    state->strict = strict;
    state->segment_count = 0;
    state->total_octets = 0;
    state->has_pending = 0;
    state->pending_value = NULL;
    state->pending_length = 0;
    state->pending_offset = 0;
    if (strict && info.form == TLV_CER_FORM_CHARACTERS && info.is_utf8)
        tlv_asn1_utf8_stream_init(&state->utf8);
}

tlv_result_t tlv_cer_segment_state_add(tlv_cer_segment_state_t* state, const tlv_tag_t* tag,
                                       const uint8_t* value, size_t length, size_t offset,
                                       size_t* error_offset) {
    /* A further segment proves the previously pending one was not last. */
    if (state->has_pending) {
        if (state->pending_length != TLV_CER_MAX_SEGMENT_OCTETS) {
            if (error_offset) *error_offset = state->pending_offset;
            return TLV_ERR_INVALID_LENGTH;
        }
        if (state->strict && state->info.form == TLV_CER_FORM_BIT_STRING &&
            state->pending_value[0] != 0) {
            if (error_offset) *error_offset = state->pending_offset;
            return TLV_ERR_INVALID_VALUE;
        }
    }

    if (!tag_matches_primitive(tag, state->number)) {
        if (error_offset) *error_offset = offset;
        return TLV_ERR_INVALID_TAG;
    }
    if (length == 0 || length > TLV_CER_MAX_SEGMENT_OCTETS) {
        if (error_offset) *error_offset = offset;
        return TLV_ERR_INVALID_LENGTH;
    }

    if (state->strict && state->info.form == TLV_CER_FORM_CHARACTERS) {
        tlv_result_t rc;
        if (state->info.is_utf8)
            rc = tlv_asn1_utf8_stream_update(&state->utf8, value, length);
        else
            rc = validate_character_segment(state->number, state->info.code_unit_width, value,
                                            length);
        if (rc != TLV_OK) {
            if (error_offset) *error_offset = offset;
            return rc;
        }
    }

    state->total_octets += length;
    state->has_pending = 1;
    state->pending_value = value;
    state->pending_length = length;
    state->pending_offset = offset;
    ++state->segment_count;
    return TLV_OK;
}

tlv_result_t tlv_cer_segment_state_finish(tlv_cer_segment_state_t* state, size_t element_offset,
                                          size_t* error_offset) {
    if (!state->has_pending) {
        if (error_offset) *error_offset = element_offset;
        return TLV_ERR_INVALID_LENGTH;
    }
    if (state->total_octets <= TLV_CER_MAX_SEGMENT_OCTETS) {
        if (error_offset) *error_offset = element_offset;
        return TLV_ERR_INVALID_LENGTH;
    }
    if (state->strict) {
        tlv_result_t rc;
        if (state->info.form == TLV_CER_FORM_BIT_STRING) {
            rc = tlv_asn1_validate_bit_string(state->pending_value, state->pending_length);
            if (rc != TLV_OK) {
                if (error_offset) *error_offset = state->pending_offset;
                return rc;
            }
        } else if (state->info.form == TLV_CER_FORM_CHARACTERS && state->info.is_utf8) {
            rc = tlv_asn1_utf8_stream_finish(&state->utf8);
            if (rc != TLV_OK) {
                if (error_offset) *error_offset = state->pending_offset;
                return rc;
            }
        }
        /* OCTETS: no content rule. Non-UTF8 CHARACTERS: every segment,
         * including this final one, was already validated when added. */
    }
    return TLV_OK;
}
