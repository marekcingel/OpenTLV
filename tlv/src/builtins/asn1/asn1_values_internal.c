#include "asn1_values_internal.h"

/* Canonical rules follow ITU-T X.690 (10/2021 edition), section 11. Every
 * validator receives one primitive UNIVERSAL element's content in isolation;
 * value is never NULL when length is nonzero. No allocation, no recursion. */

tlv_result_t tlv_asn1_validate_boolean(const uint8_t* value, size_t length) {
    if (length != 1) return TLV_ERR_INVALID_VALUE;
    return (value[0] == 0x00 || value[0] == 0xFF) ? TLV_OK : TLV_ERR_INVALID_VALUE;
}

/* Minimal two's complement: shared by INTEGER, ENUMERATED and REAL exponents. */
tlv_result_t tlv_asn1_validate_integer(const uint8_t* value, size_t length) {
    if (length < 1) return TLV_ERR_INVALID_VALUE;
    if (length > 1 && ((value[0] == 0x00 && (value[1] & 0x80) == 0) ||
                       (value[0] == 0xFF && (value[1] & 0x80) != 0)))
        return TLV_ERR_INVALID_VALUE;
    return TLV_OK;
}

tlv_result_t tlv_asn1_validate_null(const uint8_t* value, size_t length) {
    (void)value;
    return length == 0 ? TLV_OK : TLV_ERR_INVALID_VALUE;
}

tlv_result_t tlv_asn1_validate_bit_string(const uint8_t* value, size_t length) {
    uint8_t unused, mask;
    if (length < 1) return TLV_ERR_INVALID_VALUE;
    unused = value[0];
    if (unused > 7) return TLV_ERR_INVALID_VALUE;
    if (length == 1) return unused == 0 ? TLV_OK : TLV_ERR_INVALID_VALUE;
    mask = (uint8_t)((1U << unused) - 1U);
    return (value[length - 1] & mask) == 0 ? TLV_OK : TLV_ERR_INVALID_VALUE;
}

tlv_result_t tlv_asn1_validate_octet_string(const uint8_t* value, size_t length) {
    (void)value;
    (void)length;
    return TLV_OK;
}

/* Shared by OBJECT IDENTIFIER and RELATIVE-OID: base-128 subidentifiers, none
 * of which may start with a redundant leading 0x80 (a non-minimal leading
 * zero digit). Arc-value semantics (X.660 naming rules) are not checked. */
tlv_result_t tlv_asn1_validate_oid(const uint8_t* value, size_t length) {
    size_t i = 0;
    if (length < 1) return TLV_ERR_INVALID_VALUE;
    while (i < length) {
        if (value[i] == 0x80) return TLV_ERR_INVALID_VALUE;
        while (i < length && (value[i] & 0x80)) ++i;
        if (i == length) return TLV_ERR_INVALID_VALUE;
        ++i;
    }
    return TLV_OK;
}

/* Binary encoding only (base 2, zero scale factor, minimal exponent and odd
 * mantissa); the four special-value octets; decimal (ISO 6093) form and the
 * long exponent-length form are never canonical. */
tlv_result_t tlv_asn1_validate_real(const uint8_t* value, size_t length) {
    size_t exp_octets, mantissa_start;
    uint8_t first;
    if (length == 0) return TLV_OK;
    first = value[0];
    if (!(first & 0x80)) {
        if (first & 0x40)
            return (length == 1 &&
                    (first == 0x40 || first == 0x41 || first == 0x42 || first == 0x43))
                       ? TLV_OK
                       : TLV_ERR_INVALID_VALUE;
        return TLV_ERR_INVALID_VALUE;
    }
    if ((first & 0x30) != 0x00) return TLV_ERR_INVALID_VALUE;
    if ((first & 0x0C) != 0x00) return TLV_ERR_INVALID_VALUE;
    switch (first & 0x03) {
        case 0: exp_octets = 1; break;
        case 1: exp_octets = 2; break;
        case 2: exp_octets = 3; break;
        default: return TLV_ERR_INVALID_VALUE;
    }
    if (length < 1 + exp_octets + 1) return TLV_ERR_INVALID_VALUE;
    if (tlv_asn1_validate_integer(value + 1, exp_octets) != TLV_OK) return TLV_ERR_INVALID_VALUE;
    mantissa_start = 1 + exp_octets;
    if (length - mantissa_start > 1 && value[mantissa_start] == 0x00) return TLV_ERR_INVALID_VALUE;
    return (value[length - 1] & 0x01) != 0 ? TLV_OK : TLV_ERR_INVALID_VALUE;
}

tlv_result_t tlv_asn1_validate_numeric_string(const uint8_t* value, size_t length) {
    size_t i;
    for (i = 0; i < length; ++i)
        if (!((value[i] >= '0' && value[i] <= '9') || value[i] == ' '))
            return TLV_ERR_INVALID_VALUE;
    return TLV_OK;
}

tlv_result_t tlv_asn1_validate_printable_string(const uint8_t* value, size_t length) {
    size_t i;
    for (i = 0; i < length; ++i) {
        uint8_t c = value[i];
        int ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                 c == ' ' || c == '\'' || c == '(' || c == ')' || c == '+' || c == ',' ||
                 c == '-' || c == '.' || c == '/' || c == ':' || c == '=' || c == '?';
        if (!ok) return TLV_ERR_INVALID_VALUE;
    }
    return TLV_OK;
}

tlv_result_t tlv_asn1_validate_ia5_string(const uint8_t* value, size_t length) {
    size_t i;
    for (i = 0; i < length; ++i)
        if (value[i] > 0x7F) return TLV_ERR_INVALID_VALUE;
    return TLV_OK;
}

tlv_result_t tlv_asn1_validate_visible_string(const uint8_t* value, size_t length) {
    size_t i;
    for (i = 0; i < length; ++i)
        if (value[i] < 0x20 || value[i] > 0x7E) return TLV_ERR_INVALID_VALUE;
    return TLV_OK;
}

void tlv_asn1_utf8_stream_init(tlv_asn1_utf8_stream_t* state) {
    state->pending_len = 0;
    state->pending_need = 0;
}

/* Validates one completed code point's leading byte range/overlong/surrogate
 * rules from its collected bytes (state->pending[0..pending_need-1]). */
static tlv_result_t utf8_stream_finish_codepoint(const tlv_asn1_utf8_stream_t* state) {
    uint8_t b0 = state->pending[0];
    uint32_t cp, min_cp;
    size_t k;
    if ((b0 & 0xE0) == 0xC0) {
        cp = (uint32_t)(b0 & 0x1F);
        min_cp = 0x80;
    } else if ((b0 & 0xF0) == 0xE0) {
        cp = (uint32_t)(b0 & 0x0F);
        min_cp = 0x800;
    } else {
        cp = (uint32_t)(b0 & 0x07);
        min_cp = 0x10000;
    }
    for (k = 1; k < state->pending_need; ++k) cp = (cp << 6) | (uint32_t)(state->pending[k] & 0x3F);
    if (cp < min_cp || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF))
        return TLV_ERR_INVALID_VALUE;
    return TLV_OK;
}

tlv_result_t tlv_asn1_utf8_stream_update(tlv_asn1_utf8_stream_t* state, const uint8_t* value,
                                         size_t length) {
    size_t i = 0;
    while (i < length) {
        if (state->pending_need == 0) {
            uint8_t b0 = value[i];
            size_t extra;
            if (b0 < 0x80) {
                ++i;
                continue;
            }
            if ((b0 & 0xE0) == 0xC0)
                extra = 1;
            else if ((b0 & 0xF0) == 0xE0)
                extra = 2;
            else if ((b0 & 0xF8) == 0xF0)
                extra = 3;
            else
                return TLV_ERR_INVALID_VALUE;
            state->pending[0] = b0;
            state->pending_len = 1;
            state->pending_need = 1 + extra;
            ++i;
        } else {
            while (state->pending_len < state->pending_need && i < length) {
                uint8_t b = value[i];
                if ((b & 0xC0) != 0x80) return TLV_ERR_INVALID_VALUE;
                state->pending[state->pending_len++] = b;
                ++i;
            }
            if (state->pending_len == state->pending_need) {
                tlv_result_t rc = utf8_stream_finish_codepoint(state);
                if (rc != TLV_OK) return rc;
                state->pending_len = 0;
                state->pending_need = 0;
            }
        }
    }
    return TLV_OK;
}

tlv_result_t tlv_asn1_utf8_stream_finish(const tlv_asn1_utf8_stream_t* state) {
    return state->pending_need == 0 ? TLV_OK : TLV_ERR_INVALID_VALUE;
}

/* Rejects overlong encodings, surrogate code points, out-of-range code
 * points, and truncated or malformed continuation bytes. */
tlv_result_t tlv_asn1_validate_utf8(const uint8_t* value, size_t length) {
    tlv_asn1_utf8_stream_t state;
    tlv_result_t rc;
    tlv_asn1_utf8_stream_init(&state);
    rc = tlv_asn1_utf8_stream_update(&state, value, length);
    if (rc != TLV_OK) return rc;
    return tlv_asn1_utf8_stream_finish(&state);
}

/* UniversalString: 4-byte big-endian code points, no surrogates. */
tlv_result_t tlv_asn1_validate_universal_string(const uint8_t* value, size_t length) {
    size_t i;
    if (length % 4) return TLV_ERR_INVALID_VALUE;
    for (i = 0; i < length; i += 4) {
        uint32_t cp = ((uint32_t)value[i] << 24) | ((uint32_t)value[i + 1] << 16) |
                      ((uint32_t)value[i + 2] << 8) | (uint32_t)value[i + 3];
        if (cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return TLV_ERR_INVALID_VALUE;
    }
    return TLV_OK;
}

/* BMPString: 2-byte big-endian code units restricted to the Basic
 * Multilingual Plane, so surrogates are never valid. */
tlv_result_t tlv_asn1_validate_bmp_string(const uint8_t* value, size_t length) {
    size_t i;
    if (length % 2) return TLV_ERR_INVALID_VALUE;
    for (i = 0; i < length; i += 2) {
        uint32_t cp = ((uint32_t)value[i] << 8) | (uint32_t)value[i + 1];
        if (cp >= 0xD800 && cp <= 0xDFFF) return TLV_ERR_INVALID_VALUE;
    }
    return TLV_OK;
}

static int is_digit(uint8_t c) {
    return c >= '0' && c <= '9';
}
static int digit_pair(const uint8_t* p) {
    return (p[0] - '0') * 10 + (p[1] - '0');
}

/* Canonical form: exactly "YYMMDDHHMMSSZ" (13 bytes). Calendar validity is
 * range-checked only (e.g. day 01-31); "30 February" is not detected. */
tlv_result_t tlv_asn1_validate_utc_time(const uint8_t* value, size_t length) {
    size_t i;
    int mm, dd, hh, mi, ss;
    if (length != 13) return TLV_ERR_INVALID_VALUE;
    for (i = 0; i < 12; ++i)
        if (!is_digit(value[i])) return TLV_ERR_INVALID_VALUE;
    if (value[12] != 'Z') return TLV_ERR_INVALID_VALUE;
    mm = digit_pair(value + 2);
    dd = digit_pair(value + 4);
    hh = digit_pair(value + 6);
    mi = digit_pair(value + 8);
    ss = digit_pair(value + 10);
    if (mm < 1 || mm > 12 || dd < 1 || dd > 31 || hh > 23 || mi > 59 || ss > 59)
        return TLV_ERR_INVALID_VALUE;
    return TLV_OK;
}

/* Canonical form: "YYYYMMDDHHMMSS" (seconds mandatory), an optional "." plus
 * one or more fractional digits not ending in '0', then a mandatory trailing
 * "Z" (no differential time zones). Calendar validity is range-checked only. */
tlv_result_t tlv_asn1_validate_generalized_time(const uint8_t* value, size_t length) {
    size_t i;
    int mm, dd, hh, mi, ss;
    if (length < 15) return TLV_ERR_INVALID_VALUE;
    for (i = 0; i < 14; ++i)
        if (!is_digit(value[i])) return TLV_ERR_INVALID_VALUE;
    mm = digit_pair(value + 4);
    dd = digit_pair(value + 6);
    hh = digit_pair(value + 8);
    mi = digit_pair(value + 10);
    ss = digit_pair(value + 12);
    if (mm < 1 || mm > 12 || dd < 1 || dd > 31 || hh > 23 || mi > 59 || ss > 59)
        return TLV_ERR_INVALID_VALUE;
    i = 14;
    if (i < length && value[i] == '.') {
        size_t frac_start = ++i;
        while (i < length && is_digit(value[i])) ++i;
        if (i == frac_start) return TLV_ERR_INVALID_VALUE;
        if (value[i - 1] == '0') return TLV_ERR_INVALID_VALUE;
    }
    return (i == length - 1 && value[i] == 'Z') ? TLV_OK : TLV_ERR_INVALID_VALUE;
}

/* Generic TIME's concrete syntax is not reduced to a fixed digit form (see
 * its own doc comment); it only needs to be legal VisibleString content. */
tlv_result_t tlv_asn1_validate_time(const uint8_t* value, size_t length) {
    if (length == 0) return TLV_ERR_INVALID_VALUE;
    return tlv_asn1_validate_visible_string(value, length);
}

tlv_result_t tlv_asn1_validate_date(const uint8_t* value, size_t length) {
    int mm, dd;
    size_t i;
    if (length != 8) return TLV_ERR_INVALID_VALUE;
    for (i = 0; i < 8; ++i)
        if (!is_digit(value[i])) return TLV_ERR_INVALID_VALUE;
    mm = digit_pair(value + 4);
    dd = digit_pair(value + 6);
    return (mm >= 1 && mm <= 12 && dd >= 1 && dd <= 31) ? TLV_OK : TLV_ERR_INVALID_VALUE;
}

tlv_result_t tlv_asn1_validate_time_of_day(const uint8_t* value, size_t length) {
    int hh, mi, ss;
    size_t i;
    if (length != 6) return TLV_ERR_INVALID_VALUE;
    for (i = 0; i < 6; ++i)
        if (!is_digit(value[i])) return TLV_ERR_INVALID_VALUE;
    hh = digit_pair(value);
    mi = digit_pair(value + 2);
    ss = digit_pair(value + 4);
    return (hh <= 23 && mi <= 59 && ss <= 59) ? TLV_OK : TLV_ERR_INVALID_VALUE;
}

tlv_result_t tlv_asn1_validate_date_time(const uint8_t* value, size_t length) {
    if (length != 14) return TLV_ERR_INVALID_VALUE;
    if (tlv_asn1_validate_date(value, 8) != TLV_OK) return TLV_ERR_INVALID_VALUE;
    return tlv_asn1_validate_time_of_day(value + 8, 6);
}

/* Consumes one or more ASCII digits starting at value[*pos], advancing *pos;
 * returns 0 (leaving *pos unchanged) if there is no digit there. */
static int duration_consume_digits(const uint8_t* value, size_t length, size_t* pos) {
    size_t start = *pos;
    while (*pos < length && is_digit(value[*pos])) ++*pos;
    return *pos > start;
}

/* Each date-part component (Y=1, M=2, D=3) and time-part component (H=1,
 * M=2, S=3) must appear in strictly increasing rank, so a single running
 * "highest rank seen so far" per part both enforces fixed component order
 * and rejects a repeated designator. */
tlv_result_t tlv_asn1_validate_duration(const uint8_t* value, size_t length) {
    size_t pos = 0;
    int have_component = 0, in_time_part = 0, date_rank = 0, time_rank = 0;
    if (length == 0) return TLV_ERR_INVALID_VALUE;
    while (pos < length) {
        int has_fraction = 0;
        uint8_t designator;
        int rank;
        if (!in_time_part && value[pos] == 'T') {
            in_time_part = 1;
            ++pos;
            continue;
        }
        if (!duration_consume_digits(value, length, &pos)) return TLV_ERR_INVALID_VALUE;
        if (pos < length && value[pos] == '.') {
            ++pos;
            if (!duration_consume_digits(value, length, &pos)) return TLV_ERR_INVALID_VALUE;
            has_fraction = 1;
        }
        if (pos >= length) return TLV_ERR_INVALID_VALUE; /* digits with no designator */
        designator = value[pos++];
        if (!in_time_part) {
            switch (designator) {
                case 'Y': rank = 1; break;
                case 'M': rank = 2; break;
                case 'D': rank = 3; break;
                default: return TLV_ERR_INVALID_VALUE;
            }
            if (rank <= date_rank) return TLV_ERR_INVALID_VALUE;
            date_rank = rank;
        } else {
            switch (designator) {
                case 'H': rank = 1; break;
                case 'M': rank = 2; break;
                case 'S': rank = 3; break;
                default: return TLV_ERR_INVALID_VALUE;
            }
            if (rank <= time_rank) return TLV_ERR_INVALID_VALUE;
            /* Accept a fractional value only on the seconds component, not
             * on M or H even when one of those is the lowest-order
             * component present (ISO 8601 permits either). */
            if (has_fraction && designator != 'S') return TLV_ERR_INVALID_VALUE;
            time_rank = rank;
        }
        have_component = 1;
    }
    if (in_time_part && time_rank == 0)
        return TLV_ERR_INVALID_VALUE; /* "T" with nothing after it */
    return have_component ? TLV_OK : TLV_ERR_INVALID_VALUE;
}

/* Shared structural check for OID-IRI (absolute) and RELATIVE-OID-IRI (not). */
static tlv_result_t validate_iri_arcs(const uint8_t* value, size_t length, int absolute) {
    size_t i;
    if (length == 0) return TLV_ERR_INVALID_VALUE;
    if (tlv_asn1_validate_utf8(value, length) != TLV_OK) return TLV_ERR_INVALID_VALUE;
    if (absolute ? value[0] != '/' : value[0] == '/') return TLV_ERR_INVALID_VALUE;
    if (value[length - 1] == '/') return TLV_ERR_INVALID_VALUE;
    for (i = 0; i + 1 < length; ++i)
        if (value[i] == '/' && value[i + 1] == '/') return TLV_ERR_INVALID_VALUE;
    return TLV_OK;
}

tlv_result_t tlv_asn1_validate_oid_iri(const uint8_t* value, size_t length) {
    return validate_iri_arcs(value, length, 1);
}

tlv_result_t tlv_asn1_validate_relative_oid_iri(const uint8_t* value, size_t length) {
    return validate_iri_arcs(value, length, 0);
}

tlv_result_t tlv_asn1_validate_universal_value(uint64_t number, const uint8_t* value,
                                               size_t length) {
    switch (number) {
        case 1: return tlv_asn1_validate_boolean(value, length);
        case 2:
        case 10: return tlv_asn1_validate_integer(value, length);
        case 3: return tlv_asn1_validate_bit_string(value, length);
        /* OCTET STRING (4) and the historical string types with no fixed,
         * checkable character repertoire (ObjectDescriptor 7, TeletexString
         * 20, VideotexString 21, GraphicString 25, GeneralString 27) all
         * accept any byte sequence under X.690: their character sets are
         * complex legacy (ISO 2022-based) encodings X.690 places no
         * canonical byte-level restriction on. */
        case 4:
        case 7:
        case 20:
        case 21:
        case 25:
        case 27: return tlv_asn1_validate_octet_string(value, length);
        case 5: return tlv_asn1_validate_null(value, length);
        case 6:
        case 13: return tlv_asn1_validate_oid(value, length);
        case 9: return tlv_asn1_validate_real(value, length);
        case 12: return tlv_asn1_validate_utf8(value, length);
        case 14: return tlv_asn1_validate_time(value, length);
        case 18: return tlv_asn1_validate_numeric_string(value, length);
        case 19: return tlv_asn1_validate_printable_string(value, length);
        case 22: return tlv_asn1_validate_ia5_string(value, length);
        case 23: return tlv_asn1_validate_utc_time(value, length);
        case 24: return tlv_asn1_validate_generalized_time(value, length);
        case 26: return tlv_asn1_validate_visible_string(value, length);
        case 28: return tlv_asn1_validate_universal_string(value, length);
        case 30: return tlv_asn1_validate_bmp_string(value, length);
        case 31: return tlv_asn1_validate_date(value, length);
        case 32: return tlv_asn1_validate_time_of_day(value, length);
        case 33: return tlv_asn1_validate_date_time(value, length);
        case 34: return tlv_asn1_validate_duration(value, length);
        case 35: return tlv_asn1_validate_oid_iri(value, length);
        case 36: return tlv_asn1_validate_relative_oid_iri(value, length);
        default: return TLV_ERR_UNSUPPORTED_TYPE;
    }
}
