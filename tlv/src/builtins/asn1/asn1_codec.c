#include "tlv/builtins/asn1/asn1_codec.h"
#include "asn1_values_internal.h"
#include <string.h>

/* BOOLEAN: X.690 section 8.2/11.1, canonical content is exactly one byte, 00 or FF. */

static tlv_codec_result_t decode_boolean(const void* context, const uint8_t* data, size_t size,
                                         void* value, size_t capacity) {
    bool result;
    (void)context;
    if (tlv_asn1_validate_boolean(data, size) != TLV_OK) return TLV_CODEC_ERR_INVALID_VALUE;
    if (capacity < sizeof(result)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    result = data[0] != 0x00;
    memcpy(value, &result, sizeof(result));
    return TLV_CODEC_OK;
}

static tlv_codec_result_t encode_boolean(const void* context, const void* value, size_t size,
                                         uint8_t* data, size_t capacity, size_t* written) {
    bool input;
    (void)context;
    if (size != sizeof(input)) return TLV_CODEC_ERR_INVALID_VALUE;
    memcpy(&input, value, sizeof(input));
    if (data) {
        if (capacity < 1) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
        data[0] = input ? 0xFF : 0x00;
    }
    *written = 1;
    return TLV_CODEC_OK;
}

/* INTEGER/ENUMERATED: X.690 section 8.3/8.4/11.2, minimal big-endian two's
 * complement; shared here because both universal types carry identical
 * content rules under section 11.2. */

static int integer_decode_value(const uint8_t* data, size_t size, int64_t* out) {
    uint64_t bits;
    size_t i;
    if (size < 1 || size > sizeof(int64_t)) return 0;
    bits = (data[0] & 0x80) ? ~(uint64_t)0 : 0;
    for (i = 0; i < size; ++i) bits = (bits << 8) | data[i];
    *out = (int64_t)bits;
    return 1;
}

static size_t integer_minimal_size(const uint8_t full[sizeof(int64_t)]) {
    size_t start = 0;
    while (start + 1 < sizeof(int64_t) && ((full[start] == 0x00 && (full[start + 1] & 0x80) == 0) ||
                                           (full[start] == 0xFF && (full[start + 1] & 0x80) != 0)))
        ++start;
    return sizeof(int64_t) - start;
}

static void integer_encode_value(int64_t value, uint8_t full[sizeof(int64_t)]) {
    uint64_t bits = (uint64_t)value;
    size_t i;
    for (i = 0; i < sizeof(int64_t); ++i)
        full[i] = (uint8_t)(bits >> (8 * (sizeof(int64_t) - 1 - i)));
}

static tlv_codec_result_t decode_integer(const void* context, const uint8_t* data, size_t size,
                                         void* value, size_t capacity) {
    int64_t result;
    (void)context;
    if (tlv_asn1_validate_integer(data, size) != TLV_OK) return TLV_CODEC_ERR_INVALID_VALUE;
    if (!integer_decode_value(data, size, &result)) return TLV_CODEC_ERR_INVALID_VALUE;
    if (capacity < sizeof(result)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    memcpy(value, &result, sizeof(result));
    return TLV_CODEC_OK;
}

static tlv_codec_result_t encode_integer(const void* context, const void* value, size_t size,
                                         uint8_t* data, size_t capacity, size_t* written) {
    int64_t input;
    uint8_t full[sizeof(int64_t)];
    size_t minimal_size, offset;
    (void)context;
    if (size != sizeof(input)) return TLV_CODEC_ERR_INVALID_VALUE;
    memcpy(&input, value, sizeof(input));
    integer_encode_value(input, full);
    minimal_size = integer_minimal_size(full);
    offset = sizeof(full) - minimal_size;
    if (data) {
        if (capacity < minimal_size) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
        memcpy(data, full + offset, minimal_size);
    }
    *written = minimal_size;
    return TLV_CODEC_OK;
}

/* BIT STRING: X.690 section 8.6/11.2, leading unused-bits octet plus borrowed
 * content bytes; decode and encode both enforce that the trailing unused
 * bits of the last content byte are clear. */

static tlv_codec_result_t decode_bit_string(const void* context, const uint8_t* data, size_t size,
                                            void* value, size_t capacity) {
    tlv_asn1_bit_string_t result;
    (void)context;
    if (tlv_asn1_validate_bit_string(data, size) != TLV_OK) return TLV_CODEC_ERR_INVALID_VALUE;
    result.unused_bits = data[0];
    result.length = size - 1;
    result.data = result.length ? data + 1 : NULL;
    if (capacity < sizeof(result)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    memcpy(value, &result, sizeof(result));
    return TLV_CODEC_OK;
}

static tlv_codec_result_t encode_bit_string(const void* context, const void* value, size_t size,
                                            uint8_t* data, size_t capacity, size_t* written) {
    tlv_asn1_bit_string_t input;
    size_t count;
    (void)context;
    if (size != sizeof(input)) return TLV_CODEC_ERR_INVALID_VALUE;
    memcpy(&input, value, sizeof(input));
    if (input.unused_bits > 7 || input.length == SIZE_MAX) return TLV_CODEC_ERR_INVALID_VALUE;
    if (input.length == 0) {
        if (input.unused_bits != 0) return TLV_CODEC_ERR_INVALID_VALUE;
    } else {
        uint8_t mask;
        if (!input.data) return TLV_CODEC_ERR_INVALID_VALUE;
        mask = (uint8_t)((1U << input.unused_bits) - 1U);
        if ((input.data[input.length - 1] & mask) != 0) return TLV_CODEC_ERR_INVALID_VALUE;
    }
    count = input.length + 1;
    if (data) {
        if (capacity < count) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
        data[0] = input.unused_bits;
        if (input.length) memcpy(data + 1, input.data, input.length);
    }
    *written = count;
    return TLV_CODEC_OK;
}

/* Named bits: X.680's NamedBitList is purely descriptive, so testing a bit's
 * state and looking up a name by position need no codec of their own. A
 * canonical DER BIT STRING already guarantees any bit beyond its encoded
 * length is (implicitly) clear, so no separate bounds-driven special case is
 * needed beyond the byte-index bounds check itself. */
int tlv_asn1_bit_string_test(const tlv_asn1_bit_string_t* bits, size_t position) {
    size_t byte_index = position / 8;
    uint8_t mask;
    if (byte_index >= bits->length) return 0;
    mask = (uint8_t)(0x80u >> (position % 8));
    return (bits->data[byte_index] & mask) != 0;
}

const char* tlv_asn1_named_bit_find(const tlv_asn1_named_bit_t* names, size_t count,
                                    size_t position) {
    size_t i;
    for (i = 0; i < count; ++i)
        if (names[i].position == position) return names[i].name;
    return NULL;
}

/* OCTET STRING: X.690 section 8.7/11.2, unconstrained borrowed content bytes. */

static tlv_codec_result_t decode_octet_string(const void* context, const uint8_t* data, size_t size,
                                              void* value, size_t capacity) {
    tlv_asn1_octet_string_t result;
    (void)context;
    if (tlv_asn1_validate_octet_string(data, size) != TLV_OK) return TLV_CODEC_ERR_INVALID_VALUE;
    result.data = size ? data : NULL;
    result.length = size;
    if (capacity < sizeof(result)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    memcpy(value, &result, sizeof(result));
    return TLV_CODEC_OK;
}

static tlv_codec_result_t encode_octet_string(const void* context, const void* value, size_t size,
                                              uint8_t* data, size_t capacity, size_t* written) {
    tlv_asn1_octet_string_t input;
    (void)context;
    if (size != sizeof(input)) return TLV_CODEC_ERR_INVALID_VALUE;
    memcpy(&input, value, sizeof(input));
    if (input.length && !input.data) return TLV_CODEC_ERR_INVALID_VALUE;
    if (data) {
        if (capacity < input.length) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
        if (input.length) memcpy(data, input.data, input.length);
    }
    *written = input.length;
    return TLV_CODEC_OK;
}

/* NULL: X.690 section 8.8/11.2, content is always empty; there is nothing to
 * represent, so decode writes nothing and encode reads nothing. */

static tlv_codec_result_t decode_null(const void* context, const uint8_t* data, size_t size,
                                      void* value, size_t capacity) {
    (void)context;
    (void)value;
    (void)capacity;
    if (tlv_asn1_validate_null(data, size) != TLV_OK) return TLV_CODEC_ERR_INVALID_VALUE;
    return TLV_CODEC_OK;
}

static tlv_codec_result_t encode_null(const void* context, const void* value, size_t size,
                                      uint8_t* data, size_t capacity, size_t* written) {
    (void)context;
    (void)value;
    (void)size;
    (void)data;
    (void)capacity;
    *written = 0;
    return TLV_CODEC_OK;
}

/* OBJECT IDENTIFIER/RELATIVE-OID: X.690 section 8.19/8.20/11.3, base-128
 * subidentifiers. OBJECT IDENTIFIER's first subidentifier combines the first
 * two arcs (section 8.19.4); RELATIVE-OID has no such combining. */

enum { ASN1_OID_ARC_MAX_ENCODED_BYTES = 10 }; /* ceil(64/7) base-128 groups for a uint64_t arc */

static int decode_oid_subidentifiers(const uint8_t* data, size_t size, uint64_t* raw,
                                     size_t max_raw, size_t* raw_count) {
    size_t i = 0, n = 0;
    while (i < size) {
        uint64_t arc = 0;
        uint8_t byte;
        do {
            byte = data[i++];
            if (arc > (UINT64_MAX >> 7)) return 0;
            arc = (arc << 7) | (uint64_t)(byte & 0x7F);
        } while (byte & 0x80);
        if (n >= max_raw) return 0;
        raw[n++] = arc;
    }
    *raw_count = n;
    return 1;
}

static tlv_codec_result_t decode_oid_like(int is_oid, const uint8_t* data, size_t size, void* value,
                                          size_t capacity) {
    uint64_t raw[TLV_ASN1_OID_MAX_ARCS];
    size_t raw_count, max_raw, i;
    tlv_asn1_oid_t result;
    if (tlv_asn1_validate_oid(data, size) != TLV_OK) return TLV_CODEC_ERR_INVALID_VALUE;
    max_raw = is_oid ? TLV_ASN1_OID_MAX_ARCS - 1 : TLV_ASN1_OID_MAX_ARCS;
    if (!decode_oid_subidentifiers(data, size, raw, max_raw, &raw_count))
        return TLV_CODEC_ERR_INVALID_VALUE;
    memset(&result, 0, sizeof(result));
    if (is_oid) {
        uint64_t first = raw[0];
        if (first < 40) {
            result.arcs[0] = 0;
            result.arcs[1] = first;
        } else if (first < 80) {
            result.arcs[0] = 1;
            result.arcs[1] = first - 40;
        } else {
            result.arcs[0] = 2;
            result.arcs[1] = first - 80;
        }
        for (i = 1; i < raw_count; ++i) result.arcs[i + 1] = raw[i];
        result.count = raw_count + 1;
    } else {
        for (i = 0; i < raw_count; ++i) result.arcs[i] = raw[i];
        result.count = raw_count;
    }
    if (capacity < sizeof(result)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    memcpy(value, &result, sizeof(result));
    return TLV_CODEC_OK;
}

static tlv_codec_result_t decode_oid(const void* context, const uint8_t* data, size_t size,
                                     void* value, size_t capacity) {
    (void)context;
    return decode_oid_like(1, data, size, value, capacity);
}

static tlv_codec_result_t decode_relative_oid(const void* context, const uint8_t* data, size_t size,
                                              void* value, size_t capacity) {
    (void)context;
    return decode_oid_like(0, data, size, value, capacity);
}

/* Writes one arc's minimal base-128 encoding; out may be NULL to only size it. */
static size_t encode_oid_arc(uint64_t arc, uint8_t* out) {
    uint8_t groups[ASN1_OID_ARC_MAX_ENCODED_BYTES];
    size_t n = 0, i;
    do {
        groups[n++] = (uint8_t)(arc & 0x7F);
        arc >>= 7;
    } while (arc);
    if (out)
        for (i = 0; i < n; ++i) out[i] = (uint8_t)(groups[n - 1 - i] | (i + 1 < n ? 0x80 : 0x00));
    return n;
}

static tlv_codec_result_t encode_oid_like(int is_oid, const void* value, size_t size, uint8_t* data,
                                          size_t capacity, size_t* written) {
    tlv_asn1_oid_t input;
    uint64_t raw[TLV_ASN1_OID_MAX_ARCS];
    size_t raw_count, i, total = 0;
    if (size != sizeof(input)) return TLV_CODEC_ERR_INVALID_VALUE;
    memcpy(&input, value, sizeof(input));
    if (is_oid) {
        if (input.count < 2 || input.count > TLV_ASN1_OID_MAX_ARCS)
            return TLV_CODEC_ERR_INVALID_VALUE;
        if (input.arcs[0] > 2) return TLV_CODEC_ERR_INVALID_VALUE;
        if (input.arcs[0] < 2 && input.arcs[1] >= 40) return TLV_CODEC_ERR_INVALID_VALUE;
        if (input.arcs[0] == 2 && input.arcs[1] > UINT64_MAX - 80)
            return TLV_CODEC_ERR_INVALID_VALUE;
        raw[0] = input.arcs[0] * 40 + input.arcs[1];
        for (i = 2; i < input.count; ++i) raw[i - 1] = input.arcs[i];
        raw_count = input.count - 1;
    } else {
        if (input.count < 1 || input.count > TLV_ASN1_OID_MAX_ARCS)
            return TLV_CODEC_ERR_INVALID_VALUE;
        for (i = 0; i < input.count; ++i) raw[i] = input.arcs[i];
        raw_count = input.count;
    }
    for (i = 0; i < raw_count; ++i) total += encode_oid_arc(raw[i], NULL);
    if (data) {
        size_t offset = 0;
        if (capacity < total) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
        for (i = 0; i < raw_count; ++i) offset += encode_oid_arc(raw[i], data + offset);
    }
    *written = total;
    return TLV_CODEC_OK;
}

static tlv_codec_result_t encode_oid(const void* context, const void* value, size_t size,
                                     uint8_t* data, size_t capacity, size_t* written) {
    (void)context;
    return encode_oid_like(1, value, size, data, capacity, written);
}

static tlv_codec_result_t encode_relative_oid(const void* context, const void* value, size_t size,
                                              uint8_t* data, size_t capacity, size_t* written) {
    (void)context;
    return encode_oid_like(0, value, size, data, capacity, written);
}

/* Restricted character strings: X.690 section 8.23, unconstrained borrowed
 * content bytes whose charset each codec's validator restricts; no extra
 * canonical (clause 11) rule beyond that charset. */

typedef tlv_result_t (*string_validator_t)(const uint8_t*, size_t);

static tlv_codec_result_t decode_string(string_validator_t validate, const uint8_t* data,
                                        size_t size, void* value, size_t capacity) {
    tlv_asn1_string_t result;
    if (validate(data, size) != TLV_OK) return TLV_CODEC_ERR_INVALID_VALUE;
    result.data = size ? data : NULL;
    result.length = size;
    if (capacity < sizeof(result)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    memcpy(value, &result, sizeof(result));
    return TLV_CODEC_OK;
}

static tlv_codec_result_t encode_string(string_validator_t validate, const void* value, size_t size,
                                        uint8_t* data, size_t capacity, size_t* written) {
    tlv_asn1_string_t input;
    if (size != sizeof(input)) return TLV_CODEC_ERR_INVALID_VALUE;
    memcpy(&input, value, sizeof(input));
    if (input.length && !input.data) return TLV_CODEC_ERR_INVALID_VALUE;
    if (validate(input.data, input.length) != TLV_OK) return TLV_CODEC_ERR_INVALID_VALUE;
    if (data) {
        if (capacity < input.length) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
        if (input.length) memcpy(data, input.data, input.length);
    }
    *written = input.length;
    return TLV_CODEC_OK;
}

#define ASN1_STRING_CODEC(name, validator)                                                         \
    static tlv_codec_result_t decode_##name(const void* context, const uint8_t* data, size_t size, \
                                            void* value, size_t capacity) {                        \
        (void)context;                                                                             \
        return decode_string(validator, data, size, value, capacity);                              \
    }                                                                                              \
    static tlv_codec_result_t encode_##name(const void* context, const void* value, size_t size,   \
                                            uint8_t* data, size_t capacity, size_t* written) {     \
        (void)context;                                                                             \
        return encode_string(validator, value, size, data, capacity, written);                     \
    }

ASN1_STRING_CODEC(utf8_string, tlv_asn1_validate_utf8)
ASN1_STRING_CODEC(numeric_string, tlv_asn1_validate_numeric_string)
ASN1_STRING_CODEC(printable_string, tlv_asn1_validate_printable_string)
ASN1_STRING_CODEC(ia5_string, tlv_asn1_validate_ia5_string)
ASN1_STRING_CODEC(visible_string, tlv_asn1_validate_visible_string)

#undef ASN1_STRING_CODEC

/* BMPString/UniversalString: X.690 section 8.23, fixed-width big-endian code
 * units/points; the representation borrows the raw content bytes unchanged,
 * so decode and encode share the same shape as the string codecs above but
 * with a code-unit count instead of a byte length. */

static tlv_codec_result_t decode_bmp_string(const void* context, const uint8_t* data, size_t size,
                                            void* value, size_t capacity) {
    tlv_asn1_bmp_string_t result;
    (void)context;
    if (tlv_asn1_validate_bmp_string(data, size) != TLV_OK) return TLV_CODEC_ERR_INVALID_VALUE;
    result.data = size ? data : NULL;
    result.length = size / 2;
    if (capacity < sizeof(result)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    memcpy(value, &result, sizeof(result));
    return TLV_CODEC_OK;
}

static tlv_codec_result_t encode_bmp_string(const void* context, const void* value, size_t size,
                                            uint8_t* data, size_t capacity, size_t* written) {
    tlv_asn1_bmp_string_t input;
    size_t byte_length;
    (void)context;
    if (size != sizeof(input)) return TLV_CODEC_ERR_INVALID_VALUE;
    memcpy(&input, value, sizeof(input));
    if (input.length && !input.data) return TLV_CODEC_ERR_INVALID_VALUE;
    if (input.length > SIZE_MAX / 2) return TLV_CODEC_ERR_INVALID_VALUE;
    byte_length = input.length * 2;
    if (tlv_asn1_validate_bmp_string(input.data, byte_length) != TLV_OK)
        return TLV_CODEC_ERR_INVALID_VALUE;
    if (data) {
        if (capacity < byte_length) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
        if (byte_length) memcpy(data, input.data, byte_length);
    }
    *written = byte_length;
    return TLV_CODEC_OK;
}

static tlv_codec_result_t decode_universal_string(const void* context, const uint8_t* data,
                                                  size_t size, void* value, size_t capacity) {
    tlv_asn1_universal_string_t result;
    (void)context;
    if (tlv_asn1_validate_universal_string(data, size) != TLV_OK)
        return TLV_CODEC_ERR_INVALID_VALUE;
    result.data = size ? data : NULL;
    result.length = size / 4;
    if (capacity < sizeof(result)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    memcpy(value, &result, sizeof(result));
    return TLV_CODEC_OK;
}

static tlv_codec_result_t encode_universal_string(const void* context, const void* value,
                                                  size_t size, uint8_t* data, size_t capacity,
                                                  size_t* written) {
    tlv_asn1_universal_string_t input;
    size_t byte_length;
    (void)context;
    if (size != sizeof(input)) return TLV_CODEC_ERR_INVALID_VALUE;
    memcpy(&input, value, sizeof(input));
    if (input.length && !input.data) return TLV_CODEC_ERR_INVALID_VALUE;
    if (input.length > SIZE_MAX / 4) return TLV_CODEC_ERR_INVALID_VALUE;
    byte_length = input.length * 4;
    if (tlv_asn1_validate_universal_string(input.data, byte_length) != TLV_OK)
        return TLV_CODEC_ERR_INVALID_VALUE;
    if (data) {
        if (capacity < byte_length) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
        if (byte_length) memcpy(data, input.data, byte_length);
    }
    *written = byte_length;
    return TLV_CODEC_OK;
}

/* UTCTime/GeneralizedTime: X.690 section 8.26/11.7/11.8, digit-string
 * calendar timestamps. Both validators already enforce the exact canonical
 * digit layout, so decoding here only ever parses digits '0'-'9'. */

static uint8_t time_digit_pair(const uint8_t* p) {
    return (uint8_t)((p[0] - '0') * 10 + (p[1] - '0'));
}

static void time_write_digit_pair(uint8_t* p, uint8_t value) {
    p[0] = (uint8_t)('0' + value / 10);
    p[1] = (uint8_t)('0' + value % 10);
}

static tlv_codec_result_t decode_utc_time(const void* context, const uint8_t* data, size_t size,
                                          void* value, size_t capacity) {
    tlv_asn1_utc_time_t result;
    uint8_t yy;
    (void)context;
    if (tlv_asn1_validate_utc_time(data, size) != TLV_OK) return TLV_CODEC_ERR_INVALID_VALUE;
    yy = time_digit_pair(data);
    result.year = (int32_t)(yy < 50 ? 2000 + yy : 1900 + yy);
    result.month = time_digit_pair(data + 2);
    result.day = time_digit_pair(data + 4);
    result.hour = time_digit_pair(data + 6);
    result.minute = time_digit_pair(data + 8);
    result.second = time_digit_pair(data + 10);
    if (capacity < sizeof(result)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    memcpy(value, &result, sizeof(result));
    return TLV_CODEC_OK;
}

static int time_calendar_fields_valid(uint8_t month, uint8_t day, uint8_t hour, uint8_t minute,
                                      uint8_t second) {
    return month >= 1 && month <= 12 && day >= 1 && day <= 31 && hour <= 23 && minute <= 59 &&
           second <= 59;
}

static tlv_codec_result_t encode_utc_time(const void* context, const void* value, size_t size,
                                          uint8_t* data, size_t capacity, size_t* written) {
    tlv_asn1_utc_time_t input;
    uint8_t buf[13];
    (void)context;
    if (size != sizeof(input)) return TLV_CODEC_ERR_INVALID_VALUE;
    memcpy(&input, value, sizeof(input));
    if (input.year < 1950 || input.year > 2049) return TLV_CODEC_ERR_INVALID_VALUE;
    if (!time_calendar_fields_valid(input.month, input.day, input.hour, input.minute, input.second))
        return TLV_CODEC_ERR_INVALID_VALUE;
    time_write_digit_pair(buf,
                          (uint8_t)(input.year >= 2000 ? input.year - 2000 : input.year - 1900));
    time_write_digit_pair(buf + 2, input.month);
    time_write_digit_pair(buf + 4, input.day);
    time_write_digit_pair(buf + 6, input.hour);
    time_write_digit_pair(buf + 8, input.minute);
    time_write_digit_pair(buf + 10, input.second);
    buf[12] = 'Z';
    if (data) {
        if (capacity < sizeof(buf)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
        memcpy(data, buf, sizeof(buf));
    }
    *written = sizeof(buf);
    return TLV_CODEC_OK;
}

static tlv_codec_result_t decode_generalized_time(const void* context, const uint8_t* data,
                                                  size_t size, void* value, size_t capacity) {
    tlv_asn1_generalized_time_t result;
    (void)context;
    if (tlv_asn1_validate_generalized_time(data, size) != TLV_OK)
        return TLV_CODEC_ERR_INVALID_VALUE;
    result.year = (int32_t)(time_digit_pair(data) * 100 + time_digit_pair(data + 2));
    result.month = time_digit_pair(data + 4);
    result.day = time_digit_pair(data + 6);
    result.hour = time_digit_pair(data + 8);
    result.minute = time_digit_pair(data + 10);
    result.second = time_digit_pair(data + 12);
    if (size > 15) {
        result.fraction_digits = data + 15;
        result.fraction_digits_length = size - 16;
    } else {
        result.fraction_digits = NULL;
        result.fraction_digits_length = 0;
    }
    if (capacity < sizeof(result)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    memcpy(value, &result, sizeof(result));
    return TLV_CODEC_OK;
}

static tlv_codec_result_t encode_generalized_time(const void* context, const void* value,
                                                  size_t size, uint8_t* data, size_t capacity,
                                                  size_t* written) {
    tlv_asn1_generalized_time_t input;
    uint8_t buf[14];
    size_t total, i;
    (void)context;
    if (size != sizeof(input)) return TLV_CODEC_ERR_INVALID_VALUE;
    memcpy(&input, value, sizeof(input));
    if (input.year < 0 || input.year > 9999) return TLV_CODEC_ERR_INVALID_VALUE;
    if (!time_calendar_fields_valid(input.month, input.day, input.hour, input.minute, input.second))
        return TLV_CODEC_ERR_INVALID_VALUE;
    if ((input.fraction_digits_length == 0) != (input.fraction_digits == NULL))
        return TLV_CODEC_ERR_INVALID_VALUE;
    for (i = 0; i < input.fraction_digits_length; ++i)
        if (input.fraction_digits[i] < '0' || input.fraction_digits[i] > '9')
            return TLV_CODEC_ERR_INVALID_VALUE;
    if (input.fraction_digits_length &&
        input.fraction_digits[input.fraction_digits_length - 1] == '0')
        return TLV_CODEC_ERR_INVALID_VALUE;
    time_write_digit_pair(buf, (uint8_t)(input.year / 100));
    time_write_digit_pair(buf + 2, (uint8_t)(input.year % 100));
    time_write_digit_pair(buf + 4, input.month);
    time_write_digit_pair(buf + 6, input.day);
    time_write_digit_pair(buf + 8, input.hour);
    time_write_digit_pair(buf + 10, input.minute);
    time_write_digit_pair(buf + 12, input.second);
    total = sizeof(buf) + (input.fraction_digits_length ? 1 + input.fraction_digits_length : 0) + 1;
    if (data) {
        size_t offset = sizeof(buf);
        if (capacity < total) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
        memcpy(data, buf, sizeof(buf));
        if (input.fraction_digits_length) {
            data[offset++] = '.';
            memcpy(data + offset, input.fraction_digits, input.fraction_digits_length);
            offset += input.fraction_digits_length;
        }
        data[offset] = 'Z';
    }
    *written = total;
    return TLV_CODEC_OK;
}

/* Generic TIME/DURATION: like the restricted character strings above, these
 * store validated raw content bytes; TIME's own doc comment explains why its
 * check is a VisibleString charset check rather than a fuller ISO 8601
 * canonical-form grammar, and DURATION's explains its documented scope. */

#define ASN1_STRING_CODEC(name, validator)                                                         \
    static tlv_codec_result_t decode_##name(const void* context, const uint8_t* data, size_t size, \
                                            void* value, size_t capacity) {                        \
        (void)context;                                                                             \
        return decode_string(validator, data, size, value, capacity);                              \
    }                                                                                              \
    static tlv_codec_result_t encode_##name(const void* context, const void* value, size_t size,   \
                                            uint8_t* data, size_t capacity, size_t* written) {     \
        (void)context;                                                                             \
        return encode_string(validator, value, size, data, capacity, written);                     \
    }

ASN1_STRING_CODEC(time, tlv_asn1_validate_time)
ASN1_STRING_CODEC(duration, tlv_asn1_validate_duration)

#undef ASN1_STRING_CODEC

/* DATE/TIME-OF-DAY/DATE-TIME: X.690, plain digit-string ISO 8601 basic forms
 * with no separators. Reuses UTCTime/GeneralizedTime's digit-pair helpers. */

static tlv_codec_result_t decode_date(const void* context, const uint8_t* data, size_t size,
                                      void* value, size_t capacity) {
    tlv_asn1_date_t result;
    (void)context;
    if (tlv_asn1_validate_date(data, size) != TLV_OK) return TLV_CODEC_ERR_INVALID_VALUE;
    result.year = (int32_t)(time_digit_pair(data) * 100 + time_digit_pair(data + 2));
    result.month = time_digit_pair(data + 4);
    result.day = time_digit_pair(data + 6);
    if (capacity < sizeof(result)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    memcpy(value, &result, sizeof(result));
    return TLV_CODEC_OK;
}

static tlv_codec_result_t encode_date(const void* context, const void* value, size_t size,
                                      uint8_t* data, size_t capacity, size_t* written) {
    tlv_asn1_date_t input;
    uint8_t buf[8];
    (void)context;
    if (size != sizeof(input)) return TLV_CODEC_ERR_INVALID_VALUE;
    memcpy(&input, value, sizeof(input));
    if (input.year < 0 || input.year > 9999) return TLV_CODEC_ERR_INVALID_VALUE;
    if (input.month < 1 || input.month > 12 || input.day < 1 || input.day > 31)
        return TLV_CODEC_ERR_INVALID_VALUE;
    time_write_digit_pair(buf, (uint8_t)(input.year / 100));
    time_write_digit_pair(buf + 2, (uint8_t)(input.year % 100));
    time_write_digit_pair(buf + 4, input.month);
    time_write_digit_pair(buf + 6, input.day);
    if (data) {
        if (capacity < sizeof(buf)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
        memcpy(data, buf, sizeof(buf));
    }
    *written = sizeof(buf);
    return TLV_CODEC_OK;
}

static tlv_codec_result_t decode_time_of_day(const void* context, const uint8_t* data, size_t size,
                                             void* value, size_t capacity) {
    tlv_asn1_time_of_day_t result;
    (void)context;
    if (tlv_asn1_validate_time_of_day(data, size) != TLV_OK) return TLV_CODEC_ERR_INVALID_VALUE;
    result.hour = time_digit_pair(data);
    result.minute = time_digit_pair(data + 2);
    result.second = time_digit_pair(data + 4);
    if (capacity < sizeof(result)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    memcpy(value, &result, sizeof(result));
    return TLV_CODEC_OK;
}

static tlv_codec_result_t encode_time_of_day(const void* context, const void* value, size_t size,
                                             uint8_t* data, size_t capacity, size_t* written) {
    tlv_asn1_time_of_day_t input;
    uint8_t buf[6];
    (void)context;
    if (size != sizeof(input)) return TLV_CODEC_ERR_INVALID_VALUE;
    memcpy(&input, value, sizeof(input));
    if (input.hour > 23 || input.minute > 59 || input.second > 59)
        return TLV_CODEC_ERR_INVALID_VALUE;
    time_write_digit_pair(buf, input.hour);
    time_write_digit_pair(buf + 2, input.minute);
    time_write_digit_pair(buf + 4, input.second);
    if (data) {
        if (capacity < sizeof(buf)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
        memcpy(data, buf, sizeof(buf));
    }
    *written = sizeof(buf);
    return TLV_CODEC_OK;
}

static tlv_codec_result_t decode_date_time(const void* context, const uint8_t* data, size_t size,
                                           void* value, size_t capacity) {
    tlv_asn1_date_time_t result;
    (void)context;
    if (tlv_asn1_validate_date_time(data, size) != TLV_OK) return TLV_CODEC_ERR_INVALID_VALUE;
    result.year = (int32_t)(time_digit_pair(data) * 100 + time_digit_pair(data + 2));
    result.month = time_digit_pair(data + 4);
    result.day = time_digit_pair(data + 6);
    result.hour = time_digit_pair(data + 8);
    result.minute = time_digit_pair(data + 10);
    result.second = time_digit_pair(data + 12);
    if (capacity < sizeof(result)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    memcpy(value, &result, sizeof(result));
    return TLV_CODEC_OK;
}

static tlv_codec_result_t encode_date_time(const void* context, const void* value, size_t size,
                                           uint8_t* data, size_t capacity, size_t* written) {
    tlv_asn1_date_time_t input;
    uint8_t buf[14];
    (void)context;
    if (size != sizeof(input)) return TLV_CODEC_ERR_INVALID_VALUE;
    memcpy(&input, value, sizeof(input));
    if (input.year < 0 || input.year > 9999) return TLV_CODEC_ERR_INVALID_VALUE;
    if (!time_calendar_fields_valid(input.month, input.day, input.hour, input.minute, input.second))
        return TLV_CODEC_ERR_INVALID_VALUE;
    time_write_digit_pair(buf, (uint8_t)(input.year / 100));
    time_write_digit_pair(buf + 2, (uint8_t)(input.year % 100));
    time_write_digit_pair(buf + 4, input.month);
    time_write_digit_pair(buf + 6, input.day);
    time_write_digit_pair(buf + 8, input.hour);
    time_write_digit_pair(buf + 10, input.minute);
    time_write_digit_pair(buf + 12, input.second);
    if (data) {
        if (capacity < sizeof(buf)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
        memcpy(data, buf, sizeof(buf));
    }
    *written = sizeof(buf);
    return TLV_CODEC_OK;
}

/* OID-IRI/RELATIVE-OID-IRI: X.690 section 8.21/8.22, UTF8-encoded
 * '/'-separated arc labels; OID-IRI's content begins with '/' (absolute),
 * RELATIVE-OID-IRI's does not. Decode splits content into borrowed per-arc
 * spans; encode joins them back with '/' separators, adding OID-IRI's
 * leading '/'. */

static tlv_codec_result_t decode_iri_like(int absolute, const uint8_t* data, size_t size,
                                          void* value, size_t capacity) {
    tlv_asn1_iri_t result;
    size_t pos, arc_start;
    tlv_result_t rc = absolute ? tlv_asn1_validate_oid_iri(data, size)
                               : tlv_asn1_validate_relative_oid_iri(data, size);
    if (rc != TLV_OK) return TLV_CODEC_ERR_INVALID_VALUE;
    memset(&result, 0, sizeof(result));
    pos = absolute ? 1 : 0; /* skip the leading '/' the validator already confirmed */
    arc_start = pos;
    while (pos <= size) {
        if (pos == size || data[pos] == '/') {
            if (result.count >= TLV_ASN1_IRI_MAX_ARCS) return TLV_CODEC_ERR_INVALID_VALUE;
            result.arcs[result.count].data = data + arc_start;
            result.arcs[result.count].length = pos - arc_start;
            ++result.count;
            arc_start = pos + 1;
        }
        ++pos;
    }
    if (capacity < sizeof(result)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    memcpy(value, &result, sizeof(result));
    return TLV_CODEC_OK;
}

static tlv_codec_result_t decode_oid_iri(const void* context, const uint8_t* data, size_t size,
                                         void* value, size_t capacity) {
    (void)context;
    return decode_iri_like(1, data, size, value, capacity);
}

static tlv_codec_result_t decode_relative_oid_iri(const void* context, const uint8_t* data,
                                                  size_t size, void* value, size_t capacity) {
    (void)context;
    return decode_iri_like(0, data, size, value, capacity);
}

static tlv_codec_result_t encode_iri_like(int absolute, const void* value, size_t size,
                                          uint8_t* data, size_t capacity, size_t* written) {
    tlv_asn1_iri_t input;
    size_t i, total = 0;
    if (size != sizeof(input)) return TLV_CODEC_ERR_INVALID_VALUE;
    memcpy(&input, value, sizeof(input));
    if (input.count == 0 || input.count > TLV_ASN1_IRI_MAX_ARCS) return TLV_CODEC_ERR_INVALID_VALUE;
    if (absolute) total += 1;
    for (i = 0; i < input.count; ++i) {
        size_t j;
        if (!input.arcs[i].length || !input.arcs[i].data) return TLV_CODEC_ERR_INVALID_VALUE;
        if (tlv_asn1_validate_utf8(input.arcs[i].data, input.arcs[i].length) != TLV_OK)
            return TLV_CODEC_ERR_INVALID_VALUE;
        for (j = 0; j < input.arcs[i].length; ++j)
            if (input.arcs[i].data[j] == '/') return TLV_CODEC_ERR_INVALID_VALUE;
        total += input.arcs[i].length;
        if (i + 1 < input.count) total += 1;
    }
    if (data) {
        size_t offset = 0;
        if (capacity < total) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
        if (absolute) data[offset++] = '/';
        for (i = 0; i < input.count; ++i) {
            memcpy(data + offset, input.arcs[i].data, input.arcs[i].length);
            offset += input.arcs[i].length;
            if (i + 1 < input.count) data[offset++] = '/';
        }
    }
    *written = total;
    return TLV_CODEC_OK;
}

static tlv_codec_result_t encode_oid_iri(const void* context, const void* value, size_t size,
                                         uint8_t* data, size_t capacity, size_t* written) {
    (void)context;
    return encode_iri_like(1, value, size, data, capacity, written);
}

static tlv_codec_result_t encode_relative_oid_iri(const void* context, const void* value,
                                                  size_t size, uint8_t* data, size_t capacity,
                                                  size_t* written) {
    (void)context;
    return encode_iri_like(0, value, size, data, capacity, written);
}

const tlv_codec_t tlv_asn1_codec_boolean = {NULL, decode_boolean, encode_boolean};
const tlv_codec_t tlv_asn1_codec_integer = {NULL, decode_integer, encode_integer};
const tlv_codec_t tlv_asn1_codec_enumerated = {NULL, decode_integer, encode_integer};
const tlv_codec_t tlv_asn1_codec_bit_string = {NULL, decode_bit_string, encode_bit_string};
const tlv_codec_t tlv_asn1_codec_octet_string = {NULL, decode_octet_string, encode_octet_string};
const tlv_codec_t tlv_asn1_codec_null = {NULL, decode_null, encode_null};
const tlv_codec_t tlv_asn1_codec_oid = {NULL, decode_oid, encode_oid};
const tlv_codec_t tlv_asn1_codec_relative_oid = {NULL, decode_relative_oid, encode_relative_oid};
const tlv_codec_t tlv_asn1_codec_utf8_string = {NULL, decode_utf8_string, encode_utf8_string};
const tlv_codec_t tlv_asn1_codec_numeric_string = {NULL, decode_numeric_string,
                                                   encode_numeric_string};
const tlv_codec_t tlv_asn1_codec_printable_string = {NULL, decode_printable_string,
                                                     encode_printable_string};
const tlv_codec_t tlv_asn1_codec_ia5_string = {NULL, decode_ia5_string, encode_ia5_string};
const tlv_codec_t tlv_asn1_codec_visible_string = {NULL, decode_visible_string,
                                                   encode_visible_string};
const tlv_codec_t tlv_asn1_codec_bmp_string = {NULL, decode_bmp_string, encode_bmp_string};
const tlv_codec_t tlv_asn1_codec_universal_string = {NULL, decode_universal_string,
                                                     encode_universal_string};
const tlv_codec_t tlv_asn1_codec_utc_time = {NULL, decode_utc_time, encode_utc_time};
const tlv_codec_t tlv_asn1_codec_generalized_time = {NULL, decode_generalized_time,
                                                     encode_generalized_time};
const tlv_codec_t tlv_asn1_codec_object_descriptor = {NULL, decode_octet_string,
                                                      encode_octet_string};
const tlv_codec_t tlv_asn1_codec_teletex_string = {NULL, decode_octet_string, encode_octet_string};
const tlv_codec_t tlv_asn1_codec_videotex_string = {NULL, decode_octet_string, encode_octet_string};
const tlv_codec_t tlv_asn1_codec_graphic_string = {NULL, decode_octet_string, encode_octet_string};
const tlv_codec_t tlv_asn1_codec_general_string = {NULL, decode_octet_string, encode_octet_string};
const tlv_codec_t tlv_asn1_codec_time = {NULL, decode_time, encode_time};
const tlv_codec_t tlv_asn1_codec_date = {NULL, decode_date, encode_date};
const tlv_codec_t tlv_asn1_codec_time_of_day = {NULL, decode_time_of_day, encode_time_of_day};
const tlv_codec_t tlv_asn1_codec_date_time = {NULL, decode_date_time, encode_date_time};
const tlv_codec_t tlv_asn1_codec_duration = {NULL, decode_duration, encode_duration};
const tlv_codec_t tlv_asn1_codec_oid_iri = {NULL, decode_oid_iri, encode_oid_iri};
const tlv_codec_t tlv_asn1_codec_relative_oid_iri = {NULL, decode_relative_oid_iri,
                                                     encode_relative_oid_iri};
