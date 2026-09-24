#include "tlv/builtins/asn1/ber.h"
#include "ber_internal.h"
#include "tlv/endian.h"
#include <string.h>
static tlv_result_t read_tag(const void* context, const uint8_t* data, size_t size, tlv_tag_t* tag,
                             size_t* used) {
    /* Universal tag zero is reserved for EOC, never an ordinary element. */
    if (size && (data[0] == 0 || data[0] == TLV_ASN1_CONSTRUCTED_BIT)) return TLV_ERR_INVALID_TAG;
    return tlv_ber_reader_wire.read_tag(context, data, size, tag, used);
}
static tlv_result_t write_tag(const void* context, uint8_t* data, size_t capacity,
                              const tlv_tag_t* tag, size_t* used) {
    if (tag->size && tag->data && (tag->data[0] == 0 || tag->data[0] == TLV_ASN1_CONSTRUCTED_BIT))
        return TLV_ERR_INVALID_TAG;
    return tlv_ber_writer_wire.write_tag(context, data, capacity, tag, used);
}
static tlv_result_t read_length(const void* context, const uint8_t* data, size_t size,
                                size_t* length, size_t* used) {
    return tlv_ber_reader_wire.read_length(context, data, size, length, used);
}
static tlv_result_t write_length(const void* context, uint8_t* data, size_t capacity, size_t length,
                                 size_t* used) {
    return tlv_ber_writer_wire.write_length(context, data, capacity, length, used);
}
static tlv_result_t length_size(const void* context, size_t length, size_t* size) {
    return tlv_ber_writer_wire.length_size(context, length, size);
}
int tlv_ber_is_constructed(const void* context, const tlv_tag_t* tag) {
    (void)context;
    return (tag->data[0] & TLV_ASN1_CONSTRUCTED_BIT) != 0;
}

tlv_result_t tlv_ber_tag_make(tlv_asn1_class_t tag_class, int constructed, uint64_t number,
                              uint8_t* storage, tlv_tag_t* tag) {
    uint8_t bytes[TLV_ASN1_TAG_MAX_SIZE] = {0};
    tlv_tag_t result = tlv_tag(bytes, 1);
    size_t written;
    if (!storage || !tag) return TLV_ERR_NULL_ARG;
    if ((unsigned)tag_class > (unsigned)TLV_ASN1_PRIVATE || (constructed != 0 && constructed != 1))
        return TLV_ERR_INVALID_TAG;
    bytes[0] = (uint8_t)(((unsigned)tag_class << TLV_ASN1_CLASS_SHIFT) |
                         (constructed ? TLV_ASN1_CONSTRUCTED_BIT : 0));
    if (number < TLV_ASN1_LOW_TAG_LIMIT)
        bytes[0] |= (uint8_t)number;
    else {
        uint8_t digits[10];
        size_t count = 0;
        bytes[0] |= TLV_ASN1_TAG_NUMBER_MASK;
        do {
            digits[count++] = (uint8_t)(number & TLV_BER_TAG_DIGIT_MASK);
            number >>= TLV_BER_TAG_DIGIT_BITS;
        } while (number);
        if (count + 1 > TLV_ASN1_TAG_MAX_SIZE) return TLV_ERR_INVALID_TAG_SIZE;
        result.size = count + 1;
        for (size_t i = 0; i < count; ++i)
            bytes[i + 1] = (uint8_t)(digits[count - i - 1] |
                                     (i + 1 < count ? TLV_BER_TAG_DIGIT_CONTINUATION_BIT : 0));
    }
    if (write_tag(NULL, NULL, 0, &result, &written) != TLV_OK) return TLV_ERR_INVALID_TAG;
    memcpy(storage, bytes, result.size);
    *tag = tlv_tag(storage, result.size);
    return TLV_OK;
}

tlv_result_t tlv_ber_tag_number(const tlv_tag_t* tag, uint64_t* number) {
    uint64_t result;
    size_t written;
    tlv_result_t rc;
    if (!tag || !number) return TLV_ERR_NULL_ARG;
    rc = write_tag(NULL, NULL, 0, tag, &written);
    if (rc != TLV_OK) return rc;
    result = tag->data[0] & TLV_ASN1_TAG_NUMBER_MASK;
    if (tag->size > 1) {
        result = 0;
        for (size_t i = 1; i < tag->size; ++i) {
            if (result > (UINT64_MAX >> TLV_BER_TAG_DIGIT_BITS)) return TLV_ERR_INVALID_TAG;
            result = (result << TLV_BER_TAG_DIGIT_BITS) | (tag->data[i] & TLV_BER_TAG_DIGIT_MASK);
        }
    }
    *number = result;
    return TLV_OK;
}

tlv_result_t tlv_ber_scan_contents(const uint8_t* data, size_t size, int indefinite,
                                   size_t* value_size, size_t* consumed) {
    size_t ends[TLV_BER_MAX_DEPTH];
    int terminated[TLV_BER_MAX_DEPTH];
    size_t depth = 1, pos = 0;
    ends[0] = size;
    terminated[0] = indefinite;
    for (;;) {
        size_t limit = ends[depth - 1], tag_size, len_size, length;
        tlv_tag_t tag;
        tlv_result_t rc;
        int child_indefinite, constructed;
        if (pos == limit) {
            if (terminated[depth - 1]) return TLV_ERR_BUFFER_TOO_SHORT;
            if (--depth == 0) {
                *value_size = pos;
                *consumed = pos;
                return TLV_OK;
            }
            continue;
        }
        if (data[pos] == 0) {
            if (limit - pos < TLV_BER_EOC_SIZE) return TLV_ERR_BUFFER_TOO_SHORT;
            if (data[pos + 1] != 0) return TLV_ERR_INVALID_LENGTH;
            if (!terminated[depth - 1]) return TLV_ERR_INVALID_TAG;
            if (--depth == 0) {
                *value_size = pos;
                *consumed = pos + TLV_BER_EOC_SIZE;
                return TLV_OK;
            }
            pos += TLV_BER_EOC_SIZE;
            continue;
        }
        rc = read_tag(NULL, data + pos, limit - pos, &tag, &tag_size);
        if (rc != TLV_OK) return rc;
        pos += tag_size;
        if (pos == limit) return TLV_ERR_BUFFER_TOO_SHORT;
        constructed = tlv_ber_is_constructed(NULL, &tag);
        child_indefinite = data[pos] == TLV_BER_LENGTH_LONG_FORM_BIT;
        if (child_indefinite) {
            if (!constructed) return TLV_ERR_INVALID_LENGTH;
            ++pos;
            length = limit - pos;
        } else {
            rc = read_length(NULL, data + pos, limit - pos, &length, &len_size);
            if (rc != TLV_OK) return rc;
            pos += len_size;
            if (length > limit - pos) return TLV_ERR_BUFFER_TOO_SHORT;
        }
        if (constructed) {
            if (depth == TLV_BER_MAX_DEPTH) return TLV_ERR_LIMIT;
            ends[depth] = pos + length;
            terminated[depth++] = child_indefinite;
        } else
            pos += length;
    }
}

static tlv_result_t read_value_bounds(const void* context, const tlv_tag_t* tag,
                                      const uint8_t* data, size_t size, size_t* len_size,
                                      size_t* value_size, size_t* trailer_size) {
    size_t length, used;
    tlv_result_t rc;
    if (!size) return TLV_ERR_BUFFER_TOO_SHORT;
    if (data[0] != TLV_BER_LENGTH_LONG_FORM_BIT) {
        rc = read_length(context, data, size, &length, &used);
        if (rc != TLV_OK) return rc;
        if (length > size - used) return TLV_ERR_BUFFER_TOO_SHORT;
        *len_size = used;
        *value_size = length;
        *trailer_size = 0;
        return TLV_OK;
    }
    if (!tlv_ber_is_constructed(context, tag)) return TLV_ERR_INVALID_LENGTH;
    rc = tlv_ber_scan_contents(data + 1, size - 1, 1, &length, &used);
    if (rc != TLV_OK) return rc;
    *len_size = TLV_BER_INDEFINITE_LENGTH_OCTET_SIZE;
    *value_size = length;
    *trailer_size = TLV_BER_EOC_SIZE;
    return TLV_OK;
}

const tlv_reader_format_t tlv_reader_format_ber = {.context = NULL,
                                                   .read_tag = read_tag,
                                                   .read_length = read_length,
                                                   .read_value_bounds = read_value_bounds};

tlv_result_t tlv_ber_indefinite_encoded_size(tlv_tag_t tag, size_t length, size_t* size) {
    size_t tag_size;
    tlv_result_t rc;
    if (!size) return TLV_ERR_NULL_ARG;
    rc = write_tag(NULL, NULL, 0, &tag, &tag_size);
    if (rc != TLV_OK) return rc;
    if (!tlv_ber_is_constructed(NULL, &tag)) return TLV_ERR_INVALID_LENGTH;
    if (length > SIZE_MAX - tag_size - (TLV_BER_INDEFINITE_LENGTH_OCTET_SIZE + TLV_BER_EOC_SIZE))
        return TLV_ERR_INVALID_LENGTH;
    *size = tag_size + TLV_BER_INDEFINITE_LENGTH_OCTET_SIZE + length + TLV_BER_EOC_SIZE;
    return TLV_OK;
}

tlv_result_t tlv_ber_write_indefinite(uint8_t* data, size_t capacity, tlv_tag_t tag,
                                      const uint8_t* value, size_t length, size_t* written) {
    size_t total, checked_length, used;
    tlv_result_t rc;
    if ((!data && capacity) || (!value && length) || !written) return TLV_ERR_NULL_ARG;
    rc = tlv_ber_indefinite_encoded_size(tag, length, &total);
    if (rc != TLV_OK) return rc;
    if (capacity < total) return TLV_ERR_BUFFER_TOO_SHORT;
    rc = tlv_ber_scan_contents(value, length, 0, &checked_length, &used);
    if (rc != TLV_OK) return rc;
    // data is non-NULL here. total is always >= 3 (tag_size + 1 end-of-contents flag byte + 2
    // terminator bytes, with tag_size >= 1 for any valid tag), and capacity >= total was just
    // checked above; the only way data could be NULL is capacity == 0 (guarded at function
    // entry), which is smaller than the always-positive total. The analyzer can't fold this
    // across the indirect write_tag() call inside tlv_ber_indefinite_encoded_size(). Left
    // unnamed (not pinned to e.g. unix.cstring.NullArg/core.NullDereference/
    // core.NonNullParamChecker) since which analyzer check fires here depends on the platform
    // libc's memcpy declaration.
    // NOLINTBEGIN
    memcpy(data, tag.data, tag.size);
    data[tag.size] = TLV_BER_LENGTH_LONG_FORM_BIT;
    // NOLINTEND
    if (length) memcpy(data + tag.size + TLV_BER_INDEFINITE_LENGTH_OCTET_SIZE, value, length);
    data[total - TLV_BER_EOC_SIZE] = 0;
    data[total - TLV_BER_EOC_SIZE + 1] = 0;
    *written = total;
    return TLV_OK;
}

tlv_result_t tlv_ber_writer_write_indefinite(tlv_writer_t* writer, tlv_tag_t tag,
                                             const uint8_t* value, size_t length) {
    size_t written;
    tlv_result_t rc;
    if (!writer) return TLV_ERR_NULL_ARG;
    if (writer->format != &tlv_writer_format_ber) return TLV_ERR_INVALID_ARG;
    if (writer->pos > writer->capacity) return TLV_ERR_BUFFER_TOO_SHORT;
    rc = tlv_ber_write_indefinite(writer->buf ? writer->buf + writer->pos : NULL,
                                  writer->capacity - writer->pos, tag, value, length, &written);
    if (rc == TLV_OK) writer->pos += written;
    return rc;
}

const tlv_writer_format_t tlv_writer_format_ber = {.context = NULL,
                                                   .write_tag = write_tag,
                                                   .write_length = write_length,
                                                   .length_size = length_size};

tlv_result_t tlv_ber_length_decode(const uint8_t* data, size_t data_size, tlv_length_t* value,
                                   size_t* consumed) {
    size_t count, offset, width;
    uint64_t decoded;
    if ((!data && data_size) || !value || !consumed) return TLV_ERR_NULL_ARG;
    if (!data_size) return TLV_ERR_BUFFER_TOO_SHORT;
    if (data[0] < TLV_BER_LENGTH_LONG_FORM_BIT) {
        *value = data[0];
        *consumed = 1;
        return TLV_OK;
    }
    /* Indefinite lengths and the reserved FF prefix are unsupported. */
    if (data[0] == TLV_BER_LENGTH_LONG_FORM_BIT || data[0] == TLV_BER_LENGTH_RESERVED_OCTET)
        return TLV_ERR_INVALID_LENGTH;
    count = data[0] & TLV_BER_LENGTH_COUNT_MASK;
    if (data_size - 1 < count) return TLV_ERR_BUFFER_TOO_SHORT;
    /* BER permits padding beyond tlv_length_t's 64-bit width. Validate the
     * complete payload before stripping only excess zero octets. */
    offset = 1;
    width = count;
    while (width > sizeof(uint64_t)) {
        if (data[offset++] != 0) return TLV_ERR_INVALID_LENGTH;
        --width;
    }
    if (tlv_read_uint(data + offset, width, TLV_BYTE_ORDER_BIG_ENDIAN, &decoded) != TLV_OK)
        return TLV_ERR_INVALID_LENGTH;
    *value = decoded;
    *consumed = count + 1;
    return TLV_OK;
}

tlv_result_t tlv_ber_length_encode(tlv_length_t value, uint8_t* out, size_t out_capacity,
                                   size_t* written) {
    size_t count = 1;
    tlv_length_t remaining = value;
    if ((!out && out_capacity) || !written) return TLV_ERR_NULL_ARG;
    if (value >= TLV_BER_LENGTH_LONG_FORM_BIT) {
        do {
            ++count;
            remaining >>= 8;
        } while (remaining);
    }
    if (!out) {
        *written = count;
        return TLV_OK;
    }
    if (out_capacity < count) return TLV_ERR_BUFFER_TOO_SHORT;
    if (count == 1)
        out[0] = (uint8_t)value;
    else {
        out[0] = (uint8_t)(TLV_BER_LENGTH_LONG_FORM_BIT | (count - 1));
        if (tlv_write_uint(out + 1, count - 1, TLV_BYTE_ORDER_BIG_ENDIAN, value) != TLV_OK)
            return TLV_ERR_INVALID_LENGTH;
    }
    *written = count;
    return TLV_OK;
}
