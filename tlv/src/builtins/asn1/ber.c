#include "tlv/size.h"
#include "tlv/layout.h"
#include "tlv/builtins/asn1/ber.h"
#include "ber_internal.h"
#include <string.h>
static tlv_result_t read_tag(const void* context, const uint8_t* data, size_t size, tlv_tag_t* tag,
                             size_t* used) {
    /* Universal tag zero is reserved for EOC, never an ordinary element. */
    if (size && (data[0] == 0 || data[0] == TLV_ASN1_CONSTRUCTED_BIT)) return TLV_ERR_INVALID_TAG;
    return tlv_ber_wire.read_tag(context, data, size, tag, used);
}

static tlv_result_t write_tag(const void* context, uint8_t* data, size_t capacity,
                              const tlv_tag_t* tag, size_t* used) {
    if (tag->size && tag->data && (tag->data[0] == 0 || tag->data[0] == TLV_ASN1_CONSTRUCTED_BIT))
        return TLV_ERR_INVALID_TAG;
    return tlv_ber_wire.write_tag(context, data, capacity, tag, used);
}

static tlv_result_t read_length(const void* context, const uint8_t* data, size_t size,
                                tlv_size_t* length, size_t* used) {
    return tlv_ber_wire.read_length(context, data, size, length, used);
}

static tlv_result_t write_length(const void* context, uint8_t* data, size_t capacity,
                                 tlv_size_t length, size_t* used) {
    return tlv_ber_wire.write_length(context, data, capacity, length, used);
}

static tlv_result_t length_size(const void* context, tlv_size_t length, size_t* size) {
    return tlv_ber_wire.length_size(context, length, size);
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

static tlv_result_t scan_failure(tlv_format_error_t* error, tlv_result_t code, size_t offset,
                                 tlv_region_t region) {
    if (error) {
        error->region = region;
        error->offset = offset;
        error->has_offset = 1;
    }
    return code;
}

tlv_result_t tlv_ber_scan_contents_diag(const uint8_t* data, size_t size, int indefinite,
                                        size_t* value_size, size_t* consumed,
                                        tlv_format_error_t* error) {
    size_t ends[TLV_BER_MAX_DEPTH];
    int terminated[TLV_BER_MAX_DEPTH];
    size_t depth = 1, pos = 0;
    tlv_region_t region = TLV_REGION_VALUE;
    ends[0] = size;
    terminated[0] = indefinite;
    for (;;) {
        size_t limit = ends[depth - 1], tag_size, len_size;
        tlv_size_t length;
        tlv_tag_t tag;
        tlv_result_t rc;
        int child_indefinite, constructed;
        if (pos == limit) {
            if (terminated[depth - 1])
                return scan_failure(error, TLV_ERR_BUFFER_TOO_SHORT, pos, TLV_REGION_TRAILER);
            if (--depth == 0) {
                *value_size = pos;
                *consumed = pos;
                return TLV_OK;
            }
            continue;
        }
        if (data[pos] == 0) {
            region = TLV_REGION_TRAILER;
            if (limit - pos < TLV_BER_EOC_SIZE)
                return scan_failure(error, TLV_ERR_BUFFER_TOO_SHORT, pos, region);
            if (data[pos + 1] != 0) return scan_failure(error, TLV_ERR_INVALID_LENGTH, pos, region);
            if (!terminated[depth - 1])
                return scan_failure(error, TLV_ERR_INVALID_TAG, pos, region);
            if (--depth == 0) {
                *value_size = pos;
                *consumed = pos + TLV_BER_EOC_SIZE;
                return TLV_OK;
            }
            pos += TLV_BER_EOC_SIZE;
            continue;
        }
        region = TLV_REGION_TAG;
        rc = read_tag(NULL, data + pos, limit - pos, &tag, &tag_size);
        if (rc != TLV_OK) return scan_failure(error, rc, pos, region);
        pos += tag_size;
        region = TLV_REGION_LENGTH;
        if (pos == limit) return scan_failure(error, TLV_ERR_BUFFER_TOO_SHORT, pos, region);
        constructed = tlv_ber_is_constructed(NULL, &tag);
        child_indefinite = data[pos] == TLV_BER_LENGTH_LONG_FORM_BIT;
        if (child_indefinite) {
            if (!constructed) return scan_failure(error, TLV_ERR_INVALID_LENGTH, pos, region);
            ++pos;
            length = limit - pos;
        } else {
            rc = read_length(NULL, data + pos, limit - pos, &length, &len_size);
            if (rc != TLV_OK) return scan_failure(error, rc, pos, region);
            pos += len_size;
            region = TLV_REGION_VALUE;
            if (length > limit - pos)
                return scan_failure(error, TLV_ERR_BUFFER_TOO_SHORT, pos, region);
        }
        if (constructed) {
            if (depth == TLV_BER_MAX_DEPTH) return scan_failure(error, TLV_ERR_LIMIT, pos, region);
            ends[depth] = pos + (size_t)length;
            terminated[depth++] = child_indefinite;
        } else
            pos += (size_t)length;
    }
}

tlv_result_t tlv_ber_scan_contents(const uint8_t* data, size_t size, int indefinite,
                                   size_t* value_size, size_t* consumed) {
    return tlv_ber_scan_contents_diag(data, size, indefinite, value_size, consumed, NULL);
}

static tlv_result_t read_value_bounds(const void* context, const tlv_tag_t* tag,
                                      const uint8_t* data, size_t size, size_t* len_size,
                                      tlv_size_t* value_size, size_t* trailer_size,
                                      tlv_format_error_t* error) {
    tlv_size_t length;
    size_t used, native_length;
    tlv_result_t rc;
    if (!size || data[0] != TLV_BER_LENGTH_LONG_FORM_BIT) {
        rc = read_length(context, data, size, &length, len_size);
        if (rc != TLV_OK) return rc;
        *value_size = length;
        *trailer_size = 0;
        return TLV_OK;
    }
    *len_size = TLV_BER_INDEFINITE_LENGTH_OCTET_SIZE;
    if (!tlv_ber_is_constructed(context, tag)) return TLV_ERR_INVALID_LENGTH;
    rc = tlv_ber_scan_contents_diag(data + 1, size - 1, 1, &native_length, &used, error);
    if (rc != TLV_OK) {
        if (error->has_offset) ++error->offset;
        return rc;
    }
    *value_size = native_length;
    *trailer_size = TLV_BER_EOC_SIZE;
    return TLV_OK;
}

tlv_result_t tlv_ber_indefinite_encoded_size(tlv_tag_t tag, size_t length, size_t* size) {
    tlv_element_t element = {tag, {NULL, length}};
    tlv_encoding_t encoding;
    tlv_result_t rc;
    if (!size) return TLV_ERR_NULL_ARG;
    rc = tlv_format_measure(&tlv_format_ber_indefinite, &element, &encoding, NULL);
    return rc == TLV_OK ? tlv_size_to_native(encoding.total, size) : rc;
}

tlv_result_t tlv_ber_write_indefinite(uint8_t* data, size_t capacity, tlv_tag_t tag,
                                      const uint8_t* value, size_t length, size_t* written) {
    tlv_element_t element = {tag, {value, length}};
    size_t used;
    tlv_result_t rc;
    if (!written) return TLV_ERR_NULL_ARG;
    rc = tlv_format_encode(&tlv_format_ber_indefinite, &element, data, capacity, &used, NULL);
    if (rc == TLV_OK) *written = used;
    return rc;
}

tlv_result_t tlv_ber_writer_write_indefinite(tlv_writer_t* writer, tlv_tag_t tag,
                                             const uint8_t* value, size_t length) {
    size_t written;
    tlv_result_t rc;
    if (!writer) return TLV_ERR_NULL_ARG;
    if (writer->format != &tlv_format_ber) return TLV_ERR_INVALID_ARG;
    if (writer->pos > writer->capacity) return TLV_ERR_BUFFER_TOO_SHORT;
    rc = tlv_ber_write_indefinite(writer->buf ? writer->buf + writer->pos : NULL,
                                  writer->capacity - writer->pos, tag, value, length, &written);
    if (rc == TLV_OK) writer->pos += written;
    return rc;
}

const tlv_field_layout_t tlv_ber_fields = {.context = NULL,
                                           .read_tag = read_tag,
                                           .read_length = read_length,
                                           .resolve = read_value_bounds,
                                           .write_tag = write_tag,
                                           .write_length = write_length,
                                           .length_size = length_size};
const tlv_format_t tlv_format_ber = {&tlv_ber_fields, tlv_fields_decode, tlv_fields_measure,
                                     tlv_fields_encode, tlv_ber_is_constructed};

tlv_result_t tlv_asn1_indefinite_measure(const void* context, const tlv_element_t* element,
                                         tlv_encoding_t* sizes, tlv_format_error_t* error) {
    const tlv_field_layout_t* fields = (const tlv_field_layout_t*)context;
    size_t tag_size;
    tlv_result_t rc;
    error->region = TLV_REGION_TAG;
    error->has_offset = 1;
    rc = fields->write_tag(fields->context, NULL, 0, &element->tag, &tag_size);
    if (rc != TLV_OK) return rc;
    if (!tlv_ber_is_constructed(NULL, &element->tag)) return TLV_ERR_INVALID_LENGTH;
    sizes->header = tag_size + (tlv_size_t)1;
    sizes->value = element->value.size;
    sizes->trailer = 2;
    rc = tlv_size_add(sizes->header, sizes->value, &sizes->total);
    if (rc != TLV_OK) return rc;
    return tlv_size_add(sizes->total, sizes->trailer, &sizes->total);
}

tlv_result_t tlv_asn1_indefinite_encode(const void* context, const tlv_element_t* element,
                                        uint8_t* data, size_t capacity, size_t* written,
                                        tlv_format_error_t* error) {
    tlv_encoding_t sizes;
    size_t n, total, checked, used;
    tlv_result_t rc = tlv_asn1_indefinite_measure(context, element, &sizes, error);
    if (rc != TLV_OK) return rc;
    rc = tlv_size_to_native(sizes.total, &total);
    if (rc != TLV_OK) return rc;
    if (capacity < total) return TLV_ERR_BUFFER_TOO_SHORT;
    n = (size_t)element->value.size;
    error->region = TLV_REGION_VALUE;
    error->offset = (size_t)sizes.header;
    rc = tlv_ber_scan_contents(element->value.data, n, 0, &checked, &used);
    if (rc != TLV_OK) return rc;
    memcpy(data, element->tag.data, element->tag.size);
    data[element->tag.size] = 0x80;
    if (n) memcpy(data + (size_t)sizes.header, element->value.data, n);
    data[total - 2] = 0;
    data[total - 1] = 0;
    *written = total;
    return TLV_OK;
}

const tlv_format_t tlv_format_ber_indefinite = {&tlv_ber_fields, tlv_fields_decode,
                                                tlv_asn1_indefinite_measure,
                                                tlv_asn1_indefinite_encode, tlv_ber_is_constructed};

tlv_result_t tlv_ber_read_identifier(const uint8_t* data, size_t size, tlv_tag_t* tag,
                                     size_t* consumed) {
    if ((!data && size) || !tag || !consumed) return TLV_ERR_NULL_ARG;
    return read_tag(NULL, data, size, tag, consumed);
}
