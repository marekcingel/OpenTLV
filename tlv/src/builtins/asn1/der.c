#include "tlv/builtins/asn1/der.h"
#include "ber_internal.h"
#include "asn1_internal.h"
#include <string.h>

static tlv_result_t der_read_tag(const void* context, const uint8_t* data, size_t size,
                                 tlv_tag_t* tag, size_t* consumed) {
    tlv_tag_t parsed;
    size_t count;
    unsigned number;
    tlv_result_t rc = tlv_asn1_read_identifier(context, data, size, &parsed, &count);
    if (rc != TLV_OK) return rc;
    /* Only tags up to 36 currently have assigned universal type semantics.
     * Larger numbers remain opaque, without narrowing large raw identifiers.
     * tlv_asn1_read_identifier already rejects tags 0/15 and requires the
     * constructed bit for the always-constructed set; DER additionally
     * requires every other assigned universal number to stay primitive
     * (unlike CER, which allows either form for the segmentable types).
     */
    number = count == 1 ? (data[0] & TLV_ASN1_TAG_NUMBER_MASK) : (count == 2 ? data[1] : 127);
    if (!(data[0] & 0xC0) && number <= 36) {
        int must_construct =
            number == 8 || number == 11 || number == 16 || number == 17 || number == 29;
        if (!must_construct && (data[0] & TLV_ASN1_CONSTRUCTED_BIT)) return TLV_ERR_INVALID_TAG;
    }
    *tag = parsed;
    *consumed = count;
    return TLV_OK;
}

static tlv_result_t der_write_tag(const void* context, uint8_t* data, size_t capacity,
                                  const tlv_tag_t* tag, size_t* written) {
    tlv_tag_t parsed;
    size_t count;
    tlv_result_t rc;
    if (!tag->size || tag->size > TLV_ASN1_TAG_MAX_SIZE) return TLV_ERR_INVALID_TAG_SIZE;
    if (!tag->data) return TLV_ERR_NULL_ARG;
    rc = der_read_tag(context, tag->data, tag->size, &parsed, &count);
    if (rc == TLV_ERR_INVALID_TAG_SIZE) return rc;
    if (rc != TLV_OK || count != tag->size) return TLV_ERR_INVALID_TAG;
    if (data && capacity < count) return TLV_ERR_BUFFER_TOO_SHORT;
    if (data) memcpy(data, tag->data, count);
    *written = count;
    return TLV_OK;
}

static tlv_result_t der_read_length(const void* context, const uint8_t* data, size_t size,
                                    size_t* length, size_t* consumed) {
    return tlv_asn1_read_minimal_length(context, data, size, length, consumed);
}

static tlv_result_t der_write_length(const void* context, uint8_t* data, size_t capacity,
                                     size_t length, size_t* written) {
    return tlv_ber_writer_wire.write_length(context, data, capacity, length, written);
}

static tlv_result_t der_length_size(const void* context, size_t length, size_t* size) {
    return tlv_ber_writer_wire.length_size(context, length, size);
}

int tlv_der_is_constructed(const void* context, const tlv_tag_t* tag) {
    (void)context;
    return (tag->data[0] & TLV_ASN1_CONSTRUCTED_BIT) != 0;
}

const tlv_reader_format_t tlv_reader_format_der = {
    .context = NULL, .read_tag = der_read_tag, .read_length = der_read_length};

const tlv_writer_format_t tlv_writer_format_der = {.context = NULL,
                                                   .write_tag = der_write_tag,
                                                   .write_length = der_write_length,
                                                   .length_size = der_length_size};

tlv_result_t tlv_der_tag_make(tlv_asn1_class_t tag_class, int constructed, uint64_t number,
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
    if (der_write_tag(NULL, NULL, 0, &result, &written) != TLV_OK) return TLV_ERR_INVALID_TAG;
    memcpy(storage, bytes, result.size);
    *tag = tlv_tag(storage, result.size);
    return TLV_OK;
}

tlv_result_t tlv_der_tag_number(const tlv_tag_t* tag, uint64_t* number) {
    uint64_t result;
    size_t written;
    tlv_result_t rc;
    if (!tag || !number) return TLV_ERR_NULL_ARG;
    rc = der_write_tag(NULL, NULL, 0, tag, &written);
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
