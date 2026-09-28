#include "tlv/layout.h"
#include "tlv/builtins/asn1/cer.h"
#include "ber_internal.h"
#include "asn1_internal.h"
#include <string.h>

static tlv_result_t cer_read_tag(const void* context, const uint8_t* data, size_t size,
                                 tlv_tag_t* tag, size_t* consumed) {
    return tlv_asn1_read_identifier(context, data, size, tag, consumed);
}

static tlv_result_t cer_write_tag(const void* context, uint8_t* data, size_t capacity,
                                  const tlv_tag_t* tag, size_t* written) {
    return tlv_asn1_write_identifier(context, data, capacity, tag, written);
}

static tlv_result_t cer_read_length(const void* context, const uint8_t* data, size_t size,
                                    tlv_size_t* length, size_t* consumed) {
    return tlv_asn1_read_minimal_length(context, data, size, length, consumed);
}

static tlv_result_t cer_write_length(const void* context, uint8_t* data, size_t capacity,
                                     tlv_size_t length, size_t* written) {
    return tlv_ber_wire.write_length(context, data, capacity, length, written);
}

static tlv_result_t cer_length_size(const void* context, tlv_size_t length, size_t* size) {
    return tlv_ber_wire.length_size(context, length, size);
}

int tlv_cer_is_constructed(const void* context, const tlv_tag_t* tag) {
    (void)context;
    return (tag->data[0] & TLV_ASN1_CONSTRUCTED_BIT) != 0;
}

/* Resolves one element's length field: a constructed tag's length must be
 * the indefinite marker (0x80), scanned to its matching EOC with
 * tlv_ber_scan_contents (bounded, no allocation, no recursion); a primitive
 * tag's length must be definite and canonically minimal. Either form found
 * on the wrong kind of tag is TLV_ERR_INVALID_LENGTH. This resolves framing
 * only, not nested segmentation -- see tlv/builtins/asn1/cer_profile.h for that. */
static tlv_result_t read_value_bounds(const void* context, const tlv_tag_t* tag,
                                      const uint8_t* data, size_t size, size_t* length_size,
                                      tlv_size_t* value_size, size_t* trailer_size,
                                      tlv_format_error_t* error) {
    tlv_size_t length;
    size_t used, native_length;
    tlv_result_t rc;
    int constructed = tlv_cer_is_constructed(context, tag);
    *length_size = tlv_ber_length_field_size(data, size);
    if (!size) return TLV_ERR_BUFFER_TOO_SHORT;
    if (data[0] == TLV_BER_LENGTH_LONG_FORM_BIT) {
        if (!constructed) return TLV_ERR_INVALID_LENGTH;
        rc = tlv_ber_scan_contents_diag(data + 1, size - 1, 1, &native_length, &used, error);
        if (rc != TLV_OK) {
            if (error->has_offset) ++error->offset;
            return rc;
        }
        *length_size = TLV_BER_INDEFINITE_LENGTH_OCTET_SIZE;
        *value_size = native_length;
        *trailer_size = TLV_BER_EOC_SIZE;
        return TLV_OK;
    }
    if (constructed) return TLV_ERR_INVALID_LENGTH;
    rc = cer_read_length(context, data, size, &length, &used);
    if (rc != TLV_OK) return rc;
    *length_size = used;
    *value_size = length;
    *trailer_size = 0;
    return TLV_OK;
}

static tlv_result_t cer_measure(const void* context, const tlv_element_t* element,
                                tlv_encoding_t* sizes, tlv_format_error_t* error) {
    if (!element->tag.size || !element->tag.data) return TLV_ERR_INVALID_TAG_SIZE;
    if (tlv_cer_is_constructed(NULL, &element->tag))
        return tlv_asn1_indefinite_measure(context, element, sizes, error);
    return tlv_fields_measure(context, element, sizes, error);
}

static tlv_result_t cer_encode(const void* context, const tlv_element_t* element, uint8_t* data,
                               size_t capacity, size_t* written, tlv_format_error_t* error) {
    if (!element->tag.size || !element->tag.data) return TLV_ERR_INVALID_TAG_SIZE;
    if (tlv_cer_is_constructed(NULL, &element->tag))
        return tlv_asn1_indefinite_encode(context, element, data, capacity, written, error);
    return tlv_fields_encode(context, element, data, capacity, written, error);
}

const tlv_field_layout_t tlv_cer_fields = {.context = NULL,
                                           .read_tag = cer_read_tag,
                                           .read_length = cer_read_length,
                                           .resolve = read_value_bounds,
                                           .write_tag = cer_write_tag,
                                           .write_length = cer_write_length,
                                           .length_size = cer_length_size};
const tlv_format_t tlv_format_cer = {&tlv_cer_fields, tlv_fields_decode, cer_measure, cer_encode,
                                     tlv_cer_is_constructed};

tlv_result_t tlv_cer_tag_make(tlv_asn1_class_t tag_class, int constructed, uint64_t number,
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
    if (cer_write_tag(NULL, NULL, 0, &result, &written) != TLV_OK) return TLV_ERR_INVALID_TAG;
    memcpy(storage, bytes, result.size);
    *tag = tlv_tag(storage, result.size);
    return TLV_OK;
}

tlv_result_t tlv_cer_tag_number(const tlv_tag_t* tag, uint64_t* number) {
    uint64_t result;
    size_t written;
    tlv_result_t rc;
    if (!tag || !number) return TLV_ERR_NULL_ARG;
    rc = cer_write_tag(NULL, NULL, 0, tag, &written);
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
