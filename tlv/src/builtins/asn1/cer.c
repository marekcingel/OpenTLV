#include "tlv/layout.h"
#include "tlv/builtins/asn1/cer.h"
#include "ber_internal.h"
#include "asn1_internal.h"

/* Resolves one element's length field: a constructed tag's length must be
 * the indefinite marker (0x80), scanned to its matching EOC with
 * tlv_ber_scan_contents (bounded, no allocation, no recursion); a primitive
 * tag's length must be definite and canonically minimal. Either form found
 * on the wrong kind of tag is TLV_ERR_INVALID_LENGTH. This resolves framing
 * only, not nested segmentation -- see tlv/builtins/asn1/cer_validation.h for that. */
static tlv_result_t read_value_bounds(const void* context, const tlv_tag_t* tag,
                                      const uint8_t* data, size_t size, size_t* length_size,
                                      tlv_size_t* value_size, size_t* trailer_size,
                                      tlv_format_error_t* error) {
    tlv_size_t length;
    size_t used, native_length;
    tlv_result_t rc;
    int constructed = tlv_asn1_is_constructed(context, tag);
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
    rc = tlv_asn1_read_minimal_length(context, data, size, &length, &used);
    if (rc != TLV_OK) return rc;
    *length_size = used;
    *value_size = length;
    *trailer_size = 0;
    return TLV_OK;
}

static tlv_result_t cer_measure(const void* context, const tlv_element_t* element,
                                tlv_encoding_t* sizes, tlv_format_error_t* error) {
    if (!element->tag.size || !element->tag.data) return TLV_ERR_INVALID_TAG_SIZE;
    if (tlv_asn1_is_constructed(NULL, &element->tag))
        return tlv_asn1_indefinite_measure(context, element, sizes, error);
    return tlv_fields_measure(context, element, sizes, error);
}

static tlv_result_t cer_encode(const void* context, const tlv_element_t* element, uint8_t* data,
                               size_t capacity, size_t* written, tlv_format_error_t* error) {
    if (!element->tag.size || !element->tag.data) return TLV_ERR_INVALID_TAG_SIZE;
    if (tlv_asn1_is_constructed(NULL, &element->tag))
        return tlv_asn1_indefinite_encode(context, element, data, capacity, written, error);
    return tlv_fields_encode(context, element, data, capacity, written, error);
}

const tlv_field_layout_t tlv_cer_fields = {.context = NULL,
                                           .read_tag = tlv_asn1_read_identifier,
                                           .read_length = tlv_asn1_read_minimal_length,
                                           .resolve = read_value_bounds,
                                           .write_tag = tlv_asn1_write_identifier,
                                           .write_length = tlv_ber_write_length,
                                           .length_size = tlv_ber_length_size};
const tlv_format_t tlv_format_cer = {&tlv_cer_fields, tlv_fields_decode, cer_measure, cer_encode,
                                     tlv_asn1_is_constructed};

tlv_result_t tlv_cer_tag_make(tlv_asn1_class_t tag_class, int constructed, uint64_t number,
                              uint8_t* storage, tlv_tag_t* tag) {
    return tlv_asn1_tag_make_checked(tlv_asn1_write_identifier, tag_class, constructed, number,
                                     storage, tag);
}

tlv_result_t tlv_cer_tag_number(const tlv_tag_t* tag, uint64_t* number) {
    return tlv_asn1_tag_number_checked(tlv_asn1_write_identifier, tag, number);
}
