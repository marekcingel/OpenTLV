#include "asn1_internal.h"
#include "ber_internal.h"

tlv_result_t tlv_asn1_read_identifier(const void* context, const uint8_t* data, size_t size,
                                      tlv_tag_t* tag, size_t* consumed) {
    tlv_tag_t parsed;
    size_t count;
    unsigned number;
    tlv_result_t rc = tlv_ber_reader_wire.read_tag(context, data, size, &parsed, &count);
    if (rc != TLV_OK) return rc;
    if (count == 2 && data[1] < TLV_ASN1_LOW_TAG_LIMIT) return TLV_ERR_INVALID_TAG;
    number = count == 1 ? (data[0] & TLV_ASN1_TAG_NUMBER_MASK) : (count == 2 ? data[1] : 127);
    if (!(data[0] & 0xC0)) {
        int must_construct;
        if (number == 0 || number == 15) return TLV_ERR_INVALID_TAG;
        must_construct =
            number == 8 || number == 11 || number == 16 || number == 17 || number == 29;
        if (must_construct && !(data[0] & TLV_ASN1_CONSTRUCTED_BIT)) return TLV_ERR_INVALID_TAG;
    }
    *tag = parsed;
    *consumed = count;
    return TLV_OK;
}

tlv_result_t tlv_asn1_write_identifier(const void* context, uint8_t* data, size_t capacity,
                                       const tlv_tag_t* tag, size_t* written) {
    tlv_tag_t parsed;
    size_t count;
    tlv_result_t rc;
    if (!tag->size || tag->size > TLV_TAG_CAPACITY) return TLV_ERR_INVALID_TAG_SIZE;
    rc = tlv_asn1_read_identifier(context, tag->data, tag->size, &parsed, &count);
    if (rc == TLV_ERR_INVALID_TAG_SIZE) return rc;
    if (rc != TLV_OK || count != tag->size) return TLV_ERR_INVALID_TAG;
    if (data && capacity < count) return TLV_ERR_BUFFER_TOO_SHORT;
    if (data) {
        size_t i;
        for (i = 0; i < count; ++i) data[i] = tag->data[i];
    }
    *written = count;
    return TLV_OK;
}

tlv_result_t tlv_asn1_read_minimal_length(const void* context, const uint8_t* data, size_t size,
                                          size_t* length, size_t* consumed) {
    size_t value, count;
    tlv_result_t rc = tlv_ber_reader_wire.read_length(context, data, size, &value, &count);
    if (rc != TLV_OK) return rc;
    if (count > 1 && (value < TLV_BER_LENGTH_LONG_FORM_BIT || data[1] == 0))
        return TLV_ERR_INVALID_LENGTH;
    *length = value;
    *consumed = count;
    return TLV_OK;
}
