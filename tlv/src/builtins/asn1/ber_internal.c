#include "ber_internal.h"
#include "tlv/format.h"
#include <string.h>

static tlv_result_t read_tag(const void* context, const uint8_t* data, size_t size, tlv_tag_t* tag,
                             size_t* consumed) {
    size_t count = 1;
    (void)context;
    if (!size) return TLV_ERR_BUFFER_TOO_SHORT;
    if ((data[0] & TLV_ASN1_TAG_NUMBER_MASK) == TLV_ASN1_TAG_NUMBER_MASK) {
        for (;;) {
            if (count == TLV_ASN1_TAG_MAX_SIZE) return TLV_ERR_INVALID_TAG_SIZE;
            if (count == size) return TLV_ERR_BUFFER_TOO_SHORT;
            /* The first base-128 digit must be nonzero. Keep raw tag bytes,
             * including BER-TLV identifiers such as 9F 1C. */
            if (count == 1 && !(data[count] & TLV_BER_TAG_DIGIT_MASK)) return TLV_ERR_INVALID_TAG;
            if (!(data[count++] & TLV_BER_TAG_DIGIT_CONTINUATION_BIT)) break;
        }
    }
    *tag = tlv_tag(data, count);
    *consumed = count;
    return TLV_OK;
}

static tlv_result_t write_tag(const void* context, uint8_t* data, size_t capacity,
                              const tlv_tag_t* tag, size_t* written) {
    tlv_tag_t parsed;
    size_t count;
    tlv_result_t rc;
    if (!tag->size || tag->size > TLV_ASN1_TAG_MAX_SIZE) return TLV_ERR_INVALID_TAG_SIZE;
    if (!tag->data) return TLV_ERR_NULL_ARG;
    rc = read_tag(context, tag->data, tag->size, &parsed, &count);
    if (rc == TLV_ERR_INVALID_TAG_SIZE) return rc;
    if (rc != TLV_OK || count != tag->size) return TLV_ERR_INVALID_TAG;
    *written = count;
    if (!data) return TLV_OK;
    if (capacity < count) return TLV_ERR_BUFFER_TOO_SHORT;
    memcpy(data, tag->data, count);
    return TLV_OK;
}

size_t tlv_ber_length_field_size(const uint8_t* data, size_t size) {
    size_t count;
    if (!size) return 0;
    count = data[0] <= TLV_BER_LENGTH_LONG_FORM_BIT || data[0] == TLV_BER_LENGTH_RESERVED_OCTET
                ? 1
                : 1 + (size_t)(data[0] & TLV_BER_LENGTH_COUNT_MASK);
    return count < size ? count : size;
}

static tlv_result_t read_length(const void* context, const uint8_t* data, size_t size,
                                tlv_size_t* length, size_t* consumed) {
    (void)context;
    *consumed = tlv_ber_length_field_size(data, size);
    return tlv_ber_length_decode(data, size, length, consumed);
}

static tlv_result_t length_size(const void* context, tlv_size_t length, size_t* size) {
    (void)context;
    return tlv_ber_length_encode(length, NULL, 0, size);
}

static tlv_result_t write_length(const void* context, uint8_t* data, size_t capacity,
                                 tlv_size_t length, size_t* written) {
    (void)context;
    return tlv_ber_length_encode(length, data, capacity, written);
}

const tlv_field_layout_t tlv_ber_wire = {.context = NULL,
                                         .read_tag = read_tag,
                                         .read_length = read_length,
                                         .write_tag = write_tag,
                                         .write_length = write_length,
                                         .length_size = length_size};
