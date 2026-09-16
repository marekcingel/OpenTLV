#include "tlv/formats/asn1/cer.h"
#include "ber_internal.h"
#include "asn1_internal.h"

static tlv_result_t cer_read_tag(const void* context, const uint8_t* data, size_t size,
                                 tlv_tag_t* tag, size_t* consumed) {
    return tlv_asn1_read_identifier(context, data, size, tag, consumed);
}

static tlv_result_t cer_write_tag(const void* context, uint8_t* data, size_t capacity,
                                  const tlv_tag_t* tag, size_t* written) {
    return tlv_asn1_write_identifier(context, data, capacity, tag, written);
}

static tlv_result_t cer_read_length(const void* context, const uint8_t* data, size_t size,
                                    size_t* length, size_t* consumed) {
    return tlv_asn1_read_minimal_length(context, data, size, length, consumed);
}

static tlv_result_t cer_write_length(const void* context, uint8_t* data, size_t capacity,
                                     size_t length, size_t* written) {
    return tlv_ber_writer_wire.write_length(context, data, capacity, length, written);
}

static tlv_result_t cer_length_size(const void* context, size_t length, size_t* size) {
    return tlv_ber_writer_wire.length_size(context, length, size);
}

int tlv_cer_is_constructed(const void* context, const tlv_tag_t* tag) {
    (void)context;
    return (tag->data[0] & 0x20) != 0;
}

/* Resolves one element's length field: a constructed tag's length must be
 * the indefinite marker (0x80), scanned to its matching EOC with
 * tlv_ber_scan_contents (bounded, no allocation, no recursion); a primitive
 * tag's length must be definite and canonically minimal. Either form found
 * on the wrong kind of tag is TLV_ERR_INVALID_LENGTH. This resolves framing
 * only, not nested segmentation -- see tlv/profiles/cer.h for that. */
static tlv_result_t read_value_bounds(const void* context, const tlv_tag_t* tag,
                                      const uint8_t* data, size_t size, size_t* length_size,
                                      size_t* value_size, size_t* trailer_size) {
    size_t length, used;
    tlv_result_t rc;
    int constructed = tlv_cer_is_constructed(context, tag);
    if (!size) return TLV_ERR_BUFFER_TOO_SHORT;
    if (data[0] == 0x80) {
        if (!constructed) return TLV_ERR_INVALID_LENGTH;
        rc = tlv_ber_scan_contents(data + 1, size - 1, 1, &length, &used);
        if (rc != TLV_OK) return rc;
        *length_size = 1;
        *value_size = length;
        *trailer_size = 2;
        return TLV_OK;
    }
    if (constructed) return TLV_ERR_INVALID_LENGTH;
    rc = cer_read_length(context, data, size, &length, &used);
    if (rc != TLV_OK) return rc;
    if (length > size - used) return TLV_ERR_BUFFER_TOO_SHORT;
    *length_size = used;
    *value_size = length;
    *trailer_size = 0;
    return TLV_OK;
}

const tlv_reader_format_t tlv_reader_format_cer = {.context = NULL,
                                                   .read_tag = cer_read_tag,
                                                   .read_length = cer_read_length,
                                                   .read_value_bounds = read_value_bounds};

const tlv_writer_format_t tlv_writer_format_cer = {.context = NULL,
                                                   .write_tag = cer_write_tag,
                                                   .write_length = cer_write_length,
                                                   .length_size = cer_length_size};

tlv_result_t tlv_cer_tag_make(tlv_asn1_class_t tag_class, int constructed, uint64_t number,
                              tlv_tag_t* tag) {
    tlv_tag_t result = {{0}, 1};
    size_t written;
    if (!tag) return TLV_ERR_NULL_ARG;
    if ((unsigned)tag_class > 3 || (constructed != 0 && constructed != 1))
        return TLV_ERR_INVALID_TAG;
    result.data[0] = (uint8_t)(((unsigned)tag_class << 6) | (constructed ? 0x20 : 0));
    if (number < 31)
        result.data[0] |= (uint8_t)number;
    else {
        uint8_t digits[10];
        size_t count = 0;
        result.data[0] |= 0x1F;
        do {
            digits[count++] = (uint8_t)(number & 0x7F);
            number >>= 7;
        } while (number);
        if (count + 1 > TLV_TAG_CAPACITY) return TLV_ERR_INVALID_TAG_SIZE;
        result.size = (uint8_t)(count + 1);
        for (size_t i = 0; i < count; ++i)
            result.data[i + 1] = (uint8_t)(digits[count - i - 1] | (i + 1 < count ? 0x80 : 0));
    }
    if (cer_write_tag(NULL, NULL, 0, &result, &written) != TLV_OK) return TLV_ERR_INVALID_TAG;
    *tag = result;
    return TLV_OK;
}

tlv_result_t tlv_cer_tag_number(const tlv_tag_t* tag, uint64_t* number) {
    uint64_t result;
    size_t written;
    tlv_result_t rc;
    if (!tag || !number) return TLV_ERR_NULL_ARG;
    rc = cer_write_tag(NULL, NULL, 0, tag, &written);
    if (rc != TLV_OK) return rc;
    result = tag->data[0] & 0x1F;
    if (tag->size > 1) {
        result = 0;
        for (size_t i = 1; i < tag->size; ++i) {
            if (result > (UINT64_MAX >> 7)) return TLV_ERR_INVALID_TAG;
            result = (result << 7) | (tag->data[i] & 0x7F);
        }
    }
    *number = result;
    return TLV_OK;
}
