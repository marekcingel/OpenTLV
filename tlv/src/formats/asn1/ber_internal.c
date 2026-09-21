#include "ber_internal.h"
#include "tlv/formats/format.h"
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

/* Delegates to the standalone tlv_ber_length_decode() (tlv/formats/asn1/ber.h)
 * for the actual field parsing, narrowing its portable tlv_length_t result to
 * this build's size_t. consumed is only published once that narrowing also
 * succeeds, so a value that decodes but does not fit size_t leaves *length
 * and *consumed unchanged, like any other failure. */
static tlv_result_t read_length(const void* context, const uint8_t* data, size_t size,
                                size_t* length, size_t* consumed) {
    tlv_length_t value;
    size_t local_consumed;
    tlv_result_t rc;
    (void)context;
    rc = tlv_ber_length_decode(data, size, &value, &local_consumed);
    if (rc != TLV_OK) return rc;
    rc = tlv_length_to_size(value, length);
    if (rc != TLV_OK) return TLV_ERR_INVALID_LENGTH;
    *consumed = local_consumed;
    return TLV_OK;
}

/* Delegates to the standalone tlv_ber_length_encode(). length always fits
 * tlv_length_t (tlv_length_from_size() is lossless), so the only failure this
 * can add is a NULL size, already excluded by tlv_writer_format_t callers. */
static tlv_result_t length_size(const void* context, size_t length, size_t* size) {
    tlv_length_t value;
    tlv_result_t rc;
    (void)context;
    rc = tlv_length_from_size(length, &value);
    if (rc != TLV_OK) return rc;
    return tlv_ber_length_encode(value, NULL, 0, size);
}

static tlv_result_t write_length(const void* context, uint8_t* data, size_t capacity, size_t length,
                                 size_t* written) {
    tlv_length_t value;
    tlv_result_t rc;
    (void)context;
    rc = tlv_length_from_size(length, &value);
    if (rc != TLV_OK) return rc;
    return tlv_ber_length_encode(value, data, capacity, written);
}

const tlv_reader_format_t tlv_ber_reader_wire = {
    .context = NULL, .read_tag = read_tag, .read_length = read_length};

const tlv_writer_format_t tlv_ber_writer_wire = {.context = NULL,
                                                 .write_tag = write_tag,
                                                 .write_length = write_length,
                                                 .length_size = length_size};
