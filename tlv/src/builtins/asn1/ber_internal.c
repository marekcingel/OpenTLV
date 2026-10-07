// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "ber_internal.h"
#include "tlv/field/variable.h"

/* X.690 wire configuration. The generic primitives have no ASN.1 policy. */
static const tlv_variable_identifier_t ber_identifier = {
    TLV_ASN1_TAG_NUMBER_MASK, TLV_ASN1_TAG_NUMBER_MASK, TLV_BER_TAG_DIGIT_CONTINUATION_BIT,
    TLV_BER_TAG_DIGIT_MASK,   TLV_ASN1_TAG_MAX_SIZE,    NULL};
static const tlv_variable_length_t ber_length = {
    TLV_BER_LENGTH_LONG_FORM_BIT, TLV_BER_LENGTH_COUNT_MASK, TLV_BYTE_ORDER_BIG_ENDIAN, NULL};

/* The leading high-tag-number digit must be nonzero (X.690 8.1.2.4.2).
 * Check the available prefix first to preserve BER's error precedence even
 * when the following continuation is truncated or exceeds the tag limit.
 * Historical raw BER-TLV acceptance of identifiers such as 9F 1C is retained;
 * this adapter does not enforce every ASN.1 identifier constraint. */
static tlv_result_t identifier_policy(const uint8_t* data, size_t size) {
    if (size > 1 && (data[0] & TLV_ASN1_TAG_NUMBER_MASK) == TLV_ASN1_TAG_NUMBER_MASK &&
        !(data[1] & TLV_BER_TAG_DIGIT_MASK))
        return TLV_ERR_INVALID_TAG;
    return TLV_OK;
}

static tlv_result_t read_tag(const void* context, const uint8_t* data, size_t size, tlv_tag_t* tag,
                             size_t* consumed) {
    if ((!data && size) || !tag || !consumed) return TLV_ERR_NULL_ARG;
    tlv_result_t rc;
    (void)context;
    rc = identifier_policy(data, size);
    if (rc != TLV_OK) return rc;
    return tlv_variable_identifier_read(&ber_identifier, data, size, tag, consumed);
}

static tlv_result_t write_tag(const void* context, const tlv_tag_t* tag, uint8_t* data,
                              size_t capacity, size_t* written) {
    if (!tag || (!tag->data && tag->size) || (!data && capacity) || !written)
        return TLV_ERR_NULL_ARG;
    tlv_result_t rc;
    (void)context;
    if (!tag->size || tag->size > TLV_ASN1_TAG_MAX_SIZE) return TLV_ERR_INVALID_TAG_SIZE;
    rc = identifier_policy(tag->data, tag->size);
    if (rc != TLV_OK) return rc;
    rc = tlv_variable_identifier_write(&ber_identifier, tag, data, capacity, written);
    return rc;
}

static tlv_result_t read_length(const void* context, const uint8_t* data, size_t size,
                                tlv_size_t* length, size_t* consumed) {
    if ((!data && size) || !length || !consumed) return TLV_ERR_NULL_ARG;
    tlv_result_t rc;
    (void)context;
    /* FF is reserved by X.690 8.1.3.5, not by the generic count encoding. */
    if (size && data[0] == TLV_BER_LENGTH_RESERVED_OCTET) {
        *consumed = 1;
        return TLV_ERR_INVALID_LENGTH;
    }
    rc = tlv_variable_length_read(&ber_length, data, size, length, consumed);
    /* Keep the public BER error contract for unrepresentable wire counts. */
    return rc == TLV_ERR_OVERFLOW ? TLV_ERR_INVALID_LENGTH : rc;
}

size_t tlv_ber_length_field_size(const uint8_t* data, size_t size) {
    tlv_size_t length;
    size_t consumed = 0;
    (void)read_length(NULL, data, size, &length, &consumed);
    return consumed;
}

tlv_result_t tlv_ber_length_decode(const uint8_t* data, size_t data_size, tlv_size_t* value,
                                   size_t* consumed) {
    tlv_size_t decoded;
    size_t used;
    tlv_result_t rc;
    if ((!data && data_size) || !value || !consumed) return TLV_ERR_NULL_ARG;
    /* Unlike field callbacks, this public helper preserves both outputs on
     * failure. Keep diagnostic prefix reporting private to the composition. */
    rc = read_length(NULL, data, data_size, &decoded, &used);
    if (rc != TLV_OK) return rc;
    *value = decoded;
    *consumed = used;
    return TLV_OK;
}

tlv_result_t tlv_ber_length_encode(tlv_size_t value, uint8_t* out, size_t out_capacity,
                                   size_t* written) {
    return tlv_variable_length_write(&ber_length, value, out, out_capacity, written);
}

tlv_result_t tlv_ber_write_length(const void* context, tlv_size_t length, uint8_t* data,
                                  size_t capacity, size_t* written) {
    (void)context;
    return tlv_ber_length_encode(length, data, capacity, written);
}

const tlv_field_composition_t tlv_ber_wire = {.context = NULL,
                                              .read_tag = read_tag,
                                              .read_length = read_length,
                                              .write_tag = write_tag,
                                              .write_length = tlv_ber_write_length};
