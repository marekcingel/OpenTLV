// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "asn1_internal.h"
#include "ber_internal.h"
#include "tlv/field/variable.h"

tlv_result_t tlv_asn1_read_identifier(const void* context, const uint8_t* data, size_t size,
                                      tlv_tag_t* tag, size_t* consumed) {
    static const tlv_identifier_policy_t policy = {NULL, 0, 1, 1};
    static const tlv_variable_identifier_t encoding = {
        TLV_ASN1_TAG_NUMBER_MASK, TLV_ASN1_TAG_NUMBER_MASK, TLV_BER_TAG_DIGIT_CONTINUATION_BIT,
        TLV_BER_TAG_DIGIT_MASK,   TLV_ASN1_TAG_MAX_SIZE,    &policy};
    tlv_tag_t parsed;
    size_t count;
    unsigned number;
    tlv_result_t rc;
    if ((!data && size) || !tag || !consumed) return TLV_ERR_NULL_ARG;
    (void)context;
    rc = tlv_variable_identifier_read(&encoding, data, size, &parsed, &count);
    if (rc != TLV_OK) {
        if (rc == TLV_ERR_BUFFER_TOO_SHORT) *consumed = count;
        return rc;
    }
    number = count == 1 ? (data[0] & TLV_ASN1_TAG_NUMBER_MASK) : (count == 2 ? data[1] : 127);
    if (!(data[0] & 0xC0)) {
        int must_construct;
        if (number == 0 || number == 15) return TLV_ERR_INVALID_TAG;
        must_construct = tlv_asn1_number_must_construct(number);
        if (must_construct && !(data[0] & TLV_ASN1_CONSTRUCTED_BIT)) return TLV_ERR_INVALID_TAG;
    }
    *tag = parsed;
    *consumed = count;
    return TLV_OK;
}

tlv_result_t tlv_asn1_write_identifier_checked(tlv_read_tag_fn read_identifier, const void* context,
                                               const tlv_tag_t* tag, uint8_t* data, size_t capacity,
                                               size_t* written) {
    tlv_tag_t parsed;
    size_t count;
    tlv_result_t rc;
    if (!read_identifier || !tag || (!tag->data && tag->size) || (!data && capacity) || !written)
        return TLV_ERR_NULL_ARG;
    if (!tag->size || tag->size > TLV_ASN1_TAG_MAX_SIZE) return TLV_ERR_INVALID_TAG_SIZE;
    rc = read_identifier(context, tag->data, tag->size, &parsed, &count);
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
                                          tlv_size_t* length, size_t* consumed) {
    static const tlv_length_policy_t policy = {1, 1, 1, 126, UINT64_MAX};
    static const tlv_variable_length_t encoding = {TLV_BER_LENGTH_LONG_FORM_BIT,
                                                   TLV_BER_LENGTH_COUNT_MASK,
                                                   TLV_BYTE_ORDER_BIG_ENDIAN, &policy};
    (void)context;
    return tlv_variable_length_read(&encoding, data, size, length, consumed);
}

int tlv_asn1_number_must_construct(uint64_t number) {
    return number == 8 || number == 11 || number == 16 || number == 17 || number == 29;
}

tlv_result_t tlv_asn1_write_identifier(const void* context, const tlv_tag_t* tag, uint8_t* data,
                                       size_t capacity, size_t* written) {
    return tlv_asn1_write_identifier_checked(tlv_asn1_read_identifier, context, tag, data, capacity,
                                             written);
}
