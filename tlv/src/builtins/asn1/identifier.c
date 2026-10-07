// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/builtins/asn1/identifier.h"
#include "asn1_internal.h"
#include "tlv/format.h"
#include "ber_internal.h"
#include <string.h>

int tlv_asn1_is_constructed(const void* context, const tlv_tag_t* tag) {
    (void)context;
    static const tlv_constructed_bit_t bit = {0, TLV_ASN1_CONSTRUCTED_BIT,
                                              TLV_ASN1_CONSTRUCTED_BIT};
    return tlv_constructed_bit_predicate(&bit, tag);
}

tlv_result_t tlv_asn1_tag_make_checked(tlv_write_tag_fn validate, tlv_asn1_class_t tag_class,
                                       int constructed, uint64_t number, uint8_t* storage,
                                       tlv_tag_t* tag) {
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
    if (validate(NULL, &result, NULL, 0, &written) != TLV_OK) return TLV_ERR_INVALID_TAG;
    memcpy(storage, bytes, result.size);
    *tag = tlv_tag(storage, result.size);
    return TLV_OK;
}

tlv_result_t tlv_asn1_tag_number_checked(tlv_write_tag_fn validate, const tlv_tag_t* tag,
                                         uint64_t* number) {
    uint64_t result;
    size_t written;
    tlv_result_t rc;
    if (!tag || !number) return TLV_ERR_NULL_ARG;
    rc = validate(NULL, tag, NULL, 0, &written);
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
