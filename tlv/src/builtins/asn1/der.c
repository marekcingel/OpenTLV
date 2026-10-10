// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/formats/compose.h"
#include "tlv/builtins/asn1/der.h"
#include "ber_internal.h"
#include "asn1_internal.h"

static tlv_result_t der_read_tag(const void* context, const uint8_t* data, size_t size,
                                 tlv_tag_t* tag, size_t* consumed) {
    tlv_tag_t parsed;
    size_t count;
    unsigned number;
    tlv_result_t rc;
    if ((!data && size) || !tag || !consumed) return TLV_ERR_NULL_ARG;
    rc = tlv_asn1_read_identifier(context, data, size, &parsed, &count);
    if (rc != TLV_OK) {
        if (rc == TLV_ERR_TRUNCATED) *consumed = count;
        return rc;
    }
    /* Only tags up to 36 currently have assigned universal type semantics.
     * Larger numbers remain opaque, without narrowing large raw identifiers.
     * tlv_asn1_read_identifier already rejects tags 0/15 and requires the
     * constructed bit for the always-constructed set; DER additionally
     * requires every other assigned universal number to stay primitive
     * (unlike CER, which allows either form for the segmentable types).
     */
    number = count == 1 ? (data[0] & TLV_ASN1_TAG_NUMBER_MASK) : (count == 2 ? data[1] : 127);
    if (!(data[0] & 0xC0) && number <= 36) {
        int must_construct = tlv_asn1_number_must_construct(number);
        if (!must_construct && (data[0] & TLV_ASN1_CONSTRUCTED_BIT)) return TLV_ERR_INVALID_TAG;
    }
    *tag = parsed;
    *consumed = count;
    return TLV_OK;
}

static tlv_result_t der_write_tag(const void* context, const tlv_tag_t* tag, uint8_t* data,
                                  size_t capacity, size_t* written) {
    return tlv_asn1_write_identifier_checked(der_read_tag, context, tag, data, capacity, written);
}

const tlv_field_composition_t tlv_der_fields = {.context = NULL,
                                                .read_tag = der_read_tag,
                                                .read_length = tlv_asn1_read_minimal_length,
                                                .write_tag = der_write_tag,
                                                .write_length = tlv_ber_write_length};
const tlv_format_t tlv_format_der = {&tlv_der_fields, tlv_fields_decode, tlv_fields_measure,
                                     tlv_fields_encode, tlv_asn1_is_constructed};

tlv_result_t tlv_der_tag_make(tlv_asn1_class_t tag_class, int constructed, uint64_t number,
                              uint8_t* storage, tlv_tag_t* tag) {
    return tlv_asn1_tag_make_checked(der_write_tag, tag_class, constructed, number, storage, tag);
}

tlv_result_t tlv_der_tag_number(const tlv_tag_t* tag, uint64_t* number) {
    return tlv_asn1_tag_number_checked(der_write_tag, tag, number);
}
