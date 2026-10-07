// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/formats/escaped.h"
#include "../field/fixed_internal.h"
#include "../field/escaped_internal.h"

static tlv_result_t read_tag(const void* context, const uint8_t* data, size_t size, tlv_tag_t* tag,
                             size_t* consumed) {
    const tlv_escaped_format_t* f = (const tlv_escaped_format_t*)context;
    return tlv_fixed_identifier_read(&f->identifier, data, size, tag, consumed);
}

static tlv_result_t write_tag(const void* context, uint8_t* data, size_t capacity,
                              const tlv_tag_t* tag, size_t* written) {
    const tlv_escaped_format_t* f = (const tlv_escaped_format_t*)context;
    return tlv_fixed_identifier_write(&f->identifier, tag, data, capacity, written);
}

static tlv_result_t read_length(const void* context, const uint8_t* data, size_t size,
                                tlv_size_t* length, size_t* consumed) {
    const tlv_escaped_format_t* f = (const tlv_escaped_format_t*)context;
    return tlv_escaped_length_read(&f->length, data, size, length, consumed);
}

static tlv_result_t write_length(const void* context, uint8_t* data, size_t capacity,
                                 tlv_size_t length, size_t* written) {
    const tlv_escaped_format_t* f = (const tlv_escaped_format_t*)context;
    return tlv_escaped_length_write(&f->length, length, data, capacity, written);
}

static tlv_result_t length_size(const void* context, tlv_size_t length, size_t* size) {
    return write_length(context, NULL, 0, length, size);
}

static tlv_tagged_fields_composition_t fields(const tlv_escaped_format_t* f) {
    tlv_tagged_fields_composition_t result = {{f, read_tag, read_length, NULL, write_tag,
                                               write_length, length_size, f->element_order,
                                               f->length_scope},
                                              f->tag_only,
                                              f->count};
    return result;
}

tlv_result_t tlv_escaped_decode(const void* context, const uint8_t* data, size_t size,
                                tlv_decoded_t* result, tlv_format_error_t* error) {
    const tlv_escaped_format_t* f = (const tlv_escaped_format_t*)context;
    tlv_tagged_fields_composition_t composition = fields(f);
    return f->count ? tlv_tagged_fields_decode(&composition, data, size, result, error)
                    : tlv_fields_decode(&composition.fields, data, size, result, error);
}

tlv_result_t tlv_escaped_measure(const void* context, const tlv_element_t* element,
                                 tlv_encoding_t* encoding, tlv_format_error_t* error) {
    const tlv_escaped_format_t* f = (const tlv_escaped_format_t*)context;
    tlv_tagged_fields_composition_t composition = fields(f);
    return f->count ? tlv_tagged_fields_measure(&composition, element, encoding, error)
                    : tlv_fields_measure(&composition.fields, element, encoding, error);
}

tlv_result_t tlv_escaped_encode(const void* context, const tlv_element_t* element, uint8_t* data,
                                size_t capacity, size_t* written, tlv_format_error_t* error) {
    const tlv_escaped_format_t* f = (const tlv_escaped_format_t*)context;
    tlv_tagged_fields_composition_t composition = fields(f);
    return f->count
               ? tlv_tagged_fields_encode(&composition, element, data, capacity, written, error)
               : tlv_fields_encode(&composition.fields, element, data, capacity, written, error);
}

tlv_result_t tlv_escaped_format_init(tlv_format_t* format, const tlv_escaped_format_t* f) {
    tlv_result_t rc;
    if (!format || !f) return TLV_ERR_NULL_ARG;
    rc = fixed_identifier_validate(&f->identifier);
    if (rc != TLV_OK) return rc;
    rc = validate_length(&f->length);
    if (rc != TLV_OK) return rc;
    if ((f->element_order != TLV_ELEMENT_ORDER_TLV && f->element_order != TLV_ELEMENT_ORDER_LTV) ||
        (f->length_scope != TLV_LENGTH_SCOPE_VALUE &&
         f->length_scope != TLV_LENGTH_SCOPE_TAG_AND_VALUE) ||
        (f->count && (!f->tag_only || f->element_order != TLV_ELEMENT_ORDER_TLV ||
                      f->length_scope != TLV_LENGTH_SCOPE_VALUE)))
        return TLV_ERR_INVALID_ARG;
    for (size_t i = 0; i < f->count; ++i)
        if (!f->tag_only[i].data || f->tag_only[i].size != f->identifier.size)
            return TLV_ERR_INVALID_ARG;
    return tlv_format_init(format, f, tlv_escaped_decode, tlv_escaped_measure, tlv_escaped_encode);
}
