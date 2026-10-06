// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/formats/variable.h"
#include "../field/variable_internal.h"

static tlv_result_t read_tag(const void* context, const uint8_t* data, size_t size, tlv_tag_t* tag,
                             size_t* consumed) {
    const tlv_variable_format_t* c = (const tlv_variable_format_t*)context;
    return tlv_variable_identifier_read(&c->identifier, data, size, tag, consumed);
}

static tlv_result_t write_tag(const void* context, uint8_t* data, size_t capacity,
                              const tlv_tag_t* tag, size_t* written) {
    const tlv_variable_format_t* c = (const tlv_variable_format_t*)context;
    return tlv_variable_identifier_write(&c->identifier, tag, data, capacity, written);
}

static tlv_result_t read_length(const void* context, const uint8_t* data, size_t size,
                                tlv_size_t* length, size_t* consumed) {
    const tlv_variable_format_t* c = (const tlv_variable_format_t*)context;
    return tlv_variable_length_read(&c->length, data, size, length, consumed);
}

static tlv_result_t write_length(const void* context, uint8_t* data, size_t capacity,
                                 tlv_size_t length, size_t* written) {
    const tlv_variable_format_t* c = (const tlv_variable_format_t*)context;
    return tlv_variable_length_write(&c->length, length, data, capacity, written);
}

static tlv_result_t length_size(const void* context, tlv_size_t length, size_t* size) {
    return write_length(context, NULL, 0, length, size);
}

static tlv_field_composition_t variable_fields(const tlv_variable_format_t* config) {
    tlv_field_composition_t fields = {0};
    fields.context = config;
    fields.read_tag = read_tag;
    fields.read_length = read_length;
    fields.write_tag = write_tag;
    fields.write_length = write_length;
    fields.length_size = length_size;
    fields.order = config->element_order;
    fields.scope = config->length_scope;
    return fields;
}

tlv_result_t tlv_variable_fields_init(tlv_field_composition_t* fields,
                                      const tlv_variable_format_t* config) {
    tlv_result_t rc;
    if (!fields || !config) return TLV_ERR_NULL_ARG;
    rc = identifier_validate(&config->identifier);
    if (rc != TLV_OK) return rc;
    rc = length_validate(&config->length);
    if (rc != TLV_OK) return rc;
    if ((config->element_order != TLV_ELEMENT_ORDER_TLV &&
         config->element_order != TLV_ELEMENT_ORDER_LTV) ||
        (config->length_scope != TLV_LENGTH_SCOPE_VALUE &&
         config->length_scope != TLV_LENGTH_SCOPE_TAG_AND_VALUE))
        return TLV_ERR_INVALID_ARG;
    *fields = variable_fields(config);
    return TLV_OK;
}

static tlv_result_t variable_decode(const void* context, const uint8_t* data, size_t size,
                                    tlv_decoded_t* decoded, tlv_format_error_t* error) {
    tlv_field_composition_t fields = variable_fields((const tlv_variable_format_t*)context);
    return tlv_fields_decode(&fields, data, size, decoded, error);
}

static tlv_result_t variable_measure(const void* context, const tlv_element_t* element,
                                     tlv_encoding_t* encoding, tlv_format_error_t* error) {
    tlv_field_composition_t fields = variable_fields((const tlv_variable_format_t*)context);
    return tlv_fields_measure(&fields, element, encoding, error);
}

static tlv_result_t variable_encode(const void* context, const tlv_element_t* element,
                                    uint8_t* data, size_t capacity, size_t* written,
                                    tlv_format_error_t* error) {
    tlv_field_composition_t fields = variable_fields((const tlv_variable_format_t*)context);
    return tlv_fields_encode(&fields, element, data, capacity, written, error);
}

tlv_result_t tlv_variable_format_init(tlv_format_t* format, const tlv_variable_format_t* config) {
    tlv_field_composition_t fields;
    tlv_result_t rc;
    if (!format) return TLV_ERR_NULL_ARG;
    rc = tlv_variable_fields_init(&fields, config);
    if (rc != TLV_OK) return rc;
    return tlv_format_init(format, config, variable_decode, variable_measure, variable_encode);
}
