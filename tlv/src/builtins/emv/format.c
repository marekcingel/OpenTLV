// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/builtins/emv/format.h"
#include "tlv/formats/variable.h"

/* Book 3 v4.4 Annex B. These are EMV policies, not ASN.1 constraints. */
static const tlv_variable_identifier_t identifier = {0x1f, 0x1f, 0x80, 0x7f, 2};
static const tlv_variable_length_t count = {0x80, 0x7f, TLV_BYTE_ORDER_BIG_ENDIAN};

static tlv_result_t tag_policy(const uint8_t* data, size_t size) {
    if (size && data[0] == 0) return TLV_ERR_INVALID_TAG;
    if (size > 1 && (data[0] & 0x1f) == 0x1f && !(data[1] & 0x7f)) return TLV_ERR_INVALID_TAG;
    return TLV_OK;
}

static tlv_result_t read_tag(const void* context, const uint8_t* data, size_t size, tlv_tag_t* tag,
                             size_t* used) {
    tlv_result_t rc;
    (void)context;
    rc = tag_policy(data, size);
    if (rc != TLV_OK) return rc;
    return tlv_variable_identifier_read(&identifier, data, size, tag, used);
}

static tlv_result_t write_tag(const void* context, uint8_t* data, size_t capacity,
                              const tlv_tag_t* tag, size_t* used) {
    tlv_result_t rc;
    (void)context;
    rc = tag_policy(tag->data, tag->size);
    if (rc != TLV_OK) return rc;
    return tlv_variable_identifier_write(&identifier, tag, data, capacity, used);
}

static tlv_result_t read_length(const void* context, const uint8_t* data, size_t size,
                                tlv_size_t* length, size_t* used) {
    (void)context;
    if (size && (data[0] == 0x80 || data[0] > 0x82)) {
        *used = 1;
        return TLV_ERR_INVALID_LENGTH;
    }
    return tlv_variable_length_read(&count, data, size, length, used);
}

static tlv_result_t write_length(const void* context, uint8_t* data, size_t capacity,
                                 tlv_size_t length, size_t* used) {
    (void)context;
    if (length > 65535) return TLV_ERR_INVALID_LENGTH;
    return tlv_variable_length_write(&count, length, data, capacity, used);
}

static tlv_result_t length_size(const void* context, tlv_size_t length, size_t* size) {
    return write_length(context, NULL, 0, length, size);
}

static int is_constructed(const void* context, const tlv_tag_t* tag) {
    (void)context;
    return tag && tag->data && tag->size && (tag->data[0] & 0x20) != 0;
}

static const tlv_field_layout_t fields = {.read_tag = read_tag,
                                          .read_length = read_length,
                                          .write_tag = write_tag,
                                          .write_length = write_length,
                                          .length_size = length_size};

const tlv_format_t tlv_format_emv = {&fields, tlv_fields_decode, tlv_fields_measure,
                                     tlv_fields_encode, is_constructed};
