// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

/*
 * A fully custom format: one raw tag byte and a two-byte little-endian
 * length field, all built from hand-written callbacks. Callbacks also
 * support writer size queries (a NULL destination with zero capacity).
 */
#include <stdint.h>
#include <stdio.h>
#include "tlv/endian.h"
#include "tlv/layout.h"
#include "tlv/size.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"

#define CHECK(call)                                                                                \
    do {                                                                                           \
        tlv_result_t rc_ = (call);                                                                 \
        if (rc_ != TLV_OK) {                                                                       \
            fprintf(stderr, "%s: %s\n", #call, tlv_strerror(rc_));                                 \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

static void print_element(const tlv_element_t* element) {
    size_t i, length;
    printf("tag=");
    for (i = 0; i < element->tag.size; ++i) printf("%02X", (unsigned)element->tag.data[i]);
    if (tlv_size_to_native(element->value.size, &length) != TLV_OK) {
        printf(" length=<unrepresentable>\n");
        return;
    }
    printf(" length=%zu value=", length);
    for (i = 0; i < length; ++i) printf("%02X ", (unsigned)element->value.data[i]);
    putchar('\n');
}

static tlv_result_t read_tag_1byte(const void* context, const uint8_t* data, size_t size,
                                   tlv_tag_t* tag, size_t* consumed) {
    (void)context;
    if (!size) return TLV_ERR_BUFFER_TOO_SHORT;
    *tag = tlv_tag(data, 1);
    *consumed = 1;
    return TLV_OK;
}
static tlv_result_t write_tag_1byte(const void* context, uint8_t* data, size_t capacity,
                                    const tlv_tag_t* tag, size_t* written) {
    (void)context;
    if (tag->size != 1) return TLV_ERR_INVALID_TAG_SIZE;
    if (!tag->data) return TLV_ERR_NULL_ARG;
    *written = 1;
    if (!data) return TLV_OK;
    if (!capacity) return TLV_ERR_BUFFER_TOO_SHORT;
    data[0] = tag->data[0];
    return TLV_OK;
}

static tlv_result_t read_length_le16(const void* context, const uint8_t* data, size_t size,
                                     tlv_size_t* length, size_t* consumed) {
    (void)context;
    if (size < sizeof(uint16_t)) return TLV_ERR_BUFFER_TOO_SHORT;
    *length = tlv_read_u16_le(data);
    *consumed = sizeof(uint16_t);
    return TLV_OK;
}
static tlv_result_t length_size_le16(const void* context, tlv_size_t length, size_t* size) {
    (void)context;
    if (length > UINT16_MAX) return TLV_ERR_INVALID_LENGTH;
    *size = sizeof(uint16_t);
    return TLV_OK;
}
static tlv_result_t write_length_le16(const void* context, uint8_t* data, size_t capacity,
                                      tlv_size_t length, size_t* written) {
    size_t       required;
    tlv_result_t result = length_size_le16(context, length, &required);
    if (result != TLV_OK) return result;
    if (capacity < required) return TLV_ERR_BUFFER_TOO_SHORT;
    tlv_write_u16_le(data, (uint16_t)length);
    *written = required;
    return TLV_OK;
}

int main(void) {
    tlv_format_t  format;
    uint8_t       encoded[16];
    const uint8_t value[] = {0xAA};
    tlv_element_t element;
    size_t        written, consumed;

    const tlv_field_layout_t layout = {NULL,
                                       read_tag_1byte,
                                       read_length_le16,
                                       NULL,
                                       write_tag_1byte,
                                       write_length_le16,
                                       length_size_le16,
                                       TLV_ELEMENT_ORDER_TLV,
                                       TLV_LENGTH_SCOPE_VALUE};
    CHECK(tlv_fields_format_init(&format, &layout));
    /* format and its optional immutable context must outlive their users. */
    CHECK(tlv_write(encoded, sizeof(encoded), &format, TLV_TAG(1), value, sizeof(value), &written));
    CHECK(tlv_read(encoded, written, &format, &element, &consumed));
    print_element(&element);
    return 0;
}
