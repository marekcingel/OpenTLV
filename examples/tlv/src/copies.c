// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

/*
 * Single-element I/O over the fixed-width format, and the explicit
 * tlv_copy_value()/tlv_copy_encoded()/tlv_copy_element() helpers: each first
 * queries the storage it needs (a null destination with zero capacity),
 * then performs the copy.
 */
#include <string.h>
#include <stdio.h>
#include "tlv/formats/fixed.h"
#include "tlv/copy.h"
#include "tlv/size.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"

#define CHECK(call)                                                                                \
    do {                                                                                           \
        tlv_result_t rc_ = (call);                                                                 \
        if (rc_ != TLV_OK) {                                                                       \
            fprintf(stderr, "%s: %s\n", #call, tlv_result_string(rc_));                            \
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

int main(void) {
    /* One tag byte and one length byte; config must outlive its readers and writers. */
    const tlv_fixed_format_t config = {.identifier = {1}, .length = {1, TLV_BYTE_ORDER_BIG_ENDIAN}};
    tlv_format_t             format;
    CHECK(tlv_fixed_format_init(&format, &config));

    uint8_t         input[32], owned[8], exact[32], serialized[32];
    const uint8_t   value[] = {0xAB, 0xCD};
    const tlv_tag_t tag = TLV_TAG(0x42);
    tlv_element_t   element;
    size_t          required, encoded_size, consumed, written;
    tlv_result_t    result;

    CHECK(tlv_encoded_size(tag, sizeof(value), &format, &required));
    printf("Required encoded storage: %zu bytes\n", required);
    CHECK(tlv_write(input, sizeof(input), &format, tag, value, sizeof(value), &encoded_size));
    CHECK(tlv_read(input, encoded_size, &format, &element, &consumed));

    CHECK(tlv_copy_value(&element, NULL, 0, &required));
    printf("Required value storage: %zu bytes\n", required);
    result = tlv_copy_value(&element, owned, 1, &written);
    if (result != TLV_ERR_BUFFER_TOO_SHORT) return 1;
    printf("Expected capacity error: %s\n", tlv_result_string(result));
    CHECK(tlv_copy_value(&element, owned, sizeof(owned), &written));

    CHECK(tlv_copy_encoded(input, consumed, NULL, 0, &required));
    printf("Required exact-copy storage: %zu bytes\n", required);
    CHECK(tlv_copy_encoded(input, consumed, exact, sizeof(exact), &written));

    /* A element does not retain the original header. Serialization may normalize
     * it (e.g. BER lengths); copy_encoded preserves the original bytes. */
    CHECK(tlv_copy_element(&element, &format, NULL, 0, &required));
    printf("Required serialized-element storage: %zu bytes\n", required);
    CHECK(tlv_copy_element(&element, &format, serialized, sizeof(serialized), &written));

    /* The tag and the value both borrow the original input; point them at
     * storage that outlives it before the input is reused. */
    element.tag = tag;
    element.value.data = owned;
    memset(input, 0, sizeof(input));
    puts("Value after reusing input:");
    print_element(&element);

    CHECK(tlv_read(exact, consumed, &format, &element, &written));
    puts("Exact encoded copy after reusing input:");
    print_element(&element);
    return 0;
}
