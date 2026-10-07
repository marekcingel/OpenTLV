// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include <stdio.h>
#include "tlv/formats/fixed.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"

int main(void) {
    /* One tag byte and one length byte; config must outlive its readers and writers. */
    const tlv_fixed_format_t config = {.identifier = {1}, .length = {1, TLV_BYTE_ORDER_BIG_ENDIAN}};
    tlv_format_t             format;
    if (tlv_fixed_format_init(&format, &config) != TLV_OK) return 1;

    const uint8_t value[] = "Hello, world!";
    uint8_t       buffer[64];
    size_t        written = 0, consumed = 0;
    tlv_element_t element;

    /* sizeof(value) - 1 excludes the trailing NUL. */
    if (tlv_write(buffer, sizeof(buffer), &format, TLV_TAG(0x01), value, sizeof(value) - 1,
                  &written) != TLV_OK)
        return 1;
    if (tlv_read(buffer, written, &format, &element, &consumed) != TLV_OK) return 1;

    /* element.value borrows buffer; keep it alive while using the element. */
    printf("%.*s\n", (int)element.value.size, (const char*)element.value.data);
    return 0;
}
