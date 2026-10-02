// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/builtins/dhcp/dhcpv4.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    /* Caller supplies the option region, excluding packet header and cookie. */
    const uint8_t options[] = {0x00, 0x35, 0x01, 0x01, 0xFF, 0x00};
    uint8_t       encoded[sizeof(options)] = {0};
    tlv_reader_t  reader;
    tlv_writer_t  writer;
    if (tlv_reader_init(&reader, options, sizeof(options), &tlv_format_dhcpv4) != TLV_OK ||
        tlv_writer_init(&writer, encoded, sizeof(encoded), &tlv_format_dhcpv4) != TLV_OK)
        return 1;
    while (!tlv_reader_at_end(&reader)) {
        tlv_element_t element;
        if (tlv_reader_next(&reader, &element) != TLV_OK) return 1;
        if (tlv_writer_copy_element(&writer, &element) != TLV_OK) return 1;
        printf("Option %u\n", (unsigned)element.tag.data[0]);
        /* End policy belongs to the caller. The trailing Pad is not read. */
        if (element.tag.data[0] == 255) break;
    }
    return tlv_writer_size(&writer) == 5 && memcmp(options, encoded, 5) == 0 ? 0 : 1;
}
