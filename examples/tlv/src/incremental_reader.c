// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

/* Caller-owned sliding storage; Reader performs no I/O or buffering. */
#include "tlv/formats/fixed.h"
#include "tlv/reader/reader.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    const tlv_fixed_format_t config = {.identifier = {1}, .length = {1, TLV_BYTE_ORDER_BIG_ENDIAN}};
    tlv_format_t             format;
    tlv_reader_t             reader;
    const uint8_t            incoming[] = {1, 2, 0xAA, 0xBB, 2, 0};
    uint8_t window[4]; /* Smaller than the complete input, large enough for each element. */
    size_t  count = 0;
    if (tlv_fixed_format_init(&format, &config) != TLV_OK) return 1;
    if (tlv_reader_init_incremental(&reader, NULL, 0, &format) != TLV_OK) return 1;

    for (size_t i = 0; i < sizeof(incoming); ++i) {
        size_t discard = tlv_reader_consumed(&reader);
        size_t retained = reader.size - discard;
        /* Previous borrowed views have been released before moving these bytes. */
        memmove(window, window + discard, retained);
        if (retained == sizeof(window)) return 1;
        window[retained] = incoming[i];
        if (tlv_reader_set_input(&reader, window, retained + 1, discard,
                                 i + 1 == sizeof(incoming)) != TLV_OK)
            return 1;
        for (;;) {
            size_t        offset = tlv_reader_offset(&reader);
            tlv_element_t element;
            tlv_result_t  rc = tlv_reader_next(&reader, &element);
            if (rc == TLV_NEED_MORE_DATA || rc == TLV_END) break;
            if (rc != TLV_OK) return 1; /* Includes truncation once input is final. */
            printf("Element at offset %zu, tag %u\n", offset, (unsigned)element.tag.data[0]);
            ++count; /* Consume the borrowed view before the next window update. */
        }
    }
    return count == 2 && tlv_reader_at_end(&reader) &&
                   tlv_reader_offset(&reader) == sizeof(incoming)
               ? 0
               : 1;
}
