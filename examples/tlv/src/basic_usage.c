/*
 * Simple example of using the C core: writes two TLV items
 * and then immediately reads them back.
 */
#include <stdio.h>
#include <string.h>
#include "tlv/reader.h"
#include "tlv/writer.h"

int main(void) {
    uint8_t buf[64];
    tlv_writer_t writer;
    tlv_writer_init(&writer, buf, sizeof(buf));

    tlv_writer_write(&writer, (tlv_tag_t){{0x01}, 1}, (const uint8_t*)"hello", 5);
    tlv_writer_write(&writer, (tlv_tag_t){{0x02}, 1}, (const uint8_t*)"world", 5);

    printf("Wrote %zu bytes\n", tlv_writer_size(&writer));

    tlv_reader_t reader;
    tlv_reader_init(&reader, buf, tlv_writer_size(&writer));

    tlv_view_t entry;
    while (!tlv_reader_at_end(&reader)) {
        tlv_result_t rc = tlv_reader_next(&reader, &entry);
        if (rc != TLV_OK) {
            fprintf(stderr, "Error: %s\n", tlv_strerror(rc));
            return 1;
        }
        printf("tag=0x%02x len=%zu value=%.*s\n",
               entry.tag.data[0], entry.value.length, (int)entry.value.length,
               entry.value.data);
    }

    return 0;
}
