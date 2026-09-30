#include "tlv/builtins/nfc/type2.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    /* A contiguous TLV stream from the data area, not a physical memory dump. */
    const uint8_t stream[] = {0x00, 0x03, 0x03, 0xD1, 0x01, 0x00, 0xFE};
    uint8_t       encoded[sizeof(stream)] = {0};
    tlv_reader_t  reader;
    tlv_writer_t  writer;
    if (tlv_reader_init(&reader, stream, sizeof(stream), &tlv_format_nfc_type2) != TLV_OK ||
        tlv_writer_init(&writer, encoded, sizeof(encoded), &tlv_format_nfc_type2) != TLV_OK)
        return 1;
    while (!tlv_reader_at_end(&reader)) {
        tlv_element_t element;
        if (tlv_reader_next(&reader, &element) != TLV_OK) return 1;
        /* Preserve NULL in the output, even though the display hides it. */
        if (tlv_writer_copy_element(&writer, &element) != TLV_OK) return 1;
        if (element.tag.data[0] == TLV_NFC_TYPE2_NULL) continue;
        if (element.tag.data[0] == TLV_NFC_TYPE2_TERMINATOR) {
            puts("TERMINATOR");
            break; /* Termination policy belongs to the caller. */
        }
        if (element.tag.data[0] == TLV_NFC_TYPE2_NDEF_MESSAGE) {
            printf("NDEF_MESSAGE:");
            for (size_t i = 0; i < (size_t)element.value.size; ++i)
                printf(" %02X", (unsigned)element.value.data[i]);
            puts("");
        }
    }
    return tlv_writer_size(&writer) == sizeof(stream) &&
                   memcmp(stream, encoded, sizeof(stream)) == 0
               ? 0
               : 1;
}
