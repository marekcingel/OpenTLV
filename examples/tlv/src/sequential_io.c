/*
 * Sequential writer and zero-copy reader over BER: appends
 * several elements with different write calls, then reads them back.
 * All storage belongs to the caller; nothing here allocates.
 */
#include <stdio.h>
#include "tlv/builtins/asn1/ber.h"
#include "tlv/size.h"
#include "tlv/reader/reader.h"
#include "tlv/value.h"
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

int main(void) {
    uint8_t       buffer[64], prebuilt[16];
    tlv_writer_t  writer;
    tlv_reader_t  reader;
    tlv_element_t element;
    size_t        prebuilt_size;

    CHECK(tlv_writer_init(&writer, buffer, sizeof(buffer), &tlv_format_ber));
    CHECK(tlv_writer_write(&writer, TLV_TAG(1), (const uint8_t*)"hello", 5));
    CHECK(tlv_writer_write(&writer, TLV_TAG(2), (const uint8_t*)"world", 5));
    /* tlv_writer_copy_element appends a element (borrowed value, no ownership transfer)
     * at the writer's current position, serialized with the writer's format. */
    element.tag = TLV_TAG(3);
    CHECK(tlv_value_init((const uint8_t*)"copied", 6, &element.value));
    CHECK(tlv_writer_copy_element(&writer, &element));
    /* tlv_writer_copy_encoded appends an exact, already-encoded byte range
     * (e.g. produced separately by tlv_write) without reinterpreting it. */
    CHECK(tlv_write(prebuilt, sizeof(prebuilt), &tlv_format_ber, TLV_TAG(4),
                    (const uint8_t*)"exact", 5, &prebuilt_size));
    CHECK(tlv_writer_copy_encoded(&writer, prebuilt, prebuilt_size));
    printf("Wrote %zu bytes\n", tlv_writer_size(&writer));

    CHECK(tlv_reader_init(&reader, buffer, tlv_writer_size(&writer), &tlv_format_ber));
    while (!tlv_reader_at_end(&reader)) {
        CHECK(tlv_reader_next(&reader, &element));
        /* element.value borrows buffer; keep buffer alive while using the element. */
        print_element(&element);
    }
    return 0;
}
