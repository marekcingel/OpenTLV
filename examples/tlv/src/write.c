/*
 * Builds the same nested BER-TLV document parse.c reads, encoding the
 * innermost elements first and using each encoded result as the next
 * level's value: the standard way to build constructed TLV bottom-up.
 */
#include <stdio.h>
#include <string.h>
#include "tlv/builtins/asn1/ber.h"
#include "tlv/writer/writer.h"

/* Same bytes as parse.c's document. */
static const uint8_t expected[] = {0x6F, 0x0A, 0x84, 0x03, 0x41, 0x42,
                                   0x43, 0xA5, 0x03, 0x50, 0x01, 0x01};

#define CHECK(call)                                                                                \
    do {                                                                                           \
        if ((call) != TLV_OK) {                                                                    \
            fprintf(stderr, "%s failed\n", #call);                                                 \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

int main(void) {
    const uint8_t application_label = 0x01;
    uint8_t       df_name[5], proprietary[8], value[16], document[20];
    size_t        df_name_size, application_label_size, proprietary_size, value_size, document_size;

    CHECK(tlv_write(df_name, sizeof(df_name), &tlv_writer_format_ber, TLV_TAG(0x84),
                    (const uint8_t*)"ABC", 3, &df_name_size));
    {
        uint8_t label[3];
        CHECK(tlv_write(label, sizeof(label), &tlv_writer_format_ber, TLV_TAG(0x50),
                        &application_label, 1, &application_label_size));
        CHECK(tlv_write(proprietary, sizeof(proprietary), &tlv_writer_format_ber, TLV_TAG(0xA5),
                        label, application_label_size, &proprietary_size));
    }

    memcpy(value, df_name, df_name_size);
    memcpy(value + df_name_size, proprietary, proprietary_size);
    value_size = df_name_size + proprietary_size;

    CHECK(tlv_write(document, sizeof(document), &tlv_writer_format_ber, TLV_TAG(0x6F), value,
                    value_size, &document_size));

    printf("Wrote %zu bytes\n", document_size);
    return document_size == sizeof(expected) && memcmp(document, expected, document_size) == 0 ? 0
                                                                                               : 1;
}
