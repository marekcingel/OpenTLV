/*
 * BER: a multi-byte tag when supported by the profile, and a long-form
 * length for a value over 127 bytes.
 */
#include <stdio.h>
#include "tlv/builtins/asn1/ber.h"
#include "tlv/length.h"
#include "tlv/reader/reader.h"

#define CHECK(call)                                                                                \
    do {                                                                                           \
        tlv_result_t rc_ = (call);                                                                 \
        if (rc_ != TLV_OK) {                                                                       \
            fprintf(stderr, "%s: %s\n", #call, tlv_strerror(rc_));                                 \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

int main(void) {
    const tlv_tag_t tag = TLV_TAG(0x9F, 0x1C);
    uint8_t         value[128] = {0}, encoded[144];
    size_t          required, written, consumed;
    tlv_view_t      view;

    CHECK(tlv_encoded_size(tag, sizeof(value), &tlv_writer_format_ber, &required));
    CHECK(tlv_write(encoded, sizeof(encoded), &tlv_writer_format_ber, tag, value, sizeof(value),
                    &written));
    CHECK(tlv_read(encoded, written, &tlv_reader_format_ber, &view, &consumed));

    {
        size_t value_length;
        CHECK(tlv_length_to_size(view.value.length, &value_length));
        printf("Tag bytes: %u, value bytes: %zu, encoded bytes: %zu\n", (unsigned)view.tag.size,
               value_length, required);
    }
    return 0;
}
