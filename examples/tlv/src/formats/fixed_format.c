/*
 * Defines a fixed-width TLV format at runtime: two tag bytes and a one-byte
 * length, then writes and reads one element. See tlv/formats/fixed.h.
 */
#include <stdio.h>
#include "tlv/formats/fixed.h"
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

int main(void) {
    const tlv_fixed_format_t config = {
        .tag_size = 2, .length_size = 1, .length_order = TLV_BYTE_ORDER_BIG_ENDIAN};
    /* config must outlive every reader and writer built from it. */
    tlv_format_t format;
    CHECK(tlv_fixed_format_init(&format, &config));

    const uint8_t value[] = {0xAA, 0xBB, 0xCC};
    uint8_t       encoded[16];
    size_t        written = 0, consumed = 0;
    tlv_element_t element;

    CHECK(tlv_write(encoded, sizeof(encoded), &format, (TLV_TAG(0x12, 0x34)), value, sizeof(value),
                    &written));
    /* Wire bytes: 12 34 03 AA BB CC. The tag is kept as is; the length is one byte. */
    CHECK(tlv_read(encoded, written, &format, &element, &consumed));

    return consumed == written && element.tag.size == 2 && element.value.size == sizeof(value) ? 0
                                                                                               : 1;
}
