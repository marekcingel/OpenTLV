/*
 * Defines a fixed-width TLV format at runtime: two tag bytes and a one-byte
 * length, then writes and reads one element. See tlv/builtins/fixed/fixed.h.
 */
#include <stdio.h>
#include "tlv/builtins/fixed/fixed.h"
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
    const tlv_fixed_config_t config = {
        .tag_size = 2, .length_size = 1, .order = TLV_BYTE_ORDER_BIG_ENDIAN};
    /* config must outlive every reader and writer built from it. */
    tlv_reader_format_t reader_format;
    tlv_writer_format_t writer_format;
    CHECK(tlv_fixed_reader_format_init(&reader_format, &config));
    CHECK(tlv_fixed_writer_format_init(&writer_format, &config));

    const uint8_t value[] = {0xAA, 0xBB, 0xCC};
    uint8_t       encoded[16];
    size_t        written = 0, consumed = 0;
    tlv_view_t    view;

    CHECK(tlv_write(encoded, sizeof(encoded), &writer_format, (TLV_TAG(0x12, 0x34)), value,
                    sizeof(value), &written));
    /* Wire bytes: 12 34 03 AA BB CC. The tag is kept as is; the length is one byte. */
    CHECK(tlv_read(encoded, written, &reader_format, &view, &consumed));

    return consumed == written && view.tag.size == 2 && view.value.length == sizeof(value) ? 0 : 1;
}
