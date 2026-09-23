/*
 * A custom format: reuses the fixed-format tag callbacks, but replaces the
 * length with a two-byte little-endian field. Callbacks also support writer
 * size queries (a NULL destination with zero capacity).
 */
#include <stdint.h>
#include <stdio.h>
#include "tlv/builtins/fixed/fixed_1byte.h"
#include "tlv/endian.h"
#include "tlv/format.h"
#include "tlv/length.h"
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

static void print_view(const tlv_view_t* view) {
    size_t i, length;
    printf("tag=");
    for (i = 0; i < view->tag.size; ++i) printf("%02X", (unsigned)view->tag.data[i]);
    if (tlv_length_to_size(view->value.length, &length) != TLV_OK) {
        printf(" length=<unrepresentable>\n");
        return;
    }
    printf(" length=%zu value=", length);
    for (i = 0; i < length; ++i) printf("%02X ", (unsigned)view->value.data[i]);
    putchar('\n');
}

static tlv_result_t read_length_le16(const void* context, const uint8_t* data, size_t size,
                                     size_t* length, size_t* consumed) {
    (void)context;
    if (size < sizeof(uint16_t)) return TLV_ERR_BUFFER_TOO_SHORT;
    *length = tlv_read_u16_le(data);
    *consumed = sizeof(uint16_t);
    return TLV_OK;
}
static tlv_result_t length_size_le16(const void* context, size_t length, size_t* size) {
    (void)context;
    if (length > UINT16_MAX) return TLV_ERR_INVALID_LENGTH;
    *size = sizeof(uint16_t);
    return TLV_OK;
}
static tlv_result_t write_length_le16(const void* context, uint8_t* data, size_t capacity,
                                      size_t length, size_t* written) {
    size_t       required;
    tlv_result_t result = length_size_le16(context, length, &required);
    if (result != TLV_OK) return result;
    if (capacity < required) return TLV_ERR_BUFFER_TOO_SHORT;
    tlv_write_u16_le(data, (uint16_t)length);
    *written = required;
    return TLV_OK;
}

int main(void) {
    tlv_reader_format_t format;
    tlv_writer_format_t writer_format;
    uint8_t             encoded[16];
    const uint8_t       value[] = {0xAA};
    tlv_view_t          view;
    size_t              written, consumed;

    CHECK(tlv_reader_format_init(&format, NULL, tlv_reader_format_fixed_1byte.read_tag,
                                 read_length_le16));
    CHECK(tlv_writer_format_init(&writer_format, NULL, tlv_writer_format_fixed_1byte.write_tag,
                                 write_length_le16, length_size_le16));
    /* format and its optional immutable context must outlive their users. */
    CHECK(tlv_write(encoded, sizeof(encoded), &writer_format, TLV_TAG(1), value, sizeof(value),
                    &written));
    CHECK(tlv_read(encoded, written, &format, &view, &consumed));
    print_view(&view);
    return 0;
}
