/*
 * Single-element I/O over the fixed-width format, and the explicit
 * tlv_copy_value()/tlv_copy_encoded()/tlv_copy_view() helpers: each first
 * queries the storage it needs (a null destination with zero capacity),
 * then performs the copy.
 */
#include <string.h>
#include <stdio.h>
#include "tlv/builtins/fixed/fixed.h"
#include "tlv/copy.h"
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

int main(void) {
    /* One tag byte and one length byte; config must outlive its readers and writers. */
    const tlv_fixed_config_t config = {
        .tag_size = 1, .length_size = 1, .order = TLV_BYTE_ORDER_BIG_ENDIAN};
    tlv_reader_format_t reader_format;
    tlv_writer_format_t writer_format;
    CHECK(tlv_fixed_reader_format_init(&reader_format, &config));
    CHECK(tlv_fixed_writer_format_init(&writer_format, &config));

    uint8_t         input[32], owned[8], exact[32], serialized[32];
    const uint8_t   value[] = {0xAB, 0xCD};
    const tlv_tag_t tag = TLV_TAG(0x42);
    tlv_view_t      view;
    size_t          required, encoded_size, consumed, written;
    tlv_result_t    result;

    CHECK(tlv_encoded_size(tag, sizeof(value), &writer_format, &required));
    printf("Required encoded storage: %zu bytes\n", required);
    CHECK(
        tlv_write(input, sizeof(input), &writer_format, tag, value, sizeof(value), &encoded_size));
    CHECK(tlv_read(input, encoded_size, &reader_format, &view, &consumed));

    CHECK(tlv_copy_value(&view, NULL, 0, &required));
    printf("Required value storage: %zu bytes\n", required);
    result = tlv_copy_value(&view, owned, 1, &written);
    if (result != TLV_ERR_BUFFER_TOO_SHORT) return 1;
    printf("Expected capacity error: %s\n", tlv_strerror(result));
    CHECK(tlv_copy_value(&view, owned, sizeof(owned), &written));

    CHECK(tlv_copy_encoded(input, consumed, NULL, 0, &required));
    printf("Required exact-copy storage: %zu bytes\n", required);
    CHECK(tlv_copy_encoded(input, consumed, exact, sizeof(exact), &written));

    /* A view does not retain the original header. Serialization may normalize
     * it (e.g. BER lengths); copy_encoded preserves the original bytes. */
    CHECK(tlv_copy_view(&view, &writer_format, NULL, 0, &required));
    printf("Required serialized-view storage: %zu bytes\n", required);
    CHECK(tlv_copy_view(&view, &writer_format, serialized, sizeof(serialized), &written));

    /* The tag and the value both borrow the original input; point them at
     * storage that outlives it before the input is reused. */
    view.tag = tag;
    view.value.data = owned;
    memset(input, 0, sizeof(input));
    puts("Value after reusing input:");
    print_view(&view);

    CHECK(tlv_read(exact, consumed, &reader_format, &view, &written));
    puts("Exact encoded copy after reusing input:");
    print_view(&view);
    return 0;
}
