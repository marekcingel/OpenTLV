/* Nested output with caller-owned frames, destination and scratch storage. */
#include "tlv/writer/tree.h"
#include "tlv/formats/fixed.h"
#include <string.h>

static int constructed(const void* context, const tlv_tag_t* tag) {
    (void)context;
    return tag->size == 1 && tag->data[0] >= 0x80;
}

int main(void) {
    const tlv_fixed_format_t config = {
        .tag_size = 1, .length_size = 1, .length_order = TLV_BYTE_ORDER_BIG_ENDIAN};
    tlv_format_t            format;
    uint8_t                 output[64], scratch[64];
    tlv_tree_writer_frame_t frames[2];
    tlv_tree_writer_t       writer;
    const uint8_t           value_a[] = {0xAA}, value_b[] = {0xBB};
    const tlv_element_t     a = {TLV_TAG(0x01), {value_a, sizeof(value_a)}};
    const tlv_element_t     b = {TLV_TAG(0x02), {value_b, sizeof(value_b)}};
    const uint8_t           expected[] = {0xE1, 8, 1, 1, 0xAA, 0xE2, 3, 2, 1, 0xBB};
    if (tlv_fixed_format_init(&format, &config) != TLV_OK) return 1;
    format.is_constructed = constructed;
    if (tlv_tree_writer_init(&writer, output, sizeof(output), &format, frames, 2, scratch,
                             sizeof(scratch), TLV_TREE_DEFAULT_DEPTH, SIZE_MAX) != TLV_OK)
        return 1;
    if (tlv_tree_writer_begin(&writer, TLV_TAG(0xE1)) != TLV_OK) return 1;
    if (tlv_tree_writer_write_element(&writer, &a) != TLV_OK) return 1;
    if (tlv_tree_writer_begin(&writer, TLV_TAG(0xE2)) != TLV_OK) return 1;
    if (tlv_tree_writer_write_element(&writer, &b) != TLV_OK) return 1;
    if (tlv_tree_writer_end(&writer) != TLV_OK) return 1;
    if (tlv_tree_writer_size(&writer) != 0) return 1; /* Outer root is still open. */
    if (tlv_tree_writer_end(&writer) != TLV_OK) return 1;
    if (tlv_tree_writer_finish(&writer) != TLV_OK) return 1;
    return tlv_tree_writer_size(&writer) == sizeof(expected) &&
                   memcmp(output, expected, sizeof(expected)) == 0
               ? 0
               : 1;
}
