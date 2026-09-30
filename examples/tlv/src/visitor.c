/* Resumable push processing uses the same caller-owned Tree Reader as pull. */
#include "tlv/reader/walker.h"
#include "tlv/formats/fixed.h"
#include <stdio.h>

static int constructed(const void* context, const tlv_tag_t* tag) {
    (void)context;
    return tag->size == 1 && tag->data[0] >= 0x80;
}

static tlv_visit_result_t visit(const tlv_element_t* element, size_t depth, size_t offset,
                                void* context) {
    size_t* count = (size_t*)context;
    printf("Depth %zu, offset %zu, tag %u\n", depth, offset, (unsigned)element->tag.data[0]);
    ++*count;
    return *count == 1 ? TLV_VISIT_STOP : TLV_VISIT_CONTINUE;
}

int main(void) {
    const tlv_fixed_format_t config = {
        .tag_size = 1, .length_size = 1, .length_order = TLV_BYTE_ORDER_BIG_ENDIAN};
    tlv_format_t      format;
    tlv_tree_frame_t  frames[1];
    tlv_tree_reader_t reader;
    const uint8_t     first[] = {0xE1, 2, 1, 0};
    const uint8_t     last[] = {2, 0};
    size_t            count = 0;
    if (tlv_fixed_format_init(&format, &config) != TLV_OK) return 1;
    format.is_constructed = constructed;
    if (tlv_tree_reader_init_incremental(&reader, first, sizeof(first), &format, frames, 1, 1, 3) !=
        TLV_OK)
        return 1;
    /* STOP after the parent; the next invocation starts with its child. */
    if (tlv_tree_reader_visit(&reader, visit, &count, NULL) != TLV_OK || count != 1) return 1;
    if (tlv_tree_reader_visit(&reader, visit, &count, NULL) != TLV_NEED_MORE_DATA || count != 2)
        return 1;
    /* No borrowed results were retained; discard the completed subtree. */
    if (tlv_tree_reader_set_input(&reader, last, sizeof(last), tlv_tree_reader_consumed(&reader),
                                  1) != TLV_OK)
        return 1;
    if (tlv_tree_reader_visit(&reader, visit, &count, NULL) != TLV_OK) return 1;
    return count == 3 && tlv_tree_reader_at_end(&reader) ? 0 : 1;
}
