// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

/* A caller-owned stack and input window; no allocation or recursion in Tree Reader. */
#include "tlv/reader/tree.h"
#include "tlv/formats/fixed.h"
#include <stdio.h>

static int constructed(const void* context, const tlv_tag_t* tag) {
    (void)context;
    return tag->size == 1 && tag->data[0] >= 0x80;
}

int main(void) {
    const tlv_fixed_format_t config = {
        .tag_size = 1, .length_size = 1, .length_order = TLV_BYTE_ORDER_BIG_ENDIAN};
    tlv_format_t      format;
    tlv_tree_frame_t  frames[TLV_TREE_DEFAULT_DEPTH];
    tlv_tree_reader_t reader;
    tlv_tree_event_t  item;
    /* E1 contains 01 and E2, which contains 02. */
    const uint8_t wire[] = {0xE1, 6, 1, 0, 0xE2, 2, 2, 0};
    const uint8_t next_root[] = {3, 0};
    size_t        count = 0;
    if (tlv_fixed_format_init(&format, &config) != TLV_OK) return 1;
    format.is_constructed = constructed;
    if (tlv_tree_reader_init_incremental(&reader, wire, 5, &format, frames, TLV_TREE_DEFAULT_DEPTH,
                                         TLV_TREE_DEFAULT_DEPTH, 5) != TLV_OK)
        return 1;
    /* No partial parent Element is published. */
    if (tlv_tree_reader_next_event(&reader, &item) != TLV_NEED_MORE_DATA) return 1;
    if (tlv_tree_reader_set_input(&reader, wire, sizeof(wire), 0, 0) != TLV_OK) return 1;
    for (;;) {
        tlv_result_t rc = tlv_tree_reader_next_event(&reader, &item);
        if (rc == TLV_NEED_MORE_DATA) break;
        if (rc != TLV_OK) return 1;
        if (item.kind == TLV_TREE_END) {
            printf("END depth %zu%s\n", item.depth, item.skipped ? " (skipped)" : "");
            continue;
        }
        printf("Depth %zu, offset %zu, tag %u\n", item.depth, item.offset,
               (unsigned)item.element.tag.data[0]);
        ++count;
        if (item.element.tag.data[0] == 0xE2 && tlv_tree_reader_skip_subtree(&reader) != TLV_OK)
            return 1;
    }
    /* No old views are used from this point. Replace the consumed subtree. */
    if (tlv_tree_reader_set_input(&reader, next_root, sizeof(next_root),
                                  tlv_tree_reader_consumed(&reader), 1) != TLV_OK)
        return 1;
    if (tlv_tree_reader_next_event(&reader, &item) != TLV_OK || item.offset != sizeof(wire) ||
        item.depth != 0)
        return 1;
    return count == 3 && tlv_tree_reader_at_end(&reader) ? 0 : 1;
}
