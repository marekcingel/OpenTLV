/*
 * Parses a nested BER-TLV document and prints every element in document
 * order. See write.c for building the same bytes, query.c for addressing one
 * field directly, and validate.c for checking the document's structure
 * without decoding it. The C++, Rust and JavaScript "parse" examples parse
 * the same bytes and report the same fields.
 */
#include <stdio.h>
#include "tlv/builtins/asn1/ber.h"
#include "tlv/length.h"
#include "tlv/reader/walker.h"

/* An FCI Template (6F) holding a DF Name (84) and an FCI Proprietary
 * Template (A5) holding an Application Label (50). */
static const uint8_t document[] = {0x6F, 0x0A, 0x84, 0x03, 0x41, 0x42,
                                   0x43, 0xA5, 0x03, 0x50, 0x01, 0x01};

static tlv_visit_result_t print_element(const tlv_view_t* view, size_t depth, size_t offset,
                                        void* context) {
    size_t* count = (size_t*)context;
    size_t  length, i;
    (void)offset;
    if (tlv_length_to_size(view->value.length, &length) != TLV_OK) return TLV_VISIT_ERROR;
    for (i = 0; i < depth; ++i) printf("  ");
    printf("tag=%02X length=%zu value=", view->tag.data[0], length);
    for (i = 0; i < length; ++i) printf("%02X", (unsigned)view->value.data[i]);
    putchar('\n');
    ++*count;
    return TLV_VISIT_CONTINUE;
}

int main(void) {
    size_t count = 0;
    if (tlv_walk_tree(document, sizeof(document), &tlv_reader_format_ber, tlv_ber_is_constructed,
                      TLV_WALK_MAX_DEPTH, 16, print_element, &count, NULL) != TLV_OK)
        return 1;
    /* 6F, its two children (84, A5) and A5's child (50). */
    return count == 4 ? 0 : 1;
}
