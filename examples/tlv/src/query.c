/*
 * Addresses the Application Label directly by path, `6F/A5/50`, without
 * walking the whole document by hand. See parse.c for the document itself.
 */
#include <stdio.h>
#include "tlv/builtins/asn1/ber.h"
#include "tlv/length.h"
#include "tlv/query/query.h"

/* Same bytes as parse.c's document. */
static const uint8_t document[] = {0x6F, 0x0A, 0x84, 0x03, 0x41, 0x42,
                                   0x43, 0xA5, 0x03, 0x50, 0x01, 0x01};

static tlv_visit_result_t print_match(const tlv_view_t* view, size_t depth, size_t offset,
                                      void* context) {
    int*   found = (int*)context;
    size_t length;
    (void)depth;
    if (tlv_length_to_size(view->value.length, &length) != TLV_OK) return TLV_VISIT_ERROR;
    printf("6F/A5/50 = %02X (offset %zu)\n", view->value.data[0], offset);
    *found = length == 1 && view->value.data[0] == 0x01;
    return TLV_VISIT_CONTINUE;
}

int main(void) {
    tlv_query_t query;
    int         found = 0;
    if (tlv_query_parse("6F/A5/50", &query, NULL) != TLV_OK) return 1;
    if (tlv_query_walk(document, sizeof(document), &tlv_reader_format_ber, tlv_ber_is_constructed,
                       &query, TLV_WALK_MAX_DEPTH, 16, print_match, &found, NULL) != TLV_OK)
        return 1;
    return found ? 0 : 1;
}
