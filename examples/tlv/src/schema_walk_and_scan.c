/*
 * Applying a length schema inside a tlv_walk() visitor, and recovering
 * candidate elements from noisy input with tlv_scan()'s schema filter.
 * Parsing never applies a schema automatically; the visitor below does.
 */
#include <stdio.h>
#include "tlv/builtins/fixed/fixed_1byte.h"
#include "tlv/length.h"
#include "tlv/reader/scanner.h"
#include "tlv/reader/walker.h"
#include "tlv/schema/schema.h"

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

/* A schema table holds borrowed tags, so their bytes need static storage. */
static const uint8_t            tag_one[] = {1};
static const uint8_t            tag_two[] = {2};
static const tlv_schema_entry_t schema_entries[] = {
    {{tag_one, sizeof(tag_one)}, 2, 2, 0, NULL}, /* Exact length. */
    {{tag_two, sizeof(tag_two)}, 0, 4, 0, NULL}  /* Inclusive length range. */
};
static const tlv_schema_t schema = {schema_entries,
                                    sizeof(schema_entries) / sizeof(schema_entries[0])};

typedef struct {
    size_t count;
    size_t stop_after;
} visit_context_t;

static tlv_visit_result_t visit(const tlv_view_t* view, void* context) {
    visit_context_t*          state = (visit_context_t*)context;
    const tlv_schema_entry_t* entry = tlv_schema_find(&schema, &view->tag);
    size_t                    length;
    if (!entry || tlv_length_to_size(view->value.length, &length) != TLV_OK ||
        tlv_schema_validate_length(entry, length) != TLV_OK)
        return TLV_VISIT_ERROR;
    print_view(view); /* The view pointer is valid only during this callback. */
    ++state->count;
    return state->stop_after && state->count >= state->stop_after ? TLV_VISIT_STOP
                                                                  : TLV_VISIT_CONTINUE;
}

int main(void) {
    const uint8_t   input[] = {1, 2, 0xAB, 0xCD, 2, 0};
    const uint8_t   noisy[] = {0xFF, 0xFF, 1, 2, 0xAB, 0xCD};
    const uint8_t   invalid[] = {1, 0}; /* Valid framing, invalid schema length. */
    tlv_view_t      view;
    size_t          offset, consumed;
    tlv_result_t    result;
    visit_context_t state = {0, 0};

    if (tlv_walk(input, sizeof(input), &tlv_reader_format_fixed_1byte, visit, &state) != TLV_OK)
        return 1;
    printf("Visited %zu elements\n", state.count);

    state.count = 0;
    state.stop_after = 1;
    if (tlv_walk(input, sizeof(input), &tlv_reader_format_fixed_1byte, visit, &state) != TLV_OK)
        return 1;
    printf("Stopped successfully after %zu element\n", state.count);

    /* Parsing never applies a schema automatically; our callback does. */
    result = tlv_walk(invalid, sizeof(invalid), &tlv_reader_format_fixed_1byte, visit, &state);
    if (result != TLV_ERR_VISITOR) return 1;
    printf("Schema rejection by visitor: %s\n", tlv_strerror(result));

    puts("Recovery scan with a schema filter");
    if (tlv_scan(noisy, sizeof(noisy), 0, &tlv_reader_format_fixed_1byte, &schema, &view, &offset,
                 &consumed) != TLV_OK)
        return 1;
    printf("Candidate at offset %zu, encoded size %zu\n", offset, consumed);
    print_view(&view);

    /* A candidate is not proof of an original boundary. Continue after it. */
    result = tlv_scan(noisy, sizeof(noisy), offset + consumed, &tlv_reader_format_fixed_1byte,
                      &schema, &view, &offset, &consumed);
    if (result != TLV_ERR_END_OF_BUFFER) return 1;
    printf("No further candidate: %s\n", tlv_strerror(result));
    return 0;
}
