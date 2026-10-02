// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

/*
 * Applying a length schema inside a tlv_reader_visit() visitor.
 * Parsing never applies a schema automatically; the visitor below does.
 */
#include <stdio.h>
#include "tlv/formats/fixed.h"
#include "tlv/size.h"
#include "tlv/reader/visitor.h"
#include "tlv/schema/schema.h"

static void print_element(const tlv_element_t* element) {
    size_t i, length;
    printf("tag=");
    for (i = 0; i < element->tag.size; ++i) printf("%02X", (unsigned)element->tag.data[i]);
    if (tlv_size_to_native(element->value.size, &length) != TLV_OK) {
        printf(" length=<unrepresentable>\n");
        return;
    }
    printf(" length=%zu value=", length);
    for (i = 0; i < length; ++i) printf("%02X ", (unsigned)element->value.data[i]);
    putchar('\n');
}

/* A schema table holds borrowed tags, so their bytes need static storage. */
static const uint8_t            tag_one[] = {1};
static const uint8_t            tag_two[] = {2};
static const tlv_schema_entry_t schema_entries[] = {
    {{tag_one, sizeof(tag_one)}, 2, 2, 0, NULL, 0}, /* Exact length. */
    {{tag_two, sizeof(tag_two)}, 0, 4, 0, NULL, 0}  /* Inclusive length range. */
};
static const tlv_schema_t schema = {schema_entries,
                                    sizeof(schema_entries) / sizeof(schema_entries[0])};

typedef struct {
    size_t count;
    size_t stop_after;
} visit_context_t;

static tlv_visit_result_t visit(const tlv_element_t* element, void* context) {
    visit_context_t*          state = (visit_context_t*)context;
    const tlv_schema_entry_t* entry = tlv_schema_find(&schema, &element->tag);
    size_t                    length;
    if (!entry || tlv_size_to_native(element->value.size, &length) != TLV_OK ||
        tlv_schema_validate_length(entry, length) != TLV_OK)
        return TLV_VISIT_ERROR;
    print_element(element); /* The element pointer is valid only during this callback. */
    ++state->count;
    return state->stop_after && state->count >= state->stop_after ? TLV_VISIT_STOP
                                                                  : TLV_VISIT_CONTINUE;
}

int main(void) {
    tlv_reader_t reader;
    /* One tag byte and one length byte; config must outlive its readers. */
    const tlv_fixed_format_t config = {
        .tag_size = 1, .length_size = 1, .length_order = TLV_BYTE_ORDER_BIG_ENDIAN};
    tlv_format_t format;
    if (tlv_fixed_format_init(&format, &config) != TLV_OK) return 1;

    const uint8_t   input[] = {1, 2, 0xAB, 0xCD, 2, 0};
    const uint8_t   invalid[] = {1, 0}; /* Valid framing, invalid schema length. */
    tlv_result_t    result;
    visit_context_t state = {0, 0};

    if (tlv_reader_init(&reader, input, sizeof(input), &format) != TLV_OK) return 1;
    if (tlv_reader_visit(&reader, visit, &state) != TLV_OK) return 1;
    printf("Visited %zu elements\n", state.count);

    state.count = 0;
    state.stop_after = 1;
    if (tlv_reader_init(&reader, input, sizeof(input), &format) != TLV_OK) return 1;
    if (tlv_reader_visit(&reader, visit, &state) != TLV_OK) return 1;
    printf("Stopped successfully after %zu element\n", state.count);

    /* Parsing never applies a schema automatically; our callback does. */
    if (tlv_reader_init(&reader, invalid, sizeof(invalid), &format) != TLV_OK) return 1;
    result = tlv_reader_visit(&reader, visit, &state);
    if (result != TLV_ERR_VISITOR) return 1;
    printf("Schema rejection by visitor: %s\n", tlv_strerror(result));

    return 0;
}
