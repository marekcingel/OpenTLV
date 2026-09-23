/*
 * Checks a document's structure -- which tags are required, how many times,
 * in what nesting, and with what value lengths -- without decoding it. See
 * parse.c for the document this schema describes.
 */
#include <stdint.h>
#include <stdio.h>
#include "tlv/builtins/asn1/ber.h"
#include "tlv/reader/walker.h"
#include "tlv/schema/schema.h"

/* Same bytes as parse.c's document. */
static const uint8_t document[] = {0x6F, 0x0A, 0x84, 0x03, 0x41, 0x42,
                                   0x43, 0xA5, 0x03, 0x50, 0x01, 0x01};
/* Missing the FCI Proprietary Template (A5) the schema requires. */
static const uint8_t incomplete[] = {0x6F, 0x05, 0x84, 0x03, 0x41, 0x42, 0x43};

static const uint8_t              application_label_tag[] = {0x50};
static const tlv_structure_rule_t proprietary_rules[] = {
    {{{application_label_tag, 1}, 1, 1, 0, NULL}, 1, 1, TLV_SCHEMA_PRIMITIVE, NULL}};
static const tlv_structure_schema_t proprietary_schema = {proprietary_rules, 1, 0};

static const uint8_t              df_name_tag[] = {0x84};
static const uint8_t              proprietary_tag[] = {0xA5};
static const tlv_structure_rule_t fci_rules[] = {
    {{{df_name_tag, 1}, 1, 16, 0, "df_name"}, 1, 1, TLV_SCHEMA_PRIMITIVE, NULL},
    {{{proprietary_tag, 1}, 0, SIZE_MAX, 0, NULL},
     1,
     1,
     TLV_SCHEMA_CONSTRUCTED,
     &proprietary_schema}};
static const tlv_structure_schema_t fci_schema = {fci_rules, 2, 0};

static const uint8_t              fci_tag[] = {0x6F};
static const tlv_structure_rule_t top_rules[] = {
    {{{fci_tag, 1}, 0, SIZE_MAX, 0, NULL}, 1, 1, TLV_SCHEMA_CONSTRUCTED, &fci_schema}};
static const tlv_structure_schema_t top_schema = {top_rules, 1, 0};

int main(void) {
    tlv_result_t result =
        tlv_schema_validate(document, sizeof(document), &tlv_reader_format_ber,
                            tlv_ber_is_constructed, &top_schema, TLV_WALK_MAX_DEPTH, 16, NULL);
    if (result != TLV_OK) {
        fprintf(stderr, "unexpected: %s\n", tlv_strerror(result));
        return 1;
    }
    puts("Document conforms to the schema");

    result = tlv_schema_validate(incomplete, sizeof(incomplete), &tlv_reader_format_ber,
                                 tlv_ber_is_constructed, &top_schema, TLV_WALK_MAX_DEPTH, 16, NULL);
    if (result != TLV_ERR_SCHEMA_MISSING) {
        fprintf(stderr, "expected a missing-field error, got %s\n", tlv_strerror(result));
        return 1;
    }
    printf("Incomplete document rejected: %s\n", tlv_strerror(result));
    return 0;
}
