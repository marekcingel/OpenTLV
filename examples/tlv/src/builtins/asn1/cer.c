// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

/*
 * CER: a nested indefinite-length container, and a logical OCTET STRING
 * over the 1,000-octet canonical segmentation threshold, written as a
 * constructed, segmented value and inspected segment by segment without
 * copying or concatenating them.
 */
#include <stdio.h>
#include "tlv/builtins/asn1/cer.h"
#include "tlv/builtins/asn1/cer_validation.h"
#include "tlv/size.h"
#include "tlv/reader/visitor.h"

#define CHECK(call)                                                                                \
    do {                                                                                           \
        tlv_result_t rc_ = (call);                                                                 \
        if (rc_ != TLV_OK) {                                                                       \
            fprintf(stderr, "%s: %s\n", #call, tlv_strerror(rc_));                                 \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

static tlv_visit_result_t print_segment(const tlv_element_t* element, void* context) {
    size_t length;
    (void)context;
    CHECK(tlv_size_to_native(element->value.size, &length));
    printf("  segment: tag 0x%02X, %zu content octets, address %p (borrowed, not copied)\n",
           element->tag.data[0], length, (const void*)element->value.data);
    return TLV_VISIT_CONTINUE;
}

int main(void) {
    /* Nested indefinite-length containers: SEQUENCE(indefinite){ INTEGER 5 }. */
    const uint8_t integer_child[] = {0x02, 1, 5};
    uint8_t       nested[16];
    size_t        required, written, consumed;
    tlv_element_t element;

    CHECK(tlv_cer_write(NULL, 0, TLV_TAG(0x30), integer_child, sizeof(integer_child), NULL,
                        &required, NULL));
    CHECK(tlv_cer_write(nested, sizeof(nested), TLV_TAG(0x30), integer_child, sizeof(integer_child),
                        NULL, &written, NULL));
    CHECK(tlv_cer_read(nested, written, NULL, &element, &consumed, NULL));
    printf("Encoded %zu bytes (tag + 0x80 + child + EOC), consumed %zu\n", written, consumed);

    {
        uint8_t content[1500], segmented[1520];
        size_t  seg_written, value_size, i;
        for (i = 0; i < sizeof(content); ++i) content[i] = (uint8_t)i;
        puts("Segmented OCTET STRING, segments accessed without copying");
        CHECK(tlv_cer_write_segmented_string(segmented, sizeof(segmented), TLV_TAG(0x04), content,
                                             sizeof(content), NULL, &seg_written, NULL));
        CHECK(tlv_cer_read_strict(segmented, seg_written, NULL, &element, &consumed, NULL));
        printf("Constructed: %d, encoded %zu bytes\n", tlv_asn1_tag_is_constructed(&element.tag),
               consumed);
        /* element.value is the encoded constructed contents (segment headers
         * included) -- distinct from the logical string data each segment's
         * own borrowed value exposes below. */
        CHECK(tlv_size_to_native(element.value.size, &value_size));
        tlv_reader_t segments;
        CHECK(tlv_reader_init(&segments, element.value.data, value_size, &tlv_format_cer));
        CHECK(tlv_reader_visit(&segments, print_segment, NULL));
    }
    return 0;
}
