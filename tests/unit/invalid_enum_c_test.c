// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

/* Out-of-range enum values are tested in C, without invalid C++ enum loads. */
#include "../diagnostic_invariant.h"
#include "tlv/field/fixed.h"
#include "tlv/formats/fixed.h"
#include "tlv/formats/variable.h"
#include "tlv/formats/packed.h"
#include "tlv/reader/visitor.h"
#include <string.h>

#define CHECK(condition)                                                                           \
    do {                                                                                           \
        if (!(condition)) return __LINE__;                                                         \
    } while (0)

int tlv_test_invalid_enum_fields(void) {
    const tlv_byte_order_t   order = (tlv_byte_order_t)99;
    const tlv_fixed_length_t config = {2, order};
    const uint8_t            input[8] = {0};
    uint8_t                  output[8], before[8];
    uint64_t                 value = 42;
    size_t                   used = 99;
    memset(output, 0xCC, sizeof output);
    memcpy(before, output, sizeof output);
    CHECK(tlv_fixed_length_read(&config, input, sizeof input, &value, &used) ==
          TLV_ERR_INVALID_BYTE_ORDER);
    CHECK(tlv_fixed_length_read(&config, NULL, 0, &value, &used) == TLV_ERR_INVALID_BYTE_ORDER);
    CHECK(tlv_fixed_length_write(&config, 0, output, sizeof output, &used) ==
          TLV_ERR_INVALID_BYTE_ORDER);
    CHECK(tlv_fixed_length_write(&config, 0, NULL, 0, &used) == TLV_ERR_INVALID_BYTE_ORDER);
    CHECK(tlv_read_uint(input, sizeof input, order, &value) == TLV_ERR_INVALID_BYTE_ORDER);
    CHECK(tlv_write_uint(output, sizeof output, order, 0) == TLV_ERR_INVALID_BYTE_ORDER);
    CHECK(tlv_write_uint(output, 1, order, UINT64_MAX) == TLV_ERR_INVALID_BYTE_ORDER);
    const size_t widths[] = {0, 9, SIZE_MAX};
    for (size_t i = 0; i < sizeof widths / sizeof widths[0]; ++i) {
        CHECK(tlv_read_uint(NULL, widths[i], order, &value) == TLV_ERR_NULL_ARG);
        CHECK(tlv_read_uint(input, widths[i], order, NULL) == TLV_ERR_NULL_ARG);
        CHECK(tlv_write_uint(NULL, widths[i], order, UINT64_MAX) == TLV_ERR_NULL_ARG);
        CHECK(tlv_read_uint(input, widths[i], order, &value) == TLV_ERR_INVALID_LENGTH);
        CHECK(tlv_write_uint(output, widths[i], order, UINT64_MAX) == TLV_ERR_INVALID_LENGTH);
    }
    tlv_format_t             format;
    const tlv_fixed_format_t fixed = {
        {1}, {2, order}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
    const tlv_variable_format_t variable = {{0x1F, 0x1F, 0x80, 0x7F, 16, NULL},
                                            {0x80, 0x7F, order, NULL},
                                            TLV_ELEMENT_ORDER_TLV,
                                            TLV_LENGTH_SCOPE_VALUE,
                                            NULL};
    CHECK(tlv_fixed_format_init(&format, &fixed) == TLV_ERR_INVALID_BYTE_ORDER);
    CHECK(tlv_variable_format_init(&format, &variable) == TLV_ERR_INVALID_BYTE_ORDER);
    const uint8_t       packed_tags[] = {0, 1};
    tlv_packed_layout_t packed = {1,
                                  {1, 7, 1, TLV_BYTE_ORDER_BIG_ENDIAN},
                                  {1, 0, 7, TLV_BYTE_ORDER_BIG_ENDIAN},
                                  (tlv_length_scope_t)99,
                                  packed_tags,
                                  1,
                                  sizeof(packed_tags)};
    CHECK(tlv_packed_layout_validate(&packed) == TLV_ERR_INVALID_ARG);
    packed.length_scope = TLV_LENGTH_SCOPE_VALUE;
    packed.length.byte_order = order;
    CHECK(tlv_packed_layout_validate(&packed) == TLV_ERR_INVALID_BYTE_ORDER);
    CHECK(value == 42 && used == 99 && memcmp(output, before, sizeof output) == 0);
    return 0;
}

static int constructed(const void* context, const tlv_tag_t* tag) {
    (void)context;
    return tag->data[0] >= 0x80;
}

static tlv_visit_result_t invalid_once(const tlv_element_t* element, void* context) {
    size_t* count = (size_t*)context;
    (void)element;
    return ++*count == 1 ? (tlv_visit_result_t)99 : TLV_VISIT_CONTINUE;
}

static tlv_visit_result_t tree_invalid_once(const tlv_element_t* element, size_t depth,
                                            size_t offset, void* context) {
    (void)depth;
    (void)offset;
    return invalid_once(element, context);
}

int tlv_test_invalid_enum_visitors(void) {
    const tlv_fixed_format_t config = {
        {1}, {1, TLV_BYTE_ORDER_BIG_ENDIAN}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
    tlv_format_t format;
    CHECK(tlv_fixed_format_init(&format, &config) == TLV_OK);
    format.is_constructed = constructed;
    const uint8_t           flat[] = {1, 0, 2, 0}, nested[] = {0xE1, 2, 1, 0, 2, 0};
    tlv_reader_t            reader;
    tlv_reader_diagnostic_t diagnostic;
    size_t                  count = 0, offset = 99;
    CHECK(tlv_reader_init(&reader, flat, sizeof flat, &format) == TLV_OK);
    CHECK(tlv_reader_visit_diag(&reader, invalid_once, &count, &diagnostic) == TLV_ERR_VISITOR);
    CHECK(tlv_reader_offset(&reader) == 2 && count == 1 &&
          test_diagnostic_matches(TLV_ERR_VISITOR, &diagnostic.diagnostic));
    CHECK(tlv_reader_visit(&reader, invalid_once, &count) == TLV_OK && count == 2);
    tlv_tree_frame_t  frames[1];
    tlv_tree_reader_t tree;
    count = 0;
    CHECK(tlv_tree_reader_init(&tree, nested, sizeof nested, &format, frames, 1, 1, 3) == TLV_OK);
    CHECK(tlv_tree_reader_visit(&tree, tree_invalid_once, &count, &offset) == TLV_ERR_VISITOR);
    CHECK(count == 1 && offset == 0);
    CHECK(tlv_tree_reader_visit(&tree, tree_invalid_once, &count, &offset) == TLV_OK);
    CHECK(count == 3 && tlv_tree_reader_at_end(&tree));
    return 0;
}
