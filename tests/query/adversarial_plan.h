// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#ifndef QUERY_ADVERSARIAL_PLAN_H
#define QUERY_ADVERSARIAL_PLAN_H
#define NONE TLV_QUERY_PLAN_NONE
#define BASE .left = NONE, .right = NONE, .predicate_guard = NONE, .path_guard = NONE, .reuse = NONE
/* Manually authored /01[@len = $n], no source text or frontend objects. */
static const struct {
    tlv_query_plan_t        header;
    tlv_query_instruction_t nodes[7];
    char                    source[1];
    uint8_t                 payload[2];
} static_plan = {
    .header = {.magic = TLV_QUERY_PLAN_MAGIC,
               .version = TLV_QUERY_PLAN_VERSION,
               .count = 7,
               .root = 6,
               .text_offset = sizeof(tlv_query_plan_t) + 7 * sizeof(tlv_query_instruction_t),
               .level = TLV_QUERY_S0,
               .reserved = sizeof(tlv_query_plan_t) + 7 * sizeof(tlv_query_instruction_t) + 3,
               .variable_count = 1,
               .payload_size = 2},
    .nodes = {{BASE, .op = TLV_QUERY_OP_ROOT},
              {.op = TLV_QUERY_OP_TEST,
               .left = NONE,
               .right = NONE,
               .low = 1,
               .predicate_guard = NONE,
               .path_guard = 0,
               .path_kind = TLV_QUERY_OP_CHILD,
               .reuse = NONE,
               .resolved = 1,
               .data_size = 1},
              {.op = TLV_QUERY_OP_META,
               .left = NONE,
               .right = NONE,
               .low = 2,
               .predicate_guard = 1,
               .path_guard = NONE,
               .reuse = NONE,
               .type = TLV_QUERY_PLAN_INTEGER,
               .selector = TLV_QUERY_META_LEN},
              {.op = TLV_QUERY_OP_VARIABLE,
               .left = NONE,
               .right = NONE,
               .low = 3,
               .predicate_guard = 1,
               .path_guard = NONE,
               .reuse = NONE,
               .type = TLV_QUERY_PLAN_INTEGER,
               .data_offset = 1,
               .data_size = 1},
              {.op = TLV_QUERY_OP_EQ,
               .left = 2,
               .right = 3,
               .low = 2,
               .predicate_guard = 1,
               .path_guard = NONE,
               .reuse = NONE,
               .type = TLV_QUERY_PLAN_BOOL},
              {.op = TLV_QUERY_OP_FILTER,
               .left = 1,
               .right = 4,
               .low = 1,
               .predicate_guard = NONE,
               .path_guard = NONE,
               .reuse = NONE},
              {.op = TLV_QUERY_OP_CHILD,
               .left = 0,
               .right = 5,
               .predicate_guard = NONE,
               .path_guard = NONE,
               .reuse = NONE}},
    .payload = {1, 'n'}};

#undef BASE
#undef NONE
#endif
