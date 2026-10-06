// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#include "tlv/query/plan.h"
#include "tlv/config.h"
#include <stdio.h>
#include <string.h>

#define CHECK(x)                                                                                   \
    do {                                                                                           \
        if (!(x)) {                                                                                \
            fprintf(stderr, "line %d: %s\n", __LINE__, #x);                                        \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)
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

static int run(const tlv_query_program_t* p, int retained, int64_t parameter, unsigned* bits) {
    uint64_t          workspace[8192];
    size_t            bytes, alignment;
    tlv_query_exec_t* exec = NULL;
    CHECK((retained ? tlv_query_eval_size(p, 2, 8, &bytes, &alignment)
                    : tlv_query_exec_size(p, 2, &bytes, &alignment)) == TLV_OK);
    CHECK(bytes <= sizeof workspace && alignment <= 16);
    /* Union-backed workspace with explicit 16-byte address alignment. */
    uint8_t* aligned = (uint8_t*)(((uintptr_t)workspace + 15) & ~(uintptr_t)15);
    CHECK(bytes <= sizeof workspace - 15);
    CHECK((retained ? tlv_query_eval_init(p, NULL, aligned, bytes, 2, 8, 10000, &exec)
                    : tlv_query_exec_init(p, aligned, bytes, 2, 8, 10000, &exec)) == TLV_OK);
    CHECK(tlv_query_exec_bind(exec, "n", TLV_QUERY_RESULT_INTEGER, parameter, NULL, 0, NULL) ==
          TLV_OK);
    const uint8_t tags[] = {1, 2, 1};
    const uint8_t value[] = {0, 0};
    *bits = 0;
    for (size_t i = 0; i < 3; ++i) {
        tlv_tree_event_t event = {0};
        event.kind = TLV_TREE_ELEMENT;
        event.element.tag.data = &tags[i];
        event.element.tag.size = 1;
        event.element.value.data = value;
        event.element.value.size = i == 2 ? 2 : 1;
        event.offset = i;
        int matched = 0;
        CHECK(tlv_query_exec_feed(exec, &event, &matched, NULL) == TLV_OK);
        if (matched) *bits |= 1u << i;
    }
    CHECK(tlv_query_exec_finish(exec, NULL) == TLV_OK);
    if (retained) {
        tlv_tree_event_t event;
        tlv_result_t     rc;
        while ((rc = tlv_query_result_next(exec, &event)) == TLV_OK) *bits |= 1u << event.offset;
        CHECK(rc == TLV_ERR_END_OF_BUFFER);
    }
    return 0;
}
int main(void) {
    const tlv_query_program_t* p = NULL;
    CHECK(tlv_query_plan_open(&static_plan, static_plan.header.reserved, &p, NULL) == TLV_OK);
    CHECK(tlv_query_program_variable_count(p) == 1);
    tlv_query_program_info_t requirements = {0};
    requirements.struct_size = sizeof requirements;
    CHECK(tlv_query_plan_info(p, &requirements) == TLV_OK);
    CHECK(requirements.instructions == 7 && requirements.variable_slots == 1 &&
          requirements.scratch_size == 0);
    requirements.struct_size = 1;
    requirements.instructions = 123;
    CHECK(tlv_query_plan_info(p, &requirements) == TLV_ERR_INVALID_ARG);
    CHECK(requirements.instructions == 123);
    tlv_query_variable_info_t variable;
    CHECK(tlv_query_program_variable(p, 0, &variable) == TLV_OK);
    CHECK(variable.name_size == 1 && variable.name[0] == 'n');
    for (int retained = 0; retained < 2; ++retained) {
        unsigned bits;
        CHECK(run(p, retained, 1, &bits) == 0 && bits == 1);
        CHECK(run(p, retained, 2, &bits) == 0 && bits == 4);
    }
    for (size_t size = 0; size < static_plan.header.reserved; ++size)
        CHECK(tlv_query_plan_open(&static_plan, size, &p, NULL) != TLV_OK);
    uint32_t damaged[1024];
    memcpy(damaged, &static_plan, static_plan.header.reserved);
    tlv_query_plan_t* header = (tlv_query_plan_t*)damaged;
    header->version++;
    CHECK(tlv_query_plan_open(damaged, static_plan.header.reserved, &p, NULL) ==
          TLV_ERR_UNSUPPORTED_TYPE);
    header->version--;
    tlv_query_instruction_t* nodes = (tlv_query_instruction_t*)(header + 1);
    nodes[4].left = 4;
    CHECK(tlv_query_plan_open(damaged, static_plan.header.reserved, &p, NULL) ==
          TLV_ERR_INVALID_ARG);
    nodes[4].left = 2;
    nodes[3].data_offset = UINT32_MAX;
    CHECK(tlv_query_plan_open(damaged, static_plan.header.reserved, &p, NULL) ==
          TLV_ERR_INVALID_ARG);
    nodes[3].data_offset = 1;
    header->level = TLV_QUERY_S1;
    CHECK(tlv_query_plan_open(damaged, static_plan.header.reserved, &p, NULL) ==
          TLV_ERR_INVALID_ARG);
    header->level = TLV_QUERY_S0;
    nodes[2].selector = UINT32_MAX;
    CHECK(tlv_query_plan_open(damaged, static_plan.header.reserved, &p, NULL) ==
          TLV_ERR_INVALID_ARG);
    nodes[2].selector = TLV_QUERY_META_LEN;
    nodes[1].resolved = 2;
    nodes[1].mask_offset = UINT32_MAX;
    CHECK(tlv_query_plan_open(damaged, static_plan.header.reserved, &p, NULL) ==
          TLV_ERR_INVALID_ARG);
    nodes[1].resolved = 1;
    nodes[1].mask_offset = 0;
    nodes[6].op = TLV_QUERY_OP_UNION;
#if OPENTLV_QUERY_SET_OPERATIONS
    CHECK(tlv_query_plan_open(damaged, static_plan.header.reserved, &p, NULL) == TLV_OK);
#else
    CHECK(tlv_query_plan_open(damaged, static_plan.header.reserved, &p, NULL) ==
          TLV_ERR_UNSUPPORTED_TYPE);
#endif
#if OPENTLV_QUERY_FRONTEND
    uint32_t                    scratch[8192], image[4096];
    const char*                 text = "/01[@len = $n]";
    tlv_query_variable_t        declaration = {"n", TLV_QUERY_RESULT_INTEGER};
    tlv_query_compile_options_t options;
    tlv_query_compile_options_init(&options);
    options.variables = &declaration;
    options.variable_count = 1;
    tlv_query_program_info_t info = {0};
    info.struct_size = sizeof info;
    CHECK(tlv_query_compile(text, strlen(text), &options, scratch, sizeof scratch, image,
                            sizeof image, &info, NULL) == TLV_OK);
    CHECK(tlv_query_plan_open(image, info.program_size, &p, NULL) == TLV_OK);
#if !OPENTLV_QUERY_SET_OPERATIONS
    tlv_query_program_info_t unsupported = {0};
    unsupported.struct_size = sizeof unsupported;
    CHECK(tlv_query_compile("01 | 02", 7, &options, scratch, sizeof scratch, NULL, 0, &unsupported,
                            NULL) == TLV_ERR_UNSUPPORTED_TYPE);
#endif
    /* Destroy source spelling: execution and named binding must still work. */
    tlv_query_plan_t* compiled = (tlv_query_plan_t*)image;
    memset((uint8_t*)image + compiled->text_offset, '!', compiled->text_size);
    CHECK(tlv_query_plan_open(image, info.program_size, &p, NULL) == TLV_OK);
    for (int retained = 0; retained < 2; ++retained) {
        unsigned bits;
        CHECK(run(p, retained, 1, &bits) == 0 && bits == 1);
        CHECK(run(p, retained, 2, &bits) == 0 && bits == 4);
    }
#endif
    return 0;
}
