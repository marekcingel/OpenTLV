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
#include "adversarial_plan.h"

/* Source-free /01[contains(value(), x'6162')]. */
static const struct {
    tlv_query_plan_t        header;
    tlv_query_instruction_t nodes[8];
    char                    source[1];
    uint8_t                 payload[3];
} contains_plan = {
    .header = {.magic = TLV_QUERY_PLAN_MAGIC,
               .version = TLV_QUERY_PLAN_VERSION,
               .count = 8,
               .root = 7,
               .text_offset = sizeof(tlv_query_plan_t) + 8 * sizeof(tlv_query_instruction_t),
               .level = TLV_QUERY_S0,
               .reserved = sizeof(tlv_query_plan_t) + 8 * sizeof(tlv_query_instruction_t) + 4,
               .payload_size = 3,
               .pattern_capacity = 2},
#define NONE TLV_QUERY_PLAN_NONE
#define BASE .left = NONE, .right = NONE, .predicate_guard = NONE, .path_guard = NONE, .reuse = NONE
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
              {.op = TLV_QUERY_OP_CALL,
               .left = NONE,
               .right = NONE,
               .low = 2,
               .predicate_guard = 1,
               .path_guard = NONE,
               .reuse = NONE,
               .type = TLV_QUERY_PLAN_BYTES,
               .selector = TLV_QUERY_FN_VALUE},
              {.op = TLV_QUERY_OP_BYTES,
               .left = NONE,
               .right = NONE,
               .low = 3,
               .predicate_guard = 1,
               .path_guard = NONE,
               .reuse = NONE,
               .type = TLV_QUERY_PLAN_BYTES,
               .data_offset = 1,
               .data_size = 2},
              {.op = TLV_QUERY_OP_ARGS,
               .left = 2,
               .right = 3,
               .low = 2,
               .predicate_guard = 1,
               .path_guard = NONE,
               .reuse = NONE},
              {.op = TLV_QUERY_OP_CALL,
               .left = 4,
               .right = NONE,
               .low = 2,
               .predicate_guard = 1,
               .path_guard = NONE,
               .reuse = NONE,
               .type = TLV_QUERY_PLAN_BOOL,
               .selector = TLV_QUERY_FN_CONTAINS},
              {.op = TLV_QUERY_OP_FILTER,
               .left = 1,
               .right = 5,
               .low = 1,
               .predicate_guard = NONE,
               .path_guard = NONE,
               .reuse = NONE},
              {.op = TLV_QUERY_OP_CHILD,
               .left = 0,
               .right = 6,
               .predicate_guard = NONE,
               .path_guard = NONE,
               .reuse = NONE}},
#undef BASE
#undef NONE
    .payload = {1, 'a', 'b'}};

static int run_contains(const tlv_query_program_t* p, int retained, size_t pattern_size,
                        tlv_result_t expected) {
    uint64_t          workspace[8192];
    size_t            bytes, alignment;
    tlv_query_exec_t* exec = NULL;
    CHECK((retained ? tlv_query_eval_size(p, 2, 8, &bytes, &alignment)
                    : tlv_query_exec_size(p, 2, &bytes, &alignment)) == TLV_OK);
    uint8_t* aligned = (uint8_t*)(((uintptr_t)workspace + 15) & ~(uintptr_t)15);
    CHECK(bytes <= sizeof workspace - 15 && alignment <= 16);
    CHECK((retained ? tlv_query_eval_init(p, NULL, aligned, bytes, 2, 8, 10000, &exec)
                    : tlv_query_exec_init(p, aligned, bytes, 2, 8, 10000, &exec)) == TLV_OK);
    const uint8_t value[] = {'a', 'b', 'a', 'b'};
    const uint8_t tag = 1;
    if (tlv_query_program_variable_count(p))
        CHECK(tlv_query_exec_bind(exec, "ab", TLV_QUERY_RESULT_BYTES, 0, value, pattern_size,
                                  NULL) == TLV_OK);
    tlv_tree_event_t event = {0};
    event.kind = TLV_TREE_ELEMENT;
    event.element.tag.data = &tag;
    event.element.tag.size = 1;
    event.element.value.data = value;
    event.element.value.size = sizeof value;
    tlv_query_diagnostic_t diagnostic;
    int                    matched = 0;
    tlv_result_t           rc = tlv_query_exec_feed(exec, &event, &matched, &diagnostic);
    if (retained) {
        CHECK(rc == TLV_OK);
        rc = tlv_query_exec_finish(exec, &diagnostic);
    }
    CHECK(rc == expected);
    if (expected == TLV_ERR_LIMIT) {
        CHECK(diagnostic.kind == TLV_QUERY_ERROR_LIMIT && diagnostic.limit &&
              strcmp(diagnostic.limit, "pattern") == 0);
        CHECK(diagnostic.configured == p->pattern_capacity);
    } else if (retained) {
        CHECK(tlv_query_result_next(exec, &event) == TLV_OK);
        CHECK(tlv_query_result_next(exec, &event) == TLV_END);
    } else {
        CHECK(matched == 1);
        CHECK(tlv_query_exec_finish(exec, NULL) == TLV_OK);
    }
    return 0;
}

static int pattern_bounds(void) {
    uint32_t image[1024];
    memcpy(image, &contains_plan, contains_plan.header.reserved);
    tlv_query_plan_t*          header = (tlv_query_plan_t*)image;
    tlv_query_instruction_t*   nodes = (tlv_query_instruction_t*)(header + 1);
    const tlv_query_program_t* p = NULL;
    tlv_query_diagnostic_t     diagnostic;
    CHECK(tlv_query_plan_open(image, header->reserved, &p, NULL) == TLV_OK);
    for (int retained = 0; retained < 2; ++retained)
        CHECK(run_contains(p, retained, 0, TLV_OK) == 0);
    for (uint32_t capacity = 0; capacity <= 3; ++capacity) {
        header->pattern_capacity = capacity;
        if (capacity < 2) {
            p = &static_plan.header;
            CHECK(tlv_query_plan_open(image, header->reserved, &p, &diagnostic) ==
                  TLV_ERR_INVALID_VALUE);
            CHECK(p == &static_plan.header && diagnostic.kind == TLV_QUERY_ERROR_IMAGE);
        } else {
            CHECK(tlv_query_plan_open(image, header->reserved, &p, NULL) == TLV_OK);
            for (int retained = 0; retained < 2; ++retained)
                CHECK(run_contains(p, retained, 0, TLV_OK) == 0);
        }
    }
    header->pattern_capacity = 0;
    nodes[3].data_size = 0;
    CHECK(tlv_query_plan_open(image, header->reserved, &p, NULL) == TLV_OK);
    for (int retained = 0; retained < 2; ++retained)
        CHECK(run_contains(p, retained, 0, TLV_OK) == 0);
    /* Dynamic patterns use the declared capacity, including the valid zero bound. */
    nodes[3].op = TLV_QUERY_OP_VARIABLE;
    nodes[3].data_size = 2;
    header->variable_count = 1;
    for (uint32_t capacity = 0; capacity <= 3; ++capacity) {
        header->pattern_capacity = capacity;
        CHECK(tlv_query_plan_open(image, header->reserved, &p, NULL) == TLV_OK);
        for (int retained = 0; retained < 2; ++retained) {
            CHECK(run_contains(p, retained, 0, TLV_OK) == 0);
            CHECK(run_contains(p, retained, 2, capacity < 2 ? TLV_ERR_LIMIT : TLV_OK) == 0);
        }
    }
    /* Source-free instruction offsets are ordered producer hints, not text bounds. */
    nodes[5].begin = UINT32_MAX - 1;
    nodes[5].end = UINT32_MAX;
    CHECK(tlv_query_plan_open(image, header->reserved, &p, NULL) == TLV_OK);
    nodes[5].end = nodes[5].begin - 1;
    CHECK(tlv_query_plan_open(image, header->reserved, &p, NULL) == TLV_ERR_INVALID_VALUE);
    return 0;
}

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
        CHECK(rc == TLV_END);
    }
    return 0;
}
int main(void) {
    CHECK(pattern_bounds() == 0);
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
          TLV_ERR_UNSUPPORTED);
    header->version--;
    tlv_query_instruction_t* nodes = (tlv_query_instruction_t*)(header + 1);
    nodes[4].left = 4;
    CHECK(tlv_query_plan_open(damaged, static_plan.header.reserved, &p, NULL) ==
          TLV_ERR_INVALID_VALUE);
    nodes[4].left = 2;
    nodes[3].data_offset = UINT32_MAX;
    CHECK(tlv_query_plan_open(damaged, static_plan.header.reserved, &p, NULL) ==
          TLV_ERR_INVALID_VALUE);
    nodes[3].data_offset = 1;
    header->level = TLV_QUERY_S1;
    CHECK(tlv_query_plan_open(damaged, static_plan.header.reserved, &p, NULL) ==
          TLV_ERR_INVALID_VALUE);
    header->level = TLV_QUERY_S0;
    nodes[2].selector = UINT32_MAX;
    CHECK(tlv_query_plan_open(damaged, static_plan.header.reserved, &p, NULL) ==
          TLV_ERR_INVALID_VALUE);
    nodes[2].selector = TLV_QUERY_META_LEN;
    nodes[1].resolved = 2;
    nodes[1].mask_offset = UINT32_MAX;
    CHECK(tlv_query_plan_open(damaged, static_plan.header.reserved, &p, NULL) ==
          TLV_ERR_INVALID_VALUE);
    nodes[1].resolved = 1;
    nodes[1].mask_offset = 0;
    nodes[6].op = TLV_QUERY_OP_UNION;
#if OPENTLV_QUERY_SET_OPERATIONS
    CHECK(tlv_query_plan_open(damaged, static_plan.header.reserved, &p, NULL) == TLV_OK);
#else
    CHECK(tlv_query_plan_open(damaged, static_plan.header.reserved, &p, NULL) ==
          TLV_ERR_UNSUPPORTED);
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
                            NULL) == TLV_ERR_UNSUPPORTED);
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
