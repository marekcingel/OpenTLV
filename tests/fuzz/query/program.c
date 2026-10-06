// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#include "tlv/query/adapters.h"
#include "../../../tlv/src/query/program_internal.h"
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > 4096) return 0;
    uint64_t                    scratch[15000], program[15000], workspace[15000], copy[15000];
    tlv_query_compile_options_t options;
    tlv_query_compile_options_init(&options);
    options.max_text = 8192;
    options.max_tokens = 512;
    options.max_states = 512;
    options.max_nesting = 32;
    options.max_resolved_tag = 64;
    size_t                  hook_count;
    tlv_query_environment_t environment = {0};
    environment.hooks = tlv_query_builtin_hooks(&hook_count);
    environment.hook_count = hook_count;
    options.environment = &environment;
    tlv_query_program_info_t info = {0};
    info.struct_size = sizeof info;
    tlv_query_diagnostic_t diagnostic;
    tlv_result_t rc = tlv_query_compile((const char*)data, size, &options, scratch, sizeof scratch,
                                        program, sizeof program, &info, &diagnostic);
    if (rc != TLV_OK) return 0;
    char   text[8193];
    size_t required;
    rc =
        tlv_query_program_format((const tlv_query_program_t*)program, text, sizeof text, &required);
    if (rc != TLV_OK) abort();
    size_t                     validation_bytes, validation_alignment;
    const tlv_query_program_t* validated = NULL;
    rc = tlv_query_program_load_scratch(program, info.program_size, &options, &validation_bytes,
                                        &validation_alignment, &diagnostic);
    if (rc != TLV_OK) abort();
    if (validation_bytes <= sizeof copy) {
        rc = tlv_query_program_load(program, info.program_size, &options, copy, validation_bytes,
                                    &validated, NULL, &diagnostic);
        if (rc != TLV_OK || validated != (const tlv_query_program_t*)program) abort();
    }
    tlv_query_program_info_t canonical_info = {0};
    canonical_info.struct_size = sizeof canonical_info;
    rc = tlv_query_compile(text, required - 1, &options, scratch, sizeof scratch, copy, sizeof copy,
                           &canonical_info, &diagnostic);
    if (rc != TLV_OK) abort();
    if (canonical_info.level != info.level || canonical_info.result_kind != info.result_kind)
        abort();
    tlv_query_exec_t* exec;
    if (info.level != TLV_QUERY_S0) {
        void* aligned = (void*)(((uintptr_t)workspace + 15) & ~(uintptr_t)15);
        rc = tlv_query_eval_init((const tlv_query_program_t*)program, &environment, aligned,
                                 sizeof workspace - 16, 16, 32, 100000, &exec);
        if (rc != TLV_OK) return 0;
    } else
        rc = tlv_query_exec_init((const tlv_query_program_t*)program, workspace, sizeof workspace,
                                 16, 128, 100000, &exec);
    if (rc != TLV_OK) abort();
    for (size_t i = 0; i < size && i < 128; ++i) {
        tlv_tree_event_t            event = {0};
        const tlv_tree_event_kind_t kinds[] = {TLV_TREE_ELEMENT, TLV_TREE_BEGIN, TLV_TREE_END};
        event.kind = kinds[data[i] % 3];
        event.depth = (data[i] / 3) % 18;
        event.element.tag = tlv_tag(data + i, 1);
        event.element.value.data = data;
        event.element.value.size = size;
        int matched;
        if (tlv_query_exec_feed(exec, &event, &matched, &diagnostic) != TLV_OK) {
            if (tlv_query_exec_feed(exec, &event, &matched, NULL) != TLV_ERR_INVALID_ARG) abort();
            break;
        }
    }
    (void)tlv_query_exec_finish(exec, &diagnostic);
    /* Mutate one field of a complete readable compiler image. This exercises
       internal consistency checks, not loading arbitrary external bytecode. */
    tlv_query_program_t* mutated = (tlv_query_program_t*)copy;
    if (size & 1) {
        uint32_t* fields = (uint32_t*)copy;
        fields[size % (sizeof *mutated / sizeof(uint32_t))] ^= UINT32_C(0x100000);
    } else {
        query_node_t* nodes = (query_node_t*)(mutated + 1);
        query_node_t* node = &nodes[size % mutated->count];
        switch (size % 6) {
            case 0: node->left = mutated->count; break;
            case 1: node->right = mutated->count; break;
            case 2: node->predicate_guard = mutated->count; break;
            case 3: node->path_guard = mutated->count; break;
            case 4: node->end = mutated->text_size + 1; break;
            case 5: node->op = Q_ARGS + 1; break;
        }
    }
    size_t bytes, alignment;
    (void)tlv_query_exec_size(mutated, 16, &bytes, &alignment);
    (void)tlv_query_program_format(mutated, text, sizeof text, &required);
    return 0;
}
