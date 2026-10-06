// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#include "tlv/query/plan.h"
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > 16384) return 0;
    uint64_t image[2048], scratch[40000];
    memcpy(image, data, size);
    const tlv_query_program_t* static_program = NULL;
    tlv_result_t               static_rc = tlv_query_plan_open(image, size, &static_program, NULL);
    if (static_rc == TLV_OK) {
        uint8_t*     workspace = (uint8_t*)(((uintptr_t)scratch + 15) & ~(uintptr_t)15);
        const size_t capacity = sizeof scratch - 15;
        for (int retained = 0; retained < 2; ++retained) {
            size_t       needed, align;
            tlv_result_t ready = retained
                                     ? tlv_query_eval_size(static_program, 8, 16, &needed, &align)
                                     : tlv_query_exec_size(static_program, 8, &needed, &align);
            if (ready != TLV_OK || needed > capacity) continue;
            tlv_query_exec_t* exec = NULL;
            ready = retained ? tlv_query_eval_init(static_program, NULL, workspace, capacity, 8, 16,
                                                   10000, &exec)
                             : tlv_query_exec_init(static_program, workspace, capacity, 8, 16,
                                                   10000, &exec);
            if (ready != TLV_OK) continue;
            uint8_t          tag = 0x5a;
            tlv_tree_event_t event = {0};
            event.kind = TLV_TREE_ELEMENT;
            event.element.tag = tlv_tag(&tag, 1);
            int matched;
            if (tlv_query_exec_feed(exec, &event, &matched, NULL) == TLV_OK)
                (void)tlv_query_exec_finish(exec, NULL);
        }
    } else if (static_program)
        abort();
    tlv_query_compile_options_t options;
    tlv_query_compile_options_init(&options);
    options.max_text = 4096;
    options.max_tokens = 256;
    options.max_states = 256;
    options.max_nesting = 32;
    size_t                 bytes = 0, alignment = 0;
    tlv_query_diagnostic_t diagnostic;
    tlv_result_t           rc =
        tlv_query_program_load_scratch(image, size, &options, &bytes, &alignment, &diagnostic);
    if (rc != TLV_OK || bytes > sizeof scratch) return 0;
    const tlv_query_program_t* program = NULL;
    rc = tlv_query_program_load(image, size, &options, scratch, bytes, &program, NULL, &diagnostic);
    if (memcmp(image, data, size)) abort();
    if (rc == TLV_OK) {
        size_t required;
        if (!program || tlv_query_program_format(program, NULL, 0, &required) != TLV_OK) abort();
    } else if (program)
        abort();
    return 0;
}
