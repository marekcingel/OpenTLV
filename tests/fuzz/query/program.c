// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#include "tlv/query/program.h"
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
    tlv_query_program_info_t info;
    tlv_query_diagnostic_t   diagnostic;
    tlv_result_t rc = tlv_query_compile((const char*)data, size, &options, scratch, sizeof scratch,
                                        program, sizeof program, &info, &diagnostic);
    if (rc != TLV_OK) return 0;
    char   text[8193];
    size_t required;
    rc =
        tlv_query_program_format((const tlv_query_program_t*)program, text, sizeof text, &required);
    if (rc != TLV_OK) abort();
    rc = tlv_query_compile(text, required - 1, &options, scratch, sizeof scratch, copy, sizeof copy,
                           &info, &diagnostic);
    if (rc != TLV_OK) abort();
    tlv_query_exec_t* exec;
    rc = tlv_query_exec_init((const tlv_query_program_t*)program, workspace, sizeof workspace, 16,
                             128, 100000, &exec);
    if (rc != TLV_OK) abort();
    for (size_t i = 0; i < size && i < 128; ++i) {
        tlv_tree_event_t event = {0};
        event.kind = TLV_TREE_ELEMENT;
        event.element.tag = tlv_tag(data + i, 1);
        event.element.value.data = data;
        event.element.value.size = size;
        int matched;
        if (tlv_query_exec_feed(exec, &event, &matched, &diagnostic) != TLV_OK) break;
    }
    (void)tlv_query_exec_finish(exec, &diagnostic);
    return 0;
}
