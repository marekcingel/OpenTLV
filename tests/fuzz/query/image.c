// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#include "tlv/query/program.h"
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > 16384) return 0;
    uint64_t image[2048], scratch[40000];
    memcpy(image, data, size);
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
