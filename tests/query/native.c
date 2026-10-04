// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#include "tlv/query/program.h"
#include "tlv/formats/fixed.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int constructed(const void* context, const tlv_tag_t* tag) {
    (void)context;
    return tag->size == 1 && tag->data[0] == 0x70;
}
static tlv_visit_result_t print_match(const tlv_tree_event_t* event, void* context) {
    (void)context;
    printf("%zu\n", event->offset);
    return TLV_VISIT_CONTINUE;
}
static int hex(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}
int main(int argc, char** argv) {
    if (argc != 3) return 2;
    size_t scratch_size, alignment, size = strlen(argv[2]) / 2;
    if (strlen(argv[2]) % 2 || size > 65536) return 2;
    uint8_t* input = malloc(size ? size : 1);
    if (!input) return 2;
    for (size_t i = 0; i < size; ++i) {
        int a = hex(argv[2][2 * i]), b = hex(argv[2][2 * i + 1]);
        if (a < 0 || b < 0) {
            free(input);
            return 2;
        }
        input[i] = (uint8_t)(a * 16 + b);
    }
    tlv_query_diagnostic_t   diagnostic;
    tlv_query_program_info_t info = {0};
    info.struct_size = sizeof info;
    void*        scratch = NULL;
    void*        program = NULL;
    void*        workspace = NULL;
    tlv_result_t rc = tlv_query_compile_scratch(argv[1], strlen(argv[1]), NULL, &scratch_size,
                                                &alignment, &diagnostic);
    if (rc != TLV_OK) goto done;
    scratch = malloc(scratch_size);
    if (!scratch) {
        rc = TLV_ERR_OUT_OF_MEMORY;
        goto done;
    }
    rc = tlv_query_compile(argv[1], strlen(argv[1]), NULL, scratch, scratch_size, NULL, 0, &info,
                           &diagnostic);
    if (rc != TLV_OK) goto done;
    program = malloc(info.program_size);
    if (!program) {
        rc = TLV_ERR_OUT_OF_MEMORY;
        goto done;
    }
    rc = tlv_query_compile(argv[1], strlen(argv[1]), NULL, scratch, scratch_size, program,
                           info.program_size, &info, &diagnostic);
    if (rc != TLV_OK) goto done;
    size_t workspace_size;
    rc = tlv_query_exec_size(program, 128, &workspace_size, &alignment);
    if (rc != TLV_OK) goto done;
    workspace = malloc(workspace_size);
    if (!workspace) {
        rc = TLV_ERR_OUT_OF_MEMORY;
        goto done;
    }
    tlv_query_exec_t* exec;
    rc = tlv_query_exec_init(program, workspace, workspace_size, 128, 100000, 10000000, &exec);
    if (rc != TLV_OK) goto done;
    tlv_fixed_format_t config = {0};
    config.tag_size = 1;
    config.length_size = 1;
    config.length_order = TLV_BYTE_ORDER_BIG_ENDIAN;
    tlv_format_t format;
    rc = tlv_fixed_format_init(&format, &config);
    if (rc != TLV_OK) goto done;
    format.is_constructed = constructed;
    tlv_tree_reader_t reader;
    tlv_tree_frame_t  frames[128];
    rc = tlv_tree_reader_init(&reader, input, size, &format, frames, 128, 128, 100000);
    if (rc != TLV_OK) goto done;
    rc = tlv_query_program_visit(&reader, exec, print_match, NULL, &diagnostic);
done:
    if (rc != TLV_OK)
        fprintf(stderr, "%d %u %zu %zu\n", (int)rc, (unsigned)diagnostic.kind, diagnostic.begin,
                diagnostic.end);
    free(workspace);
    free(program);
    free(scratch);
    free(input);
    return rc == TLV_OK ? 0 : 1;
}
