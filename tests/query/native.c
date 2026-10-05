// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#include "tlv/query/adapters.h"
#include "../../tlv/src/query/program_internal.h"
#include "tlv/formats/fixed.h"
#include "tlv/document/document.h"
#include "tlv/writer/tree.h"
#include "tlv/config.h"
#if OPENTLV_FORMAT_BER
#include "tlv/builtins/asn1/query.h"
#endif
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
#if OPENTLV_DOCUMENT
static tlv_result_t document_run(const uint8_t* input, size_t size, const tlv_format_t* format,
                                 tlv_query_exec_t* exec, tlv_query_diagnostic_t* diagnostic) {
    tlv_document_options_t options;
    tlv_result_t           rc = tlv_document_options_init(&options, format);
    if (rc != TLV_OK) return rc;
    tlv_document_t* document = NULL;
    size_t          offset;
    rc = tlv_document_parse(input, size, &options, &document, &offset);
    if (rc != TLV_OK) return rc;
    tlv_tree_writer_frame_t     writer_frames[128];
    uint8_t*                    staged = malloc(size ? size : 1);
    uint8_t*                    scratch = malloc(size ? size : 1);
    tlv_tree_writer_workspace_t staging = {0};
    staging.frames = writer_frames;
    staging.frame_capacity = 128;
    staging.data = staged;
    staging.data_capacity = size;
    staging.scratch = scratch;
    staging.scratch_capacity = size;
    size_t bytes;
    rc = staged && scratch ? tlv_document_query_value_size(document, &staging, &bytes)
                           : TLV_ERR_OUT_OF_MEMORY;
    void* values = rc == TLV_OK ? malloc(bytes ? bytes : 1) : NULL;
    if (rc == TLV_OK && !values) rc = TLV_ERR_OUT_OF_MEMORY;
    if (rc == TLV_OK)
        rc = tlv_document_query_evaluate(document, exec, NULL, values, bytes, &staging, diagnostic);
    tlv_query_result_t result;
    if (rc == TLV_OK) rc = tlv_query_exec_result(exec, &result);
    if (rc == TLV_OK && result.kind == TLV_QUERY_RESULT_NODES) {
        /* Fixture adapter maps source-less handles to immutable Reader preorder offsets.
           Neither the VM nor the oracle derives identity from those offsets. */
        tlv_node_t*       handles[1024];
        size_t            offsets[1024], count = 0;
        tlv_node_t*       node = tlv_document_first(document);
        tlv_tree_frame_t  frames[128];
        tlv_tree_reader_t reader;
        rc = tlv_tree_reader_init(&reader, input, size, format, frames, 128, 128, 1024);
        tlv_tree_event_t event;
        while (rc == TLV_OK && (rc = tlv_tree_reader_next_event(&reader, &event)) == TLV_OK) {
            if (event.kind == TLV_TREE_END) continue;
            if (count == 1024 || !node) {
                rc = TLV_ERR_LIMIT;
                break;
            }
            handles[count] = node;
            offsets[count++] = event.offset;
            if (tlv_node_first_child(node))
                node = tlv_node_first_child(node);
            else {
                while (node && !tlv_node_next(node)) node = tlv_node_parent(node);
                node = tlv_node_next(node);
            }
        }
        if (rc == TLV_ERR_END_OF_BUFFER) rc = TLV_OK;
        while (rc == TLV_OK && (rc = tlv_document_query_next(exec, &node)) == TLV_OK) {
            for (size_t i = 0; i < count; ++i)
                if (handles[i] == node) {
                    printf("%zu\n", offsets[i]);
                    break;
                }
        }
        if (rc == TLV_ERR_END_OF_BUFFER) rc = TLV_OK;
    }
    /* Scalar spans need printing before releasing their Document/Value storage. */
    if (rc == TLV_OK && result.kind != TLV_QUERY_RESULT_NODES) {
        if (result.kind == TLV_QUERY_RESULT_BOOL)
            printf("bool:%d\n", result.boolean);
        else if (result.kind == TLV_QUERY_RESULT_INTEGER)
            printf("int:%lld\n", (long long)result.integer);
        else {
            printf("%s:", result.kind == TLV_QUERY_RESULT_STRING ? "string" : "bytes");
            for (size_t i = 0; i < result.size; ++i) printf("%02x", result.data[i]);
            printf("\n");
        }
    }
    free(values);
    free(staged);
    free(scratch);
    tlv_document_free(document);
    return rc;
}
#endif
static tlv_result_t fixture_resolve(const void* context, const char* ns, size_t ns_size,
                                    const char* name, size_t name_size, tlv_tag_t* tag) {
    (void)context;
    static const uint8_t leaf = 0x5a, container = 0x70;
    if (ns_size != 7 || memcmp(ns, "fixture", 7)) return TLV_ERR_INVALID_TAG;
    if (name_size == 4 && !memcmp(name, "leaf", 4))
        *tag = tlv_tag(&leaf, 1);
    else if (name_size == 9 && !memcmp(name, "container", 9))
        *tag = tlv_tag(&container, 1);
    else
        return TLV_ERR_INVALID_TAG;
    return TLV_OK;
}
int main(int argc, char** argv) {
    if (argc == 2 && !strcmp(argv[1], "--language-features")) {
        for (unsigned i = 0; i < F_UNKNOWN; ++i) printf("function-%s\n", query_function_name(i));
        for (unsigned i = 0; i <= A_PRECEDE; ++i) printf("%s\n", query_axis_name(i));
        return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "--capabilities")) {
#if OPENTLV_DOCUMENT
        printf("document ");
#endif
#if OPENTLV_FORMAT_BER
        printf("asn1 ");
#endif
        printf("\n");
        return 0;
    }
    if (argc < 3 || argc > 5) return 2;
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
    void*              scratch = NULL;
    void*              program = NULL;
    void*              workspace = NULL;
    void*              workspace_allocation = NULL;
    tlv_fixed_format_t config = {0};
    config.tag_size = 1;
    config.length_size = 1;
    config.length_order = TLV_BYTE_ORDER_BIG_ENDIAN;
    tlv_format_t format;
    tlv_result_t rc = tlv_fixed_format_init(&format, &config);
    if (rc != TLV_OK) return 2;
    format.is_constructed = constructed;
    size_t                  hook_count;
    tlv_query_environment_t environment = {0};
    environment.format = &format;
    const tlv_query_hook_t* builtin = tlv_query_builtin_hooks(&hook_count);
    tlv_query_hook_t        hooks[4];
    memcpy(hooks, builtin, hook_count * sizeof *hooks);
#if OPENTLV_FORMAT_BER
    hooks[hook_count++] = tlv_asn1_query_date;
    environment.tags = &tlv_asn1_query_tags;
#endif
    environment.hooks = hooks;
    environment.hook_count = hook_count;
    tlv_query_compile_options_t options;
    tlv_query_compile_options_init(&options);
    options.environment = &environment;
    options.resolve = fixture_resolve;
    options.optimize = argc >= 4 && strchr(argv[3], 'u') ? 0 : 1;
    rc = tlv_query_compile_scratch(argv[1], strlen(argv[1]), &options, &scratch_size, &alignment,
                                   &diagnostic);
    if (rc != TLV_OK) goto done;
    scratch = malloc(scratch_size);
    if (!scratch) {
        rc = TLV_ERR_OUT_OF_MEMORY;
        goto done;
    }
    rc = tlv_query_compile(argv[1], strlen(argv[1]), &options, scratch, scratch_size, NULL, 0,
                           &info, &diagnostic);
    if (rc != TLV_OK) goto done;
    program = malloc(info.program_size);
    if (!program) {
        rc = TLV_ERR_OUT_OF_MEMORY;
        goto done;
    }
    rc = tlv_query_compile(argv[1], strlen(argv[1]), &options, scratch, scratch_size, program,
                           info.program_size, &info, &diagnostic);
    if (rc != TLV_OK) goto done;
    size_t workspace_size;
    int    document_mode = info.level == TLV_QUERY_D || (argc >= 4 && strchr(argv[3], 'd'));
    int    retained =
        document_mode || info.level >= TLV_QUERY_S2 || (argc >= 4 && strchr(argv[3], 'r'));
    rc = retained ? tlv_query_eval_size(program, 128, 1024, &workspace_size, &alignment)
                  : tlv_query_exec_size(program, 128, &workspace_size, &alignment);
    if (rc != TLV_OK) goto done;
    workspace_allocation = malloc(workspace_size + alignment);
    workspace = workspace_allocation ? (void*)(((uintptr_t)workspace_allocation + alignment - 1) &
                                               ~(uintptr_t)(alignment - 1))
                                     : NULL;
    if (!workspace) {
        rc = TLV_ERR_OUT_OF_MEMORY;
        goto done;
    }
    tlv_query_exec_t* exec;
    rc = retained ? tlv_query_eval_init(program, &environment, workspace, workspace_size, 128, 1024,
                                        100000000, &exec)
                  : tlv_query_exec_init(program, workspace, workspace_size, 128, 100000, 10000000,
                                        &exec);
    if (rc != TLV_OK) goto done;
#if OPENTLV_DOCUMENT
    if (document_mode) {
        rc = document_run(input, size, &format, exec, &diagnostic);
        goto done;
    }
#else
    if (document_mode) {
        rc = TLV_ERR_UNSUPPORTED_TYPE;
        goto done;
    }
#endif
    tlv_tree_reader_t reader;
    tlv_tree_frame_t  frames[128];
    size_t            split = argc == 5 ? (size_t)strtoul(argv[4], NULL, 10) : size;
    if (split > size) {
        rc = TLV_ERR_INVALID_ARG;
        goto done;
    }
    rc = argc == 5 ? tlv_tree_reader_init_incremental(&reader, input, split, &format, frames, 128,
                                                      128, 100000)
                   : tlv_tree_reader_init(&reader, input, size, &format, frames, 128, 128, 100000);
    if (rc != TLV_OK) goto done;
    rc = tlv_query_program_visit(&reader, exec, print_match, NULL, &diagnostic);
    if (argc == 5 && rc == TLV_NEED_MORE_DATA) {
        rc = tlv_query_program_visit(&reader, exec, print_match, NULL, &diagnostic);
        if (rc == TLV_NEED_MORE_DATA) rc = tlv_tree_reader_set_input(&reader, input, size, 0, 1);
        if (rc == TLV_OK)
            rc = tlv_query_program_visit(&reader, exec, print_match, NULL, &diagnostic);
    }
    if (rc == TLV_OK && info.result_kind != TLV_QUERY_RESULT_NODES) {
        tlv_query_result_t result;
        rc = tlv_query_exec_result(exec, &result);
        if (rc == TLV_OK) {
            if (result.kind == TLV_QUERY_RESULT_BOOL)
                printf("bool:%d\n", result.boolean);
            else if (result.kind == TLV_QUERY_RESULT_INTEGER)
                printf("int:%lld\n", (long long)result.integer);
            else {
                printf("%s:", result.kind == TLV_QUERY_RESULT_STRING ? "string" : "bytes");
                for (size_t i = 0; i < result.size; ++i) printf("%02x", result.data[i]);
                printf("\n");
            }
        }
    }
done:
    if (rc != TLV_OK)
        fprintf(stderr, "%d %u %zu %zu\n", (int)rc, (unsigned)diagnostic.kind, diagnostic.begin,
                diagnostic.end);
    free(workspace_allocation);
    free(program);
    free(scratch);
    free(input);
    return rc == TLV_OK ? 0 : 1;
}
