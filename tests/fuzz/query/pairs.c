// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#include "tlv/query/program.h"
#include "tlv/formats/fixed.h"
#include "tlv/document/document.h"
#include "tlv/config.h"
#include <stdlib.h>
#include <string.h>

typedef struct matches {
    size_t offsets[40], count;
    int    stop;
} matches_t;
static tlv_visit_result_t collect(const tlv_tree_event_t* event, void* context) {
    matches_t* matches = context;
    if (matches->count == 40) abort();
    matches->offsets[matches->count++] = event->offset;
    return matches->stop ? TLV_VISIT_STOP : TLV_VISIT_CONTINUE;
}
static int constructed(const void* context, const tlv_tag_t* tag) {
    (void)context;
    return tag->size == 1 && tag->data[0] == 0x70;
}
static void* align16(void* buffer) {
    return (void*)(((uintptr_t)buffer + 15) & ~(uintptr_t)15);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (!size || size > 4096) return 0;
    const char* texts[] = {"//5A", "//70//5A | //50", "(//5A)[last()]", "count(//5A)",
                           "//5A[following-sibling::50]"};
    const char* text = texts[data[0] % 5];
    uint8_t     wire[256] = {0x70, 0};
    size_t      extent = 2;
    for (size_t i = 1; i < size && i <= 32; ++i) {
        wire[extent++] = data[i] & 1 ? 0x5a : 0x50;
        wire[extent++] = 1;
        wire[extent++] = data[i];
    }
    wire[1] = (uint8_t)(extent - 2);
    tlv_fixed_format_t config = {0};
    config.tag_size = config.length_size = 1;
    config.length_order = TLV_BYTE_ORDER_BIG_ENDIAN;
    tlv_format_t format;
    if (tlv_fixed_format_init(&format, &config) != TLV_OK) abort();
    format.is_constructed = constructed;
    uint64_t                    scratch[8192], image[2048], workspace[3][20000];
    tlv_query_compile_options_t options;
    tlv_query_compile_options_init(&options);
    options.optimize = (data[0] & 128) != 0;
    tlv_query_program_info_t info = {0};
    info.struct_size = sizeof info;
    if (tlv_query_compile(text, strlen(text), &options, scratch, sizeof scratch, image,
                          sizeof image, &info, NULL) != TLV_OK)
        abort();
    const tlv_query_program_t* program = (const tlv_query_program_t*)image;
    matches_t                  matches[2];
    memset(matches, 0, sizeof matches);
    tlv_query_result_t results[2];
    for (size_t mode = 0; mode < 2; ++mode) {
        tlv_query_exec_t* exec;
        tlv_result_t      rc =
            mode || info.level >= TLV_QUERY_S2
                ? tlv_query_eval_init(program, NULL, align16(workspace[mode]),
                                      sizeof workspace[mode] - 16, 2, 40, 1000000, &exec)
                : tlv_query_exec_init(program, align16(workspace[mode]),
                                      sizeof workspace[mode] - 16, 2, 40, 1000000, &exec);
        if (rc != TLV_OK) abort();
        tlv_tree_frame_t  frames[3];
        tlv_tree_reader_t reader;
        if (tlv_tree_reader_init(&reader, wire, extent, &format, frames, 3, 2, 40) != TLV_OK)
            abort();
        matches[mode].stop = (data[0] & 64) != 0;
        for (size_t resume = 0; resume < 42; ++resume) {
            size_t before = matches[mode].count;
            if (tlv_query_program_visit(&reader, exec, collect, &matches[mode], NULL) != TLV_OK)
                abort();
            tlv_query_exec_info_t status = {0};
            status.struct_size = sizeof status;
            if (tlv_query_exec_info(exec, &status) != TLV_OK) abort();
            if (status.finished && before == matches[mode].count) break;
        }
        memset(&results[mode], 0, sizeof results[mode]);
        if (mode || info.level >= TLV_QUERY_S2) {
            if (tlv_query_exec_result(exec, &results[mode]) != TLV_OK) abort();
        } else
            results[mode].kind = TLV_QUERY_RESULT_NODES;
    }
    if (results[0].kind != results[1].kind ||
        (results[0].kind == TLV_QUERY_RESULT_INTEGER && results[0].integer != results[1].integer) ||
        matches[0].count != matches[1].count ||
        memcmp(matches[0].offsets, matches[1].offsets, matches[0].count * sizeof(size_t)))
        abort();
#if OPENTLV_DOCUMENT
    tlv_document_options_t document_options;
    if (tlv_document_options_init(&document_options, &format) != TLV_OK) abort();
    tlv_document_t* document = NULL;
    if (tlv_document_parse(wire, extent, &document_options, &document, NULL) != TLV_OK) abort();
    tlv_query_exec_t* exec;
    if (tlv_query_eval_init(program, NULL, align16(workspace[2]), sizeof workspace[2] - 16, 2, 40,
                            1000000, &exec) != TLV_OK ||
        tlv_document_query_evaluate(document, exec, NULL, NULL, 0, NULL, NULL) != TLV_OK)
        abort();
    tlv_query_result_t result;
    if (tlv_query_exec_result(exec, &result) != TLV_OK || result.kind != results[0].kind ||
        (result.kind == TLV_QUERY_RESULT_INTEGER && result.integer != results[0].integer))
        abort();
    if (result.kind == TLV_QUERY_RESULT_NODES) {
        size_t       count = 0;
        tlv_node_t*  selected;
        tlv_result_t rc;
        while ((rc = tlv_document_query_next(exec, &selected)) == TLV_OK) {
            size_t offset = 0;
            if (selected != tlv_document_first(document)) {
                tlv_node_t* child = tlv_node_first_child(tlv_document_first(document));
                offset = 2;
                while (child != selected && child) {
                    child = tlv_node_next(child);
                    offset += 3;
                }
                if (!child) abort();
            }
            if (count >= matches[0].count || matches[0].offsets[count++] != offset) abort();
        }
        if (rc != TLV_ERR_END_OF_BUFFER || count != matches[0].count) abort();
    }
    tlv_document_free(document);
#endif
    return 0;
}
