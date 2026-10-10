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
    int    fail;
} matches_t;
static tlv_visit_result_t collect(const tlv_tree_event_t* event, void* context) {
    matches_t* matches = context;
    if (matches->count == 40) abort();
    matches->offsets[matches->count++] = event->offset;
    if (matches->fail) return TLV_VISIT_ERROR;
    return matches->stop ? TLV_VISIT_STOP : TLV_VISIT_CONTINUE;
}
typedef struct provider {
    tlv_result_t status;
    int          invalid_type;
} provider_t;
static tlv_result_t decode(const void* context, const tlv_tree_event_t* event, const uint8_t* data,
                           size_t size, void* scratch, size_t capacity, tlv_query_result_t* result,
                           tlv_codec_diagnostic_t* diagnostic) {
    tlv_codec_diagnostic_init(diagnostic, TLV_CODEC_OP_DECODE);
    const provider_t* provider = context;
    if (!event || event->element.tag.size != 1 || event->element.tag.data[0] != 0x5a || size != 1 ||
        !data || capacity != 8 || (uintptr_t)scratch % 8)
        abort();
    if (provider->status != TLV_OK)
        return tlv_codec_diagnostic_result(diagnostic, provider->status);
    memset(result, 0, sizeof *result);
    result->kind = provider->invalid_type ? TLV_QUERY_RESULT_BOOL : TLV_QUERY_RESULT_INTEGER;
    result->integer = data[0];
    return tlv_codec_diagnostic_result(diagnostic, TLV_OK);
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
    const char* texts[] = {"//5A",
                           "//70//5A | //50",
                           "(//5A)[last()]",
                           "count(//5A)",
                           "//5A[following-sibling::50]",
                           "70[not(5A)]"};
    const char* text = texts[data[0] % (sizeof texts / sizeof *texts)];
    uint8_t     wire[256] = {0x70, 0};
    size_t      extent = 2;
    for (size_t i = 1; i < size && i <= 32; ++i) {
        wire[extent++] = data[i] & 1 ? 0x5a : 0x50;
        wire[extent++] = 1;
        wire[extent++] = data[i];
    }
    wire[1] = (uint8_t)(extent - 2);
    tlv_fixed_format_t config = {
        {0}, {0, TLV_BYTE_ORDER_UNKNOWN}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
    config.identifier.size = config.length.size = 1;
    config.length.byte_order = TLV_BYTE_ORDER_BIG_ENDIAN;
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
    matches_t                  matches[3];
    memset(matches, 0, sizeof matches);
    tlv_query_result_t results[3];
    for (size_t mode = 0; mode < 3; ++mode) {
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
        size_t            available = size > 1 ? data[1] % (extent + 1) : 0;
        rc = mode == 2 ? tlv_tree_reader_init_incremental(&reader, wire, available, &format, frames,
                                                          3, 2, 40)
                       : tlv_tree_reader_init(&reader, wire, extent, &format, frames, 3, 2, 40);
        if (rc != TLV_OK) abort();
        matches[mode].stop = (data[0] & 64) != 0;
        int finished = 0;
        for (size_t resume = 0; resume < 300; ++resume) {
            size_t before = matches[mode].count;
            rc = tlv_query_program_visit(&reader, exec, collect, &matches[mode], NULL);
            if (rc == TLV_NEED_MORE_DATA && mode == 2) {
                /* Keep every previously published span stable. An unchanged
                 * incomplete window must not advance or publish twice. */
                before = matches[mode].count;
                if (tlv_query_program_visit(&reader, exec, collect, &matches[mode], NULL) !=
                        TLV_NEED_MORE_DATA ||
                    matches[mode].count != before)
                    abort();
                if (available < extent) available += 1 + data[resume % size] % (extent - available);
                if (tlv_tree_reader_set_input(&reader, wire, available, 0, available == extent) !=
                    TLV_OK)
                    abort();
                continue;
            }
            if (rc != TLV_OK) abort();
            tlv_query_exec_info_t status = {0};
            status.struct_size = sizeof status;
            if (tlv_query_exec_info(exec, &status) != TLV_OK) abort();
            if (status.finished && before == matches[mode].count) {
                finished = 1;
                break;
            }
        }
        if (!finished) abort();
        memset(&results[mode], 0, sizeof results[mode]);
        if (mode || info.level >= TLV_QUERY_S2) {
            if (tlv_query_exec_result(exec, &results[mode]) != TLV_OK) abort();
        } else
            results[mode].kind = TLV_QUERY_RESULT_NODES;
    }
    for (size_t mode = 1; mode < 3; ++mode)
        if (results[0].kind != results[mode].kind ||
            (results[0].kind == TLV_QUERY_RESULT_INTEGER &&
             results[0].integer != results[mode].integer) ||
            matches[0].count != matches[mode].count ||
            memcmp(matches[0].offsets, matches[mode].offsets, matches[0].count * sizeof(size_t)))
            abort();
    if (matches[0].count) {
        for (size_t retained = 0; retained < 2; ++retained) {
            tlv_query_exec_t* failed;
            tlv_result_t      rc =
                retained || info.level >= TLV_QUERY_S2
                    ? tlv_query_eval_init(program, NULL, align16(workspace[2]),
                                          sizeof workspace[2] - 16, 2, 40, 1000000, &failed)
                    : tlv_query_exec_init(program, align16(workspace[2]), sizeof workspace[2] - 16,
                                          2, 40, 1000000, &failed);
            tlv_tree_frame_t  frames[3];
            tlv_tree_reader_t reader;
            matches_t         rejected = {{0}, 0, 0, 1};
            if (rc != TLV_OK ||
                tlv_tree_reader_init(&reader, wire, extent, &format, frames, 3, 2, 40) != TLV_OK ||
                tlv_query_program_visit(&reader, failed, collect, &rejected, NULL) !=
                    TLV_ERR_VISITOR ||
                rejected.count != 1 || rejected.offsets[0] != matches[0].offsets[0] ||
                tlv_query_program_visit(&reader, failed, collect, &rejected, NULL) !=
                    TLV_ERR_INVALID_STATE)
                abort();
            tlv_query_exec_info_t status = {0};
            status.struct_size = sizeof status;
            if (tlv_query_exec_info(failed, &status) != TLV_OK || !status.invalid) abort();
        }
    }
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
        if (rc != TLV_END || count != matches[0].count) abort();
    }
    tlv_document_free(document);
#endif
    /* Provider failure and malformed result types are independent fuzz inputs.
     * Reinitialize exactly the same workspace after failure, then prove that a
     * compatible successful provider can evaluate without stale invalid state. */
    provider_t              provider = {(tlv_result_t)(data[0] % 6), (data[0] & 32) != 0};
    tlv_query_hook_t        hook = {101, TLV_QUERY_NUM, 8, 8, &provider, decode};
    tlv_query_environment_t environment = {0};
    environment.hooks = &hook;
    environment.hook_count = 1;
    options.environment = &environment;
    const char* conversion = "num(//5A)";
    if (tlv_query_compile(conversion, strlen(conversion), &options, scratch, sizeof scratch, image,
                          sizeof image, &info, NULL) != TLV_OK)
        abort();
    const uint8_t value[] = {0x5a, 1, data[0]};
    for (size_t attempt = 0; attempt < 2; ++attempt) {
        tlv_query_exec_t* conversion_exec;
        tlv_tree_frame_t  frames[3];
        tlv_tree_reader_t reader;
        size_t            required, alignment;
        if (tlv_query_eval_size(program, 2, 1, &required, &alignment) != TLV_OK ||
            required > sizeof workspace[2] - 16)
            abort();
        if (tlv_query_eval_init(program, &environment, align16(workspace[2]), required - 1, 2, 1,
                                1000000, &conversion_exec) != TLV_ERR_BUFFER_TOO_SHORT ||
            tlv_query_eval_init(program, &environment, align16(workspace[2]), required, 2, 1,
                                1000000, &conversion_exec) != TLV_OK ||
            tlv_tree_reader_init(&reader, value, sizeof value, &format, frames, 3, 2, 1) != TLV_OK)
            abort();
        tlv_query_diagnostic_t diagnostic;
        tlv_result_t           rc =
            tlv_query_program_visit(&reader, conversion_exec, collect, &matches[2], &diagnostic);
        if (provider.status != TLV_OK || provider.invalid_type) {
            const int32_t      expected_codec = (int32_t)provider.status;
            const tlv_result_t expected = provider.status == TLV_OK || provider.status == TLV_END
                                              ? TLV_ERR_CALLBACK
                                              : provider.status;
            const tlv_codec_violation_t violation =
                provider.status == TLV_OK    ? TLV_CODEC_VIOLATION_TYPE
                : provider.status == TLV_END ? TLV_CODEC_VIOLATION_RESULT
                                             : TLV_CODEC_VIOLATION_NONE;
            if (rc != expected || diagnostic.diagnostic.code != expected ||
                diagnostic.kind != (expected == TLV_ERR_CALLBACK ? TLV_QUERY_ERROR_CALLBACK
                                                                 : TLV_QUERY_ERROR_CODEC) ||
                !diagnostic.has_codec || diagnostic.codec != expected_codec ||
                diagnostic.codec_detail.reported != expected_codec ||
                diagnostic.codec_detail.violation != violation ||
                diagnostic.diagnostic.location.kind != TLV_LOCATION_UNKNOWN ||
                diagnostic.begin >= diagnostic.end ||
                tlv_query_program_visit(&reader, conversion_exec, collect, &matches[2], NULL) !=
                    TLV_ERR_INVALID_STATE)
                abort();
        } else {
            tlv_query_result_t result;
            if (rc != TLV_OK || tlv_query_exec_result(conversion_exec, &result) != TLV_OK ||
                result.kind != TLV_QUERY_RESULT_INTEGER || result.integer != data[0])
                abort();
        }
        provider.status = TLV_OK;
        provider.invalid_type = 0;
    }
    return 0;
}
