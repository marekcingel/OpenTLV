// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#include "adversarial_native.h"
#if OPENTLV_DOCUMENT && OPENTLV_READER && OPENTLV_WRITER
#include "tlv/document/document.h"
#include "tlv/formats/fixed.h"
#include "tlv/writer/tree.h"
static int native_constructed(const void* context, const tlv_tag_t* tag) {
    (void)context;
    return tag->size == 1 && tag->data[0] == 0x70;
}
static int native_document(const tlv_query_program_t* p, size_t kind) {
    tlv_fixed_format_t config = {
        {0}, {0, TLV_BYTE_ORDER_UNKNOWN}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
    config.identifier.size = config.length.size = 1;
    config.length.byte_order = TLV_BYTE_ORDER_BIG_ENDIAN;
    tlv_format_t format;
    CHECK(tlv_fixed_format_init(&format, &config) == TLV_OK);
    format.is_constructed = native_constructed;
    tlv_document_options_t options;
    CHECK(tlv_document_options_init(&options, &format) == TLV_OK);
    options.retain_source_locations = 1;
    const uint8_t   wire[] = {2, 0, 0x70, 3, 1, 1, 9};
    tlv_document_t* document = NULL;
    CHECK(tlv_document_parse(wire, sizeof wire, &options, &document, NULL) == TLV_OK);
    arena             memory;
    tlv_query_exec_t* e;
    size_t            bytes;
    CHECK(initialize(p, 1, &memory, &e, &bytes) == 0);
    uint8_t                     values[64], scratch[64];
    tlv_tree_writer_frame_t     frames[8];
    tlv_tree_writer_workspace_t staging = {0};
    staging.data = values;
    staging.data_capacity = sizeof values;
    staging.scratch = scratch;
    staging.scratch_capacity = sizeof scratch;
    staging.frames = frames;
    staging.frame_capacity = 8;
    CHECK(tlv_document_query_evaluate(document, e, NULL, values, sizeof values, &staging, NULL) ==
          TLV_OK);
    tlv_query_result_t result;
    CHECK(tlv_query_exec_result(e, &result) == TLV_OK);
    if (kind < 4) {
        tlv_node_t* node = NULL;
        CHECK(tlv_document_query_next(e, &node) == TLV_OK);
        tlv_node_t* expected =
            kind == 3   ? tlv_document_first(document)
            : kind == 1 ? tlv_node_next(tlv_document_first(document))
                        : tlv_node_first_child(tlv_node_next(tlv_document_first(document)));
        CHECK(node == expected);
        CHECK(tlv_document_query_next(e, &node) == TLV_ERR_END_OF_BUFFER);
    } else if (kind == 4)
        CHECK(result.integer == 1);
    else if (kind == 5)
        CHECK(result.boolean);
    else
        CHECK(result.size == 1 && result.data[0] == 9);
    /* A successful edit between public calls invalidates all result access. */
    const uint8_t replacement = 7;
    CHECK(tlv_node_set_value(tlv_document_first(document), &replacement, 1) == TLV_OK);
    CHECK(tlv_query_exec_result(e, &result) == TLV_ERR_INVALID_STATE);
    CHECK(tlv_query_exec_reset(e) == TLV_OK);
    tlv_document_free(document);
    return 0;
}
#endif
static int native_profiles(void) {
    const tlv_query_level_t levels[] = {TLV_QUERY_S0, TLV_QUERY_S1, TLV_QUERY_S2, TLV_QUERY_D,
                                        TLV_QUERY_S2, TLV_QUERY_S2, TLV_QUERY_S2};
    const uint8_t           tags[] = {0x70, 1, 0x70, 2};
    const uint8_t           value[] = {1, 1, 9};
    for (size_t kind = 0; kind < sizeof native_plans / sizeof *native_plans; ++kind) {
        const tlv_query_program_t* p = NULL;
        const tlv_query_program_t* image = native_plans[kind];
#if !OPENTLV_DOCUMENT
        if (levels[kind] == TLV_QUERY_D) {
            CHECK(tlv_query_plan_open(image, image->reserved, &p, NULL) ==
                  TLV_ERR_UNSUPPORTED_TYPE);
            continue;
        }
#endif
        CHECK(tlv_query_plan_open(image, image->reserved, &p, NULL) == TLV_OK);
        CHECK(p->text_size == 0 && p->level == (unsigned)levels[kind]);
#if OPENTLV_DOCUMENT && OPENTLV_READER && OPENTLV_WRITER
        CHECK(native_document(p, kind) == 0);
#endif
#if OPENTLV_QUERY_FRONTEND
        const char* sources[] = {
            "//01",        "/70[child::01]", "(//01)[last()]", "//01/preceding::*",
            "count(//01)", "exists(//01)",   "value(//01[1])"};
        arena                      runtime_image;
        const tlv_query_program_t* runtime;
        CHECK(compile_plan(sources[kind], NULL, &runtime_image, &runtime) == 0);
        CHECK(runtime->level == p->level && runtime->count == p->count &&
              runtime->pattern_capacity == p->pattern_capacity &&
              runtime->codec_stride == p->codec_stride);
        CHECK(!memcmp(p + 1, runtime + 1, p->count * sizeof(tlv_query_instruction_t)));
        CHECK(!memcmp((const uint8_t*)p + p->text_offset + 1,
                      (const uint8_t*)runtime + runtime->text_offset + runtime->text_size + 1,
                      p->payload_size));
#endif
        arena             memory;
        tlv_query_exec_t* e;
        size_t            bytes;
        CHECK(initialize(p, 1, &memory, &e, &bytes) == 0);
        if (levels[kind] == TLV_QUERY_D) {
            CHECK(tlv_query_exec_finish(e, NULL) == TLV_ERR_UNSUPPORTED_TYPE);
            CHECK(tlv_query_exec_finish(e, NULL) == TLV_ERR_INVALID_STATE);
            CHECK(tlv_query_exec_reset(e) == TLV_OK);
            continue;
        }
        for (size_t i = 0; i < 4; ++i) {
            tlv_tree_event_t input = {0};
            input.kind = i == 0 ? TLV_TREE_BEGIN : i == 2 ? TLV_TREE_END : TLV_TREE_ELEMENT;
            input.depth = i == 1 ? 1 : 0;
            input.element.tag = tlv_tag(tags + i, 1);
            input.element.value.data = i == 1 ? value + 2 : value;
            input.element.value.size = i == 1 ? 1 : i == 0 ? 3 : 0;
            input.offset = i;
            int matched;
            CHECK(tlv_query_exec_feed(e, &input, &matched, NULL) == TLV_OK);
        }
        CHECK(tlv_query_exec_finish(e, NULL) == TLV_OK);
        tlv_query_result_t result;
        CHECK(tlv_query_exec_result(e, &result) == TLV_OK);
        if (kind < 3) {
            tlv_tree_event_t output;
            size_t           ordinal;
            CHECK(tlv_query_result_next_ordinal(e, &output, &ordinal) == TLV_OK);
            CHECK(ordinal == (kind == 1 ? 0u : 1u));
            CHECK(tlv_query_result_next(e, &output) == TLV_ERR_END_OF_BUFFER);
        } else if (kind == 4)
            CHECK(result.kind == TLV_QUERY_RESULT_INTEGER && result.integer == 1);
        else if (kind == 5)
            CHECK(result.kind == TLV_QUERY_RESULT_BOOL && result.boolean);
        else
            CHECK(result.kind == TLV_QUERY_RESULT_BYTES && result.size == 1 && result.data[0] == 9);
        /* Invalid calls after EOF preserve the result. Reset removes publication. */
        CHECK(tlv_query_exec_finish(e, NULL) == TLV_OK);
        CHECK(tlv_query_exec_reset(e) == TLV_OK);
        CHECK(tlv_query_exec_result(e, &result) == TLV_ERR_INVALID_STATE);
    }
    /* S1 publication survives selected/selected, but terminal malformed feed
     * hides it. This is the delayed-match counterpart of generated S0 sequences. */
    const tlv_query_program_t* p = &native_1.header;
    arena                      memory;
    tlv_query_exec_t*          e;
    size_t                     bytes;
    CHECK(initialize(p, 0, &memory, &e, &bytes) == 0);
    tlv_tree_event_t input = event();
    int              matched;
    input.kind = TLV_TREE_BEGIN;
    input.element.tag = tlv_tag(tags, 1);
    CHECK(tlv_query_exec_feed(e, &input, &matched, NULL) == TLV_OK);
    input = event();
    input.depth = 1;
    CHECK(tlv_query_exec_feed(e, &input, &matched, NULL) == TLV_OK);
    input.kind = TLV_TREE_END;
    input.depth = 0;
    CHECK(tlv_query_exec_feed(e, &input, &matched, NULL) == TLV_OK && matched);
    tlv_tree_event_t output;
    CHECK(tlv_query_exec_selected(e, &output) == TLV_OK && output.element.tag.data[0] == 0x70);
    CHECK(tlv_query_exec_selected(e, &output) == TLV_OK);
    CHECK(tlv_query_exec_feed(e, &input, &matched, NULL) == TLV_ERR_INVALID_VALUE);
    CHECK(tlv_query_exec_selected(e, &output) == TLV_ERR_INVALID_STATE);
    return 0;
}
