// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
/* Included after adversarial_callbacks.h; shares CHECK/arena/compile_plan. */
#if OPENTLV_QUERY_FRONTEND && OPENTLV_DOCUMENT && OPENTLV_READER && OPENTLV_WRITER
typedef struct document_format_reinit_state {
    tlv_format_t               base;
    const tlv_query_program_t* program;
    tlv_query_exec_t*          exec;
    tlv_document_t*            document;
    tlv_node_t*                node;
    size_t                     bytes;
    unsigned                   trigger, calls, errors;
    int                        active, mutation;
} document_format_reinit_state;

static void document_format_reinit(document_format_reinit_state* state, unsigned trigger) {
    if (!state->active || state->trigger != trigger || state->calls) return;
    ++state->calls;
    /* Deliberately violate raw-init ownership inside the format callback. */
    if (tlv_query_eval_init(state->program, NULL, state->exec, state->bytes, 3, 8, 100000,
                            &state->exec) != TLV_OK)
        ++state->errors;
    if (state->mutation == 1) tlv_node_erase(state->node);
    if (state->mutation == 2) tlv_document_free(state->document);
}

static tlv_result_t document_format_reinit_measure(const void*          context,
                                                   const tlv_element_t* element,
                                                   tlv_encoding_t*      encoding,
                                                   tlv_format_error_t*  error) {
    document_format_reinit_state* state = (document_format_reinit_state*)context;
    document_format_reinit(state, 0);
    return state->base.measure(state->base.context, element, encoding, error);
}

static tlv_result_t document_format_reinit_encode(const void* context, const tlv_element_t* element,
                                                  uint8_t* data, size_t capacity, size_t* written,
                                                  tlv_format_error_t* error) {
    document_format_reinit_state* state = (document_format_reinit_state*)context;
    document_format_reinit(state, 1);
    return state->base.encode(state->base.context, element, data, capacity, written, error);
}

static tlv_result_t document_format_reinit_decode(const void* context, const uint8_t* data,
                                                  size_t size, tlv_decoded_t* decoded,
                                                  tlv_format_error_t* error) {
    document_format_reinit_state* state = (document_format_reinit_state*)context;
    document_format_reinit(state, 2);
    return state->base.decode(state->base.context, data, size, decoded, error);
}

static int document_format_reinitialization(void) {
    tlv_fixed_format_t config = {
        {0}, {0, TLV_BYTE_ORDER_UNKNOWN}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
    config.identifier.size = config.length.size = 1;
    config.length.byte_order = TLV_BYTE_ORDER_BIG_ENDIAN;
    for (unsigned trigger = 0; trigger < 3; ++trigger)
        for (int mutation = 0; mutation < 3; ++mutation) {
            const uint8_t                wire[] = {1, 1, 9, 1, 1, 8};
            document_format_reinit_state state = {0};
            state.trigger = trigger;
            state.mutation = mutation;
            CHECK(tlv_fixed_format_init(&state.base, &config) == TLV_OK);
            tlv_format_t format;
            CHECK(tlv_format_init(&format, &state, document_format_reinit_decode,
                                  document_format_reinit_measure,
                                  document_format_reinit_encode) == TLV_OK);
            tlv_document_options_t options;
            CHECK(tlv_document_options_init(&options, &format) == TLV_OK);
            CHECK(tlv_document_parse(wire, sizeof wire, &options, &state.document, NULL) == TLV_OK);
            state.node = tlv_document_first(state.document);
            arena image, memory;
            CHECK(compile_plan("value(//01[1])", NULL, &image, &state.program) == 0);
            size_t alignment;
            CHECK(tlv_query_eval_size(state.program, 3, 8, &state.bytes, &alignment) == TLV_OK);
            CHECK(state.bytes <= sizeof memory.bytes - 16);
            CHECK(tlv_query_eval_init(state.program, NULL, aligned(&memory), state.bytes, 3, 8,
                                      100000, &state.exec) == TLV_OK);
            uint8_t                     values[64], scratch[64];
            tlv_tree_writer_frame_t     frames[8];
            tlv_tree_writer_workspace_t staging = {0};
            staging.data = values;
            staging.data_capacity = sizeof values;
            staging.scratch = scratch;
            staging.scratch_capacity = sizeof scratch;
            staging.frames = frames;
            staging.frame_capacity = 8;
            state.active = 1;
            tlv_query_diagnostic_t diagnostic = {0};
            tlv_result_t rc = tlv_document_query_evaluate(state.document, state.exec, NULL, values,
                                                          sizeof values, &staging, &diagnostic);
            CHECK(rc == TLV_ERR_INVALID_ARG);
            CHECK(test_query_diagnostic_matches(rc, &diagnostic));
            CHECK(state.calls == 1 && !state.errors);
            tlv_query_exec_info_t info = {0};
            info.struct_size = sizeof info;
            CHECK(tlv_query_exec_info(state.exec, &info) == TLV_OK && info.invalid &&
                  !info.finished && !info.elements);
            tlv_query_result_t result;
            CHECK(tlv_query_exec_result(state.exec, &result) == TLV_ERR_INVALID_ARG);
            CHECK(tlv_query_exec_reset(state.exec) == TLV_OK);
            if (mutation != 2) {
                /* The failed evaluation must release the original Document scope. */
                CHECK(tlv_document_count(state.document) == (mutation ? 1 : 2));
                const uint8_t value = 7;
                CHECK(tlv_node_set_value(tlv_document_first(state.document), &value, 1) == TLV_OK);
                state.active = 0;
                CHECK(tlv_document_query_evaluate(state.document, state.exec, NULL, values,
                                                  sizeof values, &staging, NULL) == TLV_OK);
                CHECK(tlv_query_exec_result(state.exec, &result) == TLV_OK);
                CHECK(result.kind == TLV_QUERY_RESULT_BYTES && result.size == 1 &&
                      result.data[0] == value);
                tlv_document_free(state.document);
            }
        }
    return 0;
}
#endif
