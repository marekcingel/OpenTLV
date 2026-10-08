// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#include "tlv/query/program.h"
#include "tlv/query/query.h"
#include "tlv/schema/schema.h"
#include <stdio.h>
#include <stddef.h>

#define TYPE(type)                                                                                 \
    do {                                                                                           \
        struct query_alignment {                                                                   \
            char prefix;                                                                           \
            type value;                                                                            \
        };                                                                                         \
        printf("\"%s\":{\"size\":%zu,\"alignment\":%zu", #type, sizeof(type),                      \
               offsetof(struct query_alignment, value));                                           \
    } while (0)
#define FIELD(type, field) printf(",\"%s\":%zu", #field, offsetof(type, field))
int main(void) {
    printf("{\"version\":1,\"pointer_bits\":%zu,\"types\":{", sizeof(void*) * 8);
    TYPE(tlv_location_t);
    FIELD(tlv_location_t, domain);
    FIELD(tlv_location_t, kind);
    FIELD(tlv_location_t, begin);
    FIELD(tlv_location_t, end);
    printf("},");
    TYPE(tlv_diagnostic_t);
    FIELD(tlv_diagnostic_t, code);
    FIELD(tlv_diagnostic_t, severity);
    FIELD(tlv_diagnostic_t, location);
    FIELD(tlv_diagnostic_t, expected);
    FIELD(tlv_diagnostic_t, actual);
    FIELD(tlv_diagnostic_t, contexts);
    FIELD(tlv_diagnostic_t, has_path);
    FIELD(tlv_diagnostic_t, path);
    printf("},");
    TYPE(tlv_schema_definition_location_t);
    FIELD(tlv_schema_definition_location_t, kind);
    FIELD(tlv_schema_definition_location_t, owner);
    FIELD(tlv_schema_definition_location_t, index);
    printf("},");
    TYPE(tlv_query_t);
    printf("},");
    TYPE(tlv_query_matcher_t);
    printf("},");
    TYPE(tlv_query_program_info_t);
    FIELD(tlv_query_program_info_t, struct_size);
    FIELD(tlv_query_program_info_t, program_size);
    FIELD(tlv_query_program_info_t, program_alignment);
    FIELD(tlv_query_program_info_t, scratch_size);
    FIELD(tlv_query_program_info_t, scratch_alignment);
    FIELD(tlv_query_program_info_t, states);
    FIELD(tlv_query_program_info_t, language_version);
    FIELD(tlv_query_program_info_t, level);
    FIELD(tlv_query_program_info_t, result_kind);
    FIELD(tlv_query_program_info_t, expression_values);
    FIELD(tlv_query_program_info_t, instructions);
    FIELD(tlv_query_program_info_t, variable_slots);
    FIELD(tlv_query_program_info_t, codec_scratch);
    FIELD(tlv_query_program_info_t, pattern_bytes);
    FIELD(tlv_query_program_info_t, optimized_states);
    FIELD(tlv_query_program_info_t, expression_stack);
    FIELD(tlv_query_program_info_t, candidate_size);
    FIELD(tlv_query_program_info_t, candidate_alignment);
    FIELD(tlv_query_program_info_t, frame_states);
    FIELD(tlv_query_program_info_t, decision_timing);
    FIELD(tlv_query_program_info_t, stable_input_required);
    FIELD(tlv_query_program_info_t, constructed_values_required);
    printf("},");
    TYPE(tlv_query_exec_info_t);
    FIELD(tlv_query_exec_info_t, struct_size);
    FIELD(tlv_query_exec_info_t, elements);
    FIELD(tlv_query_exec_info_t, work);
    FIELD(tlv_query_exec_info_t, skipped_subtrees);
    FIELD(tlv_query_exec_info_t, finished);
    FIELD(tlv_query_exec_info_t, full_validation);
    FIELD(tlv_query_exec_info_t, invalid);
    printf("},");
    TYPE(tlv_query_diagnostic_t);
    FIELD(tlv_query_diagnostic_t, diagnostic);
    FIELD(tlv_query_diagnostic_t, kind);
    FIELD(tlv_query_diagnostic_t, begin);
    FIELD(tlv_query_diagnostic_t, end);
    FIELD(tlv_query_diagnostic_t, reader);
    printf("},");
    TYPE(tlv_query_result_t);
    FIELD(tlv_query_result_t, kind);
    FIELD(tlv_query_result_t, boolean);
    FIELD(tlv_query_result_t, integer);
    FIELD(tlv_query_result_t, data);
    printf(",\"size_offset\":%zu", offsetof(tlv_query_result_t, size));
    printf("},");
    TYPE(tlv_query_compile_options_t);
    FIELD(tlv_query_compile_options_t, struct_size);
    FIELD(tlv_query_compile_options_t, environment);
    FIELD(tlv_query_compile_options_t, optimize);
    printf("},");
    TYPE(tlv_query_environment_t);
    printf("},");
    TYPE(tlv_query_hook_t);
    printf("},");
    TYPE(tlv_query_variable_t);
    printf("},");
    TYPE(tlv_query_variable_info_t);
    printf("}}}\n");
    return 0;
}
