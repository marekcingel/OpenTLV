#include "commands/validate_command.hpp"
#include <cstring>
#include <sstream>
#include "commands/support.hpp"
#include "tlv/config.h"
#if OPENTLV_PROFILE_EMV
#include "tlv/builtins/emv/emv.h"
#include "tlv/builtins/emv/emv_schema.h"
#endif

namespace cli {

void validate_command::run_emv_checks() {
#if OPENTLV_PROFILE_EMV
    check_.presentation = cli_presentation_t();
    check_.data = data();
    check_.predicate = predicate_;
    diagnostic_scope_init(check_.scope, size());
    check_.result = TLV_OK;
    check_.offset = 0;
    check_.field_name = nullptr;

    if (options_.emv_check & emv_check_structure) {
        tlv_schema_diagnostic_t        diag;
        tlv_schema_diagnostic_report_t report = {&diag, 1, 0};
        std::size_t                    schema_offset = error_offset_;
        tlv_result_t                   schema_result = tlv_schema_validate_all_diag(
            data(), size(), format_, predicate_, &tlv_emv_structure_schema, options_.max_depth,
            options_.max_elements, TLV_SCHEMA_UNKNOWN_BY_SCHEMA, &report, &schema_offset);
        // tlv_schema_validate_all_diag() only reports the generic
        // TLV_ERR_SCHEMA itself and leaves *error_offset alone for a
        // violation (multiple can exist); the specific code and offset
        // tlv_schema_validate() would have returned live on the first
        // recorded diagnostic instead.
        if (report.count) {
            schema_result = diag.diagnostic.code;
            if (diag.diagnostic.has_offset) schema_offset = diag.diagnostic.offset;
        }
        if (schema_result != TLV_OK) {
            result_ = schema_result;
            error_offset_ = schema_offset;
            stage_ = "schema ";
            if (report.count) {
                schema_diag_ = diag;
                has_schema_diag_ = true;
            }
        }
    }
    if (result_ == TLV_OK && (options_.emv_check & emv_check_dictionary)) {
        check_.presentation.data = data();
        check_.presentation.ends[0] = size();
        check_.presentation.contexts[0] = options_.emv_context;
        const walk_env env = {&options_, format_, predicate_, is_der_};
        result_ = walk_slice(env, data(), size(), 0, options_.max_elements,
                             check_dictionary_trampoline, this, &error_offset_);
        if (result_ == TLV_OK && check_.result != TLV_OK) {
            result_ = check_.result;
            error_offset_ = check_.offset;
            stage_ = "dictionary ";
        }
    }
#endif
}

std::string validate_command::render_failure_diagnostic(diagnostic_format  diag_format,
                                                        const char*        tag_hex_ptr,
                                                        const std::string& stage_name) {
#if OPENTLV_PROFILE_EMV
    if (stage_name == "dictionary" && check_.result == result_) {
        tlv::diagnostic diag = tlv::make_diagnostic(result_, TLV_DIAGNOSTIC_SEVERITY_ERROR);
        tlv_diagnostic_set_offset(&diag, error_offset_);
        if (check_.scope.path.length) tlv_diagnostic_set_path(&diag, &check_.scope.path);
        if (!check_.expected.empty()) diag.expected = check_.expected.c_str();
        if (!check_.actual.empty()) diag.actual = check_.actual.c_str();
        if (check_.field_name)
            tlv_diagnostic_add_context(&diag, &check_.field_context, "dictionary", "field",
                                       check_.field_name);
        return format_diagnostic(diag, diag_format, "dictionary", tag_hex_ptr);
    }
#endif
    return walk_command::render_failure_diagnostic(diag_format, tag_hex_ptr, stage_name);
}

#if OPENTLV_PROFILE_EMV
tlv_visit_result_t validate_command::check_dictionary_trampoline(const tlv_view_t* view,
                                                                 std::size_t       depth,
                                                                 std::size_t       offset,
                                                                 void*             context) {
    return static_cast<validate_command*>(context)->check_dictionary_element(view, depth, offset);
}

tlv_visit_result_t validate_command::check_dictionary_element(const tlv_view_t* view,
                                                              std::size_t       depth,
                                                              std::size_t       offset) {
    diagnostic_scope_visit(check_.scope, check_.data, view, depth, check_.predicate);
    cli_presentation_visit(&check_.presentation, view, depth, 0);
    const tlv_emv_definition_t* definition =
        tlv_emv_find((tlv_emv_context_t)check_.presentation.contexts[depth], &view->tag);
    // A tag without a dictionary entry in its context is preserved unchecked.
    if (!definition) return TLV_VISIT_CONTINUE;
    const size_t       value_length = (size_t)view->value.length;
    const tlv_result_t rc = tlv_emv_validate_length(definition, value_length);
    if (rc == TLV_OK) return TLV_VISIT_CONTINUE;
    check_.result = rc;
    check_.offset = offset;
    std::ostringstream expected;
    expected << definition->schema->min_length << ".." << definition->schema->max_length;
    if (definition->length_step > 1) expected << " (step " << definition->length_step << ")";
    check_.expected = expected.str();
    check_.actual = std::to_string(value_length);
    check_.field_name = definition->name; // borrowed from the immutable dictionary tables
    return TLV_VISIT_STOP;
}
#else
tlv_visit_result_t validate_command::check_dictionary_trampoline(const tlv_view_t*, std::size_t,
                                                                 std::size_t, void*) {
    return TLV_VISIT_CONTINUE;
}

tlv_visit_result_t validate_command::check_dictionary_element(const tlv_view_t*, std::size_t,
                                                              std::size_t) {
    return TLV_VISIT_CONTINUE;
}
#endif

} // namespace cli
