#ifndef OPENTLV_CLI_COMMANDS_VALIDATE_COMMAND_HPP
#define OPENTLV_CLI_COMMANDS_VALIDATE_COMMAND_HPP
#include "commands/walk_command.hpp"

namespace cli {

// otlv validate: walks the whole input, checking structure only (no display),
// plus the EMV structure/dictionary checks under --profile emv. Also used
// internally by "encode" to validate its own freshly encoded output under
// the same limits as a standalone "otlv validate" run.
class validate_command : public walk_command {
public:
    using walk_command::walk_command;

protected:
    void        run_emv_checks() override;
    std::string render_failure_diagnostic(diagnostic_format diag_format, const char* tag_hex_ptr,
                                          const std::string& stage_name) override;

private:
    // State for the EMV dictionary length check: the first element whose
    // length the dictionary, in that element's context, does not permit,
    // plus enough detail -- independent of `presentation`, which exists only
    // for display bookkeeping -- to report it richly.
    struct dictionary_check {
        cli_presentation_t       presentation = {};
        const uint8_t*           data = nullptr;
        tlv_is_constructed_fn    predicate = nullptr;
        diagnostic_scope         scope = {};
        tlv_result_t             result = TLV_OK;
        std::size_t              offset = 0;
        std::string              expected;
        std::string              actual;
        const char*              field_name = nullptr;
        tlv_diagnostic_context_t field_context = {};
    };
    static tlv_visit_result_t check_dictionary_trampoline(const tlv_view_t* view, std::size_t depth,
                                                          std::size_t offset, void* context);
    tlv_visit_result_t        check_dictionary_element(const tlv_view_t* view, std::size_t depth,
                                                       std::size_t offset);

    dictionary_check check_;
};

} // namespace cli
#endif
