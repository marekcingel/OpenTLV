#ifndef OPENTLV_CLI_COMMANDS_DUMP_COMMAND_HPP
#define OPENTLV_CLI_COMMANDS_DUMP_COMMAND_HPP
#include "commands/walk_command.hpp"

namespace cli {

// otlv dump: prints every visited element (top-level only, or the whole
// nested BER/DER tree with --tree/--pretty) as text or, with --output json,
// a JSON document.
class dump_command : public walk_command {
public:
    using walk_command::walk_command;

protected:
    tlv_visit_result_t visit_element(const tlv_view_t* view, std::size_t depth,
                                     std::size_t offset) override;
    void               render_output() override;
    bool               prints_pdol_annotations() const override;
    bool               prints_skipped_inline() const override;
};

} // namespace cli
#endif
