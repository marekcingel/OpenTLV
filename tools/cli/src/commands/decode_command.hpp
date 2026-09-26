#ifndef OPENTLV_CLI_COMMANDS_DECODE_COMMAND_HPP
#define OPENTLV_CLI_COMMANDS_DECODE_COMMAND_HPP
#include "commands/walk_command.hpp"

namespace cli {

// otlv decode: prints the versioned JSON document (docs/cli/json-schema.md)
// that "encode --input" reads, on success only.
class decode_command : public walk_command {
public:
    using walk_command::walk_command;

protected:
    tlv_visit_result_t visit_element(const tlv_view_t* view, std::size_t depth,
                                     std::size_t offset) override;
    void               render_output() override;
};

} // namespace cli
#endif
