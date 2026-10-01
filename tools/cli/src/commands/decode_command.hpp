#ifndef OPENTLV_CLI_COMMANDS_DECODE_COMMAND_HPP
#define OPENTLV_CLI_COMMANDS_DECODE_COMMAND_HPP
#include "commands/traversal_command.hpp"

namespace cli {

// otlv decode: prints the versioned JSON document (docs/cli/json-schema.md)
// that "encode --input" reads, on success only.
class decode_command : public traversal_command {
public:
    using traversal_command::traversal_command;

protected:
    tlv_visit_result_t visit_element(const tlv::element_view& element, std::size_t depth,
                                     std::size_t offset) override;
    void               render_output() override;
};

} // namespace cli
#endif
