#ifndef OPENTLV_CLI_COMMANDS_QUERY_COMMAND_HPP
#define OPENTLV_CLI_COMMANDS_QUERY_COMMAND_HPP
#include "commands/traversal_command.hpp"

namespace cli {

// otlv query PATH: prints every element addressed by a path of hexadecimal
// tags as text or, with --output json, one JSON document; exit code 5 means
// nothing matched.
class query_command : public traversal_command {
public:
    using traversal_command::traversal_command;

protected:
    int                prepare() override;
    tlv_visit_result_t visit_element(const tlv_element_t* element, std::size_t depth,
                                     std::size_t offset) override;
    void               render_output() override;
    int                after_success() override;
};

} // namespace cli
#endif
