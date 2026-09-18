#ifndef OPENTLV_CLI_COMMANDS_HPP
#define OPENTLV_CLI_COMMANDS_HPP
#include <cstddef>
#include <cstdint>
#include "options.hpp"

namespace cli {
namespace commands {

// Prints the TLV formats enabled in this build, one per line.
void formats();

// Runs the parsed "dump" or "validate" command against decoded input,
// writing dump output (via cli_presentation_*) to stdout. Both commands walk
// the same TLV tree; validate simply omits the printing visitor. Returns the
// process exit code.
int execute(const options& o, const uint8_t* data, std::size_t size);

} // namespace commands
} // namespace cli
#endif
