#ifndef OPENTLV_CLI_ENCODE_HPP
#define OPENTLV_CLI_ENCODE_HPP
#include <cstdint>
#include <vector>
#include "options.hpp"

namespace cli {
namespace commands {

// One TLV element to write: raw tag bytes in wire order and raw value bytes.
// This is the command's input model. --tag/--value build a single-element
// list today; a structured (JSON) source can fill the same list, with nested
// elements flattened into their parent's value bytes, without changing the
// encoding or output stages.
struct element_spec {
    std::vector<uint8_t> tag;
    std::vector<uint8_t> value;
};

// Runs the parsed "encode" command: builds element specs from the options,
// validates and writes them with the selected format's OpenTLV writer, and
// prints the result as uppercase hex plus newline or as raw bytes. Returns
// the process exit code.
int encode(const options& o);

} // namespace commands
} // namespace cli
#endif
