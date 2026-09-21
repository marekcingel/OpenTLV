#ifndef OPENTLV_CLI_ENCODE_HPP
#define OPENTLV_CLI_ENCODE_HPP
#include <cstdint>
#include <vector>
#include "options.hpp"

namespace cli {
namespace commands {

// One TLV element to write: raw tag bytes in wire order and raw value bytes.
// --tag/--value build a single-element list of these; a JSON document
// (--input) is encoded recursively, with children written into their parent's
// value bytes, and does not use this type.
struct element_spec {
    std::vector<uint8_t> tag;
    std::vector<uint8_t> value;
};

// Runs the parsed "encode" command: builds the elements from --tag/--value or
// a JSON document (--input), writes them with the selected format's OpenTLV
// writer, validates the result, and prints it as uppercase hex plus newline or
// as raw bytes (to stdout or --output-file). Returns the process exit code.
int encode(const options& o);

} // namespace commands
} // namespace cli
#endif
