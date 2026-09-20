#ifndef OPENTLV_CLI_OPTIONS_HPP
#define OPENTLV_CLI_OPTIONS_HPP
#include <cstddef>

namespace cli {

// Parses and validates opentlv's "dump"/"validate" command-line arguments.
// Fields are set to their command-line defaults on construction and
// overwritten by parse(); on failure it prints a diagnostic (via cli::fail)
// and returns a nonzero exit code, matching this CLI's exit-code contract.
class options {
public:
    int         parse(int argc, char** argv);
    static void usage();

    const char* command = nullptr;
    const char* format = nullptr;
    const char* input = nullptr;
    const char* hex = nullptr;
    const char* profile = nullptr;
    std::size_t max_input = 16777216;
    std::size_t max_depth = 64;
    std::size_t max_elements = 100000;
    int         tree = 0;
    int         pretty = 0;
    int         describe = 0;
    int         color = 0;
    int         hex_input = 0;
    int         pdol = 0;
    int         decode = 0;
    const char* output = "text";
    // encode only: tag/value hex text and whether to emit raw bytes.
    const char* tag = nullptr;
    const char* value = nullptr;
    int         binary_output = 0;
    // tags only: case-insensitive name filter.
    const char* search = nullptr;
};

} // namespace cli
#endif
