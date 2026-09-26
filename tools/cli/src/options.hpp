#ifndef OPENTLV_CLI_OPTIONS_HPP
#define OPENTLV_CLI_OPTIONS_HPP
#include <cstddef>
#include "tlv/query/query.h"

namespace cli {

// Parses and validates otlv's command-line arguments.
// Fields are set to their command-line defaults on construction and
// overwritten by parse(); on failure it prints a diagnostic (via cli::fail)
// and returns a nonzero exit code, matching this CLI's exit-code contract.
enum { emv_check_structure = 1, emv_check_dictionary = 2 };

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
    // dump/decode only: resynchronize after damaged data instead of failing.
    int recover = 0;
    // EMV dictionary context (tlv_emv_context_t) the top-level elements start in.
    int emv_context = 0;
    // validate --profile emv only: bit mask of emv_check_* (0 = default).
    int         emv_check = 0;
    const char* output = "text";
    // dump/validate/decode/query only: shape of the diagnostic printed on
    // failure, or of a --recover skipped range.
    const char* diagnostics = "human";
    // encode only: tag/value hex text and whether to emit raw bytes.
    const char* tag = nullptr;
    const char* value = nullptr;
    int         binary_output = 0;
    // encode only: write the encoded bytes to this file instead of stdout.
    const char* output_file = nullptr;
    // tags only: case-insensitive name filter.
    const char* search = nullptr;
    // query only: the path text, its parsed form and whether to print only
    // the values of the addressed elements.
    const char* path = nullptr;
    tlv_query_t query = {};
    int         value_only = 0;
    // --format fixed only: tag width, length width and length byte order.
    std::size_t fixed_tag_size = 1;
    std::size_t fixed_length_size = 1;
    const char* fixed_byte_order = "big";
};

} // namespace cli
#endif
