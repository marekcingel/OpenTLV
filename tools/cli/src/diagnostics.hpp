#ifndef OPENTLV_CLI_DIAGNOSTICS_HPP
#define OPENTLV_CLI_DIAGNOSTICS_HPP
#include <cstdio>

namespace cli {

// Prints "opentlv: <message>" to stderr and returns code, so call sites can
// return a diagnostic in one expression: `return fail(2, "...");`.
inline int fail(int code, const char* message) {
    std::fprintf(stderr, "opentlv: %s\n", message);
    return code;
}

} // namespace cli
#endif
