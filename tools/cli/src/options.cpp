#include "options.hpp"
#include "diagnostics.hpp"
#include <cstdint>
#include <cstring>
#include <iostream>
#include "tlv/config.h"
#include "tlv/reader/walker.h"

namespace {

int number(const char* text, std::size_t* out) {
    std::size_t n = 0;
    if (!*text) return 0;
    for (; *text; ++text) {
        unsigned digit = (unsigned)(*text - '0');
        if (digit > 9 || n > (SIZE_MAX - digit) / 10) return 0;
        n = n * 10 + digit;
    }
    *out = n;
    return 1;
}

} // namespace

namespace cli {

int options::parse(int argc, char** argv) {
    unsigned seen = 0;
    int      i;
    command = argv[1];
    if (strcmp(command, "dump") && strcmp(command, "validate"))
        return fail(2, "unknown command; use --help");
    for (i = 2; i < argc; ++i) {
        unsigned    bit;
        const char* arg = argv[i];
        if (!strcmp(arg, "--tree"))
            bit = 1;
        else if (!strcmp(arg, "--format"))
            bit = 2;
        else if (!strcmp(arg, "--input"))
            bit = 4;
        else if (!strcmp(arg, "--hex"))
            bit = 8;
        else if (!strcmp(arg, "--max-input-size"))
            bit = 16;
        else if (!strcmp(arg, "--max-depth"))
            bit = 32;
        else if (!strcmp(arg, "--max-elements"))
            bit = 64;
        else if (!strcmp(arg, "--pretty"))
            bit = 128;
        else if (!strcmp(arg, "--describe"))
            bit = 256;
        else if (!strcmp(arg, "--force-color"))
            bit = 512;
        else if (!strcmp(arg, "--no-color"))
            bit = 1024;
        else if (!strcmp(arg, "--profile"))
            bit = 2048;
        else if (!strcmp(arg, "--input-encoding"))
            bit = 4096;
        else if (!strcmp(arg, "--pdol"))
            bit = 8192;
        else
            return fail(2, "unknown option; use --help");
        if (seen & bit) return fail(2, "duplicate option");
        seen |= bit;
        if (bit == 1) {
            tree = 1;
            continue;
        }
        if (bit == 8192) {
            pdol = 1;
            continue;
        }
        if (bit == 128) {
            pretty = tree = 1;
            continue;
        }
        if (bit == 256) {
            describe = 1;
            continue;
        }
        if (bit == 512 || bit == 1024) {
            color = bit == 512 ? 1 : -1;
            continue;
        }
        if (++i == argc) return fail(2, "missing option value");
        if (bit == 2)
            format = argv[i];
        else if (bit == 4)
            input = argv[i];
        else if (bit == 8)
            hex = argv[i];
        else if (bit == 2048)
            profile = argv[i];
        else if (bit == 4096) {
            if (strcmp(argv[i], "binary") && strcmp(argv[i], "hex"))
                return fail(2, "input encoding must be binary or hex");
            hex_input = !strcmp(argv[i], "hex");
        } else if (!number(argv[i], bit == 16   ? &max_input
                                    : bit == 32 ? &max_depth
                                                : &max_elements))
            return fail(2, "limits must be nonnegative decimal integers fitting size_t");
    }
    if (!format || (!!input + !!hex) != 1)
        return fail(2, "specify --format and exactly one of --input or --hex");
    if (max_depth > TLV_WALK_MAX_DEPTH) return fail(2, "maximum depth must be in 0..64");
    if (tree && strcmp(command, "dump")) return fail(2, "--tree requires dump");
    if (pdol && (strcmp(format, "ber") || tree))
        return fail(2, "--pdol requires --format ber and cannot use --tree or --pretty");
    if ((seen & 512) && (seen & 1024)) return fail(2, "conflicting color options");
    if ((seen & 4096) && !input) return fail(2, "--input-encoding requires --input");
    if ((profile || describe || color) && strcmp(command, "dump"))
        return fail(2, "presentation options require dump");
    if (describe && !profile) return fail(2, "--describe requires --profile emv");
    if (profile) {
        if (strcmp(profile, "emv")) return fail(2, "unknown profile");
        if (strcmp(format, "ber")) return fail(2, "EMV annotations require --format ber");
#if !OPENTLV_PROFILE_EMV
        return fail(2, "EMV profile is disabled in this build");
#endif
    }
    return 0;
}

void options::usage() {
    std::cout << "Usage: otlv dump|validate --format NAME (--input PATH|- | --hex BYTES) "
                 "[OPTIONS]\n"
                 "       otlv formats | --help | --version\n"
                 "Formats: default, fixed-1byte, ber, der (when enabled in this build)\n"
                 "Options:\n"
                 "  --pdol                 Read raw DOL tag/one-byte-length pairs (BER)\n"
                 "  --tree                 Print nested BER/DER elements (dump only)\n"
                 "  --pretty               Print a graphical UTF-8 tree (implies --tree)\n"
                 "  --profile emv          Annotate BER tags using the EMV dictionary\n"
                 "  --describe             Include EMV type and length descriptions\n"
                 "  --input-encoding NAME  binary (default) or hex, for --input\n"
                 "  --force-color          Emit ANSI colors even when redirected\n"
                 "  --no-color             Disable colors (default: auto for terminals)\n"
                 "  --max-input-size N     Maximum input bytes (default 16777216)\n"
                 "  --max-depth N          Maximum child depth, 0..64 (default 64)\n"
                 "  --max-elements N       Maximum visited elements (default 100000)\n"
                 "Input is binary; hex accepts contiguous bytes or whitespace between pairs.\n"
                 "Validation accepts empty input and checks all concatenated elements.\n"
                 "Exit codes: 0 success, 1 invalid TLV, 2 invalid usage/hex/format, 3 "
                 "I/O/resource error.\n";
}

} // namespace cli
