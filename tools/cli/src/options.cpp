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
    const unsigned encode_only = 65536 | 131072 | 262144; // --tag, --value, --output-encoding
    const bool     encoding = argc > 1 && !strcmp(command, "encode");
    if (strcmp(command, "dump") && strcmp(command, "validate") && !encoding)
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
        else if (!strcmp(arg, "--decode"))
            bit = 16384;
        else if (!strcmp(arg, "--output"))
            bit = 32768;
        else if (!strcmp(arg, "--tag"))
            bit = 65536;
        else if (!strcmp(arg, "--value"))
            bit = 131072;
        else if (!strcmp(arg, "--output-encoding"))
            bit = 262144;
        else
            return fail(2, "unknown option; use --help");
        // encode takes only --format, --max-input-size and its own options;
        // dump/validate never take the encode-only ones.
        if (encoding ? !(bit & (2 | 16 | encode_only)) : (bit & encode_only))
            return fail(2, encoding ? "option is not valid for encode" : "option requires encode");
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
        if (bit == 16384) {
            decode = 1;
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
        else if (bit == 65536)
            tag = argv[i];
        else if (bit == 131072)
            value = argv[i];
        else if (bit == 262144) {
            if (strcmp(argv[i], "binary") && strcmp(argv[i], "hex"))
                return fail(2, "output encoding must be binary or hex");
            binary_output = !strcmp(argv[i], "binary");
        } else if (bit == 4096) {
            if (strcmp(argv[i], "binary") && strcmp(argv[i], "hex"))
                return fail(2, "input encoding must be binary or hex");
            hex_input = !strcmp(argv[i], "hex");
        } else if (bit == 32768) {
            if (strcmp(argv[i], "text") && strcmp(argv[i], "json"))
                return fail(2, "output must be text or json");
            output = argv[i];
        } else if (!number(argv[i], bit == 16   ? &max_input
                                    : bit == 32 ? &max_depth
                                                : &max_elements))
            return fail(2, "limits must be nonnegative decimal integers fitting size_t");
    }
    if (encoding) {
        if (!format || !tag) return fail(2, "encode requires --format and --tag");
        return 0;
    }
    if (!format || (!!input + !!hex) != 1)
        return fail(2, "specify --format and exactly one of --input or --hex");
    if (max_depth > TLV_WALK_MAX_DEPTH) return fail(2, "maximum depth must be in 0..64");
    if (tree && strcmp(command, "dump")) return fail(2, "--tree requires dump");
    if (pdol && (strcmp(format, "ber") || tree || decode))
        return fail(2, "--pdol requires --format ber and cannot use --tree, --pretty, or --decode");
    if ((seen & 512) && (seen & 1024)) return fail(2, "conflicting color options");
    if ((seen & 4096) && !input) return fail(2, "--input-encoding requires --input");
    if ((describe || color || decode || strcmp(output, "text")) && strcmp(command, "dump"))
        return fail(2, "presentation options require dump");
    if (describe && !profile) return fail(2, "--describe requires --profile emv");
    if (decode && !profile) return fail(2, "--decode requires --profile emv");
    if (profile) {
        if (strcmp(profile, "emv")) return fail(2, "unknown profile");
        if (strcmp(format, "ber")) return fail(2, "EMV profile requires --format ber");
#if !OPENTLV_PROFILE_EMV
        return fail(2, "EMV profile is disabled in this build");
#endif
    }
    return 0;
}

void options::usage() {
    std::cout << "Usage: otlv dump|validate --format NAME (--input PATH|- | --hex BYTES) "
                 "[OPTIONS]\n"
                 "       otlv encode --format NAME --tag HEX [--value HEX] "
                 "[--output-encoding hex|binary]\n"
                 "       otlv formats | --help | --version\n"
                 "Formats: default, fixed-1byte, ber, der (when enabled in this build)\n"
                 "Options:\n"
                 "  --pdol                 Read raw DOL tag/one-byte-length pairs (BER)\n"
                 "  --tree                 Print nested BER/DER elements (dump only)\n"
                 "  --pretty               Print a graphical UTF-8 tree (implies --tree)\n"
                 "  --profile emv          Annotate BER tags (dump) or check EMV schema "
                 "structure (validate)\n"
                 "  --describe             Include EMV type and length descriptions\n"
                 "  --decode               Decode known EMV values (requires --profile emv)\n"
                 "  --output text|json     Print text (default) or a hierarchical JSON document\n"
                 "  --input-encoding NAME  binary (default) or hex, for --input\n"
                 "  --force-color          Emit ANSI colors even when redirected\n"
                 "  --no-color             Disable colors (default: auto for terminals)\n"
                 "  --max-input-size N     Maximum input bytes (default 16777216)\n"
                 "  --max-depth N          Maximum child depth, 0..64 (default 64)\n"
                 "  --max-elements N       Maximum visited elements (default 100000)\n"
                 "  --tag HEX              encode: tag bytes in wire order\n"
                 "  --value HEX            encode: value bytes (default: empty)\n"
                 "  --output-encoding NAME encode: hex (default, one line) or binary\n"
                 "Input is binary; hex accepts contiguous bytes or whitespace between pairs.\n"
                 "Validation accepts empty input and checks all concatenated elements.\n"
                 "With --profile emv, validate also checks the EMV schema structure "
                 "(mandatory/forbidden/duplicate tags, lengths, and nesting) and reports a "
                 "schema-labeled diagnostic distinct from format errors; --pdol skips it.\n"
                 "Exit codes: 0 success, 1 invalid TLV (or element rejected by encode), 2 invalid "
                 "usage/hex/format, 3 "
                 "I/O/resource error.\n";
}

} // namespace cli
