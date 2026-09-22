#include "options.hpp"
#include "diagnostics.hpp"
#include <cstdint>
#include <cstring>
#include <iostream>
#include "tlv/config.h"
#include "tlv/reader/walker.h"
#if OPENTLV_PROFILE_EMV
#include "tlv/profiles/emv.h"
#endif

namespace {

// Option bits, matched by name in options::parse().
enum : unsigned {
    opt_tree = 1,
    opt_format = 2,
    opt_input = 4,
    opt_hex = 8,
    opt_max_input = 16,
    opt_max_depth = 32,
    opt_max_elements = 64,
    opt_pretty = 128,
    opt_describe = 256,
    opt_force_color = 512,
    opt_no_color = 1024,
    opt_profile = 2048,
    opt_input_encoding = 4096,
    opt_pdol = 8192,
    opt_decode = 16384,
    opt_output = 32768,
    opt_tag = 65536,
    opt_value = 131072,
    opt_output_encoding = 262144,
    opt_search = 524288,
    opt_recover = 1048576,
    opt_emv_context = 2097152,
    opt_emv_check = 4194304,
    opt_output_file = 8388608,
    opt_diagnostics = 16777216,
    // Options only encode takes.
    encode_only = opt_tag | opt_value | opt_output_encoding | opt_output_file
};

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

#if OPENTLV_PROFILE_EMV
struct context_name {
    const char* name;
    int         context;
};

// Command-line names of the EMV dictionary contexts (tlv_emv_context_t).
const context_name context_names[] = {
    {"base", TLV_EMV_CONTEXT_BASE},
    {"bit", TLV_EMV_CONTEXT_BIT},
    {"bht", TLV_EMV_CONTEXT_BHT},
    {"bht-format", TLV_EMV_CONTEXT_BHT_FORMAT},
    {"bit-group", TLV_EMV_CONTEXT_BIT_GROUP},
    {"biometric-counters", TLV_EMV_CONTEXT_BIOMETRIC_COUNTERS},
    {"biometric-attempts", TLV_EMV_CONTEXT_BIOMETRIC_ATTEMPTS},
    {"biometric-verification", TLV_EMV_CONTEXT_BIOMETRIC_VERIFICATION},
};

int context_by_name(const char* text, int* out) {
    for (const context_name& entry : context_names) {
        if (!strcmp(text, entry.name)) {
            *out = entry.context;
            return 1;
        }
    }
    return 0;
}
#endif

unsigned option_bit(const char* arg) {
    static const struct {
        const char* name;
        unsigned    bit;
    } table[] = {
        {"--tree", opt_tree},
        {"--format", opt_format},
        {"--input", opt_input},
        {"--hex", opt_hex},
        {"--max-input-size", opt_max_input},
        {"--max-depth", opt_max_depth},
        {"--max-elements", opt_max_elements},
        {"--pretty", opt_pretty},
        {"--describe", opt_describe},
        {"--force-color", opt_force_color},
        {"--no-color", opt_no_color},
        {"--profile", opt_profile},
        {"--input-encoding", opt_input_encoding},
        {"--pdol", opt_pdol},
        {"--decode", opt_decode},
        {"--output", opt_output},
        {"--tag", opt_tag},
        {"--value", opt_value},
        {"--output-encoding", opt_output_encoding},
        {"--search", opt_search},
        {"--recover", opt_recover},
        {"--emv-context", opt_emv_context},
        {"--emv-check", opt_emv_check},
        {"--output-file", opt_output_file},
        {"--diagnostics", opt_diagnostics},
    };
    for (const auto& entry : table)
        if (!strcmp(arg, entry.name)) return entry.bit;
    return 0;
}

} // namespace

namespace cli {

int options::parse(int argc, char** argv) {
    unsigned seen = 0;
    int      i;
    command = argv[1];
    const bool encoding = argc > 1 && !strcmp(command, "encode");
    const bool lookup = argc > 1 && !strcmp(command, "tag");
    const bool listing = argc > 1 && !strcmp(command, "tags");
    const bool decoding = argc > 1 && !strcmp(command, "decode");
    const bool validating = argc > 1 && !strcmp(command, "validate");
    const bool querying = argc > 1 && !strcmp(command, "query");
    if (strcmp(command, "dump") && !validating && !decoding && !encoding && !lookup && !listing &&
        !querying)
        return fail(2, "unknown command; use --help");
    i = 2;
    if (querying) {
        // query takes the path as a positional argument: otlv query 6F/A5/50 --format ber ...
        if (argc < 3 || !strncmp(argv[2], "--", 2)) return fail(2, "query requires a path");
        path = argv[2];
        i = 3;
    }
    if (lookup) {
        // tag takes the tag bytes as a positional argument: otlv tag 9F02 --profile emv
        if (argc < 3 || !strncmp(argv[2], "--", 2)) return fail(2, "tag requires a hex tag");
        tag = argv[2];
        i = 3;
    }
    for (; i < argc; ++i) {
        const unsigned bit = option_bit(argv[i]);
        if (!bit) return fail(2, "unknown option; use --help");
        // Each command accepts only its own options. dump and validate share
        // the input, limit and presentation options; decode takes the subset
        // that makes sense for a JSON export.
        const unsigned decode_options = opt_format | opt_input | opt_hex | opt_max_input |
                                        opt_max_depth | opt_max_elements | opt_describe |
                                        opt_profile | opt_input_encoding | opt_decode |
                                        opt_recover | opt_emv_context | opt_diagnostics;
        const unsigned encode_options =
            opt_format | opt_input | opt_max_input | opt_max_depth | opt_max_elements | encode_only;
        const unsigned query_options = opt_format | opt_input | opt_hex | opt_max_input |
                                       opt_max_depth | opt_max_elements | opt_input_encoding |
                                       opt_output | opt_value | opt_diagnostics;
        if (lookup       ? !(bit & (opt_profile | opt_output))
            : listing    ? !(bit & (opt_profile | opt_output | opt_search))
            : querying   ? !(bit & query_options)
            : encoding   ? !(bit & encode_options)
            : decoding   ? !(bit & decode_options)
            : validating ? (bit & (encode_only | opt_search | opt_recover))
                         : (bit & (encode_only | opt_search | opt_emv_check)))
            return fail(2, lookup                ? "option is not valid for tag"
                           : listing             ? "option is not valid for tags"
                           : querying            ? "option is not valid for query"
                           : encoding            ? "option is not valid for encode"
                           : decoding            ? "option is not valid for decode"
                           : (bit & encode_only) ? "option requires encode"
                           : (bit & opt_search)  ? "option requires tags"
                           : (bit & opt_recover) ? "--recover requires dump or decode"
                                                 : "--emv-check requires validate");
        if (seen & bit) return fail(2, "duplicate option");
        seen |= bit;
        if (bit == opt_tree) {
            tree = 1;
            continue;
        }
        if (bit == opt_pdol) {
            pdol = 1;
            continue;
        }
        if (bit == opt_decode) {
            decode = 1;
            continue;
        }
        if (bit == opt_pretty) {
            pretty = tree = 1;
            continue;
        }
        if (bit == opt_describe) {
            describe = 1;
            continue;
        }
        if (bit == opt_force_color || bit == opt_no_color) {
            color = bit == opt_force_color ? 1 : -1;
            continue;
        }
        if (bit == opt_recover) {
            recover = 1;
            continue;
        }
        if (bit == opt_value && querying) {
            value_only = 1;
            continue;
        }
        if (++i == argc) return fail(2, "missing option value");
        if (bit == opt_format)
            format = argv[i];
        else if (bit == opt_input)
            input = argv[i];
        else if (bit == opt_hex)
            hex = argv[i];
        else if (bit == opt_profile)
            profile = argv[i];
        else if (bit == opt_tag)
            tag = argv[i];
        else if (bit == opt_search)
            search = argv[i];
        else if (bit == opt_value)
            value = argv[i];
        else if (bit == opt_output_file)
            output_file = argv[i];
        else if (bit == opt_emv_context) {
#if OPENTLV_PROFILE_EMV
            if (!context_by_name(argv[i], &emv_context))
                return fail(2, "unknown EMV context; use base, bit, bht, bht-format, bit-group, "
                               "biometric-counters, biometric-attempts or biometric-verification");
#else
            return fail(2, "EMV profile is disabled in this build");
#endif
        } else if (bit == opt_emv_check) {
            if (!strcmp(argv[i], "structure"))
                emv_check = emv_check_structure;
            else if (!strcmp(argv[i], "dictionary"))
                emv_check = emv_check_dictionary;
            else if (!strcmp(argv[i], "all"))
                emv_check = emv_check_structure | emv_check_dictionary;
            else
                return fail(2, "EMV check must be structure, dictionary or all");
        } else if (bit == opt_output_encoding) {
            if (strcmp(argv[i], "binary") && strcmp(argv[i], "hex"))
                return fail(2, "output encoding must be binary or hex");
            binary_output = !strcmp(argv[i], "binary");
        } else if (bit == opt_input_encoding) {
            if (strcmp(argv[i], "binary") && strcmp(argv[i], "hex"))
                return fail(2, "input encoding must be binary or hex");
            hex_input = !strcmp(argv[i], "hex");
        } else if (bit == opt_output) {
            if (strcmp(argv[i], "text") && strcmp(argv[i], "json"))
                return fail(2, "output must be text or json");
            output = argv[i];
        } else if (bit == opt_diagnostics) {
            if (strcmp(argv[i], "human") && strcmp(argv[i], "compact") && strcmp(argv[i], "json"))
                return fail(2, "diagnostics must be human, compact or json");
            diagnostics = argv[i];
        } else if (!number(argv[i], bit == opt_max_input   ? &max_input
                                    : bit == opt_max_depth ? &max_depth
                                                           : &max_elements))
            return fail(2, "limits must be nonnegative decimal integers fitting size_t");
    }
    if (lookup || listing) {
        if (!profile)
            return fail(2, listing ? "tags requires --profile emv" : "tag requires --profile emv");
        if (strcmp(profile, "emv")) return fail(2, "unknown profile");
#if !OPENTLV_PROFILE_EMV
        return fail(2, "EMV profile is disabled in this build");
#endif
        return 0;
    }
    if (encoding) {
        if (!format || (!tag && !input))
            return fail(2, "encode requires --format and --tag or --input");
        if (tag && input) return fail(2, "encode takes --tag/--value or --input, not both");
        if (value && !tag) return fail(2, "--value requires --tag");
        if (max_depth > TLV_WALK_MAX_DEPTH) return fail(2, "maximum depth must be in 0..64");
        return 0;
    }
    if (!format || (!!input + !!hex) != 1)
        return fail(2, "specify --format and exactly one of --input or --hex");
    if (max_depth > TLV_WALK_MAX_DEPTH) return fail(2, "maximum depth must be in 0..64");
    if (querying) {
        const tlv_result_t rc = tlv_query_parse(path, &query, nullptr);
        if (rc == TLV_ERR_INVALID_ARG)
            return fail(2, "invalid query path; use hexadecimal tags separated by /");
        if (rc == TLV_ERR_INVALID_TAG_SIZE) return fail(2, "query tag is too long");
        if (rc != TLV_OK) return fail(2, "query path has too many tags");
        if (query.count > 1 && strcmp(format, "ber") && strcmp(format, "der"))
            return fail(2, "a query with nested tags requires --format ber or der");
        if (value_only && strcmp(output, "text"))
            return fail(2, "--value cannot be combined with --output json");
        return 0;
    }
    if (tree && strcmp(command, "dump")) return fail(2, "--tree requires dump");
    if (pdol && (strcmp(format, "ber") || tree || decode))
        return fail(2, "--pdol requires --format ber and cannot use --tree, --pretty, or --decode");
    if ((seen & opt_force_color) && (seen & opt_no_color))
        return fail(2, "conflicting color options");
    if ((seen & opt_input_encoding) && !input) return fail(2, "--input-encoding requires --input");
    if ((describe || color || decode || strcmp(output, "text")) && validating)
        return fail(2, "presentation options require dump or decode");
    if (recover && pdol) return fail(2, "--recover cannot be combined with --pdol");
    if (describe && !profile) return fail(2, "--describe requires --profile emv");
    if (decode && !profile) return fail(2, "--decode requires --profile emv");
    if ((seen & opt_emv_context) && !profile)
        return fail(2, "--emv-context requires --profile emv");
    if ((seen & opt_emv_check) && !profile) return fail(2, "--emv-check requires --profile emv");
    if (profile) {
        if (strcmp(profile, "emv")) return fail(2, "unknown profile");
        if (strcmp(format, "ber")) return fail(2, "EMV profile requires --format ber");
#if !OPENTLV_PROFILE_EMV
        return fail(2, "EMV profile is disabled in this build");
#endif
        if (pdol && (seen & (opt_emv_context | opt_emv_check)))
            return fail(2, "--pdol cannot use --emv-context or --emv-check");
        if (validating && !emv_check) emv_check = emv_check_structure;
        if (validating && (emv_check & emv_check_structure) && emv_context)
            return fail(2, "the structure check requires the base EMV context; use --emv-check "
                           "dictionary with --emv-context");
    }
    return 0;
}

void options::usage() {
    std::cout
        << "Usage: otlv dump|validate|decode --format NAME (--input PATH|- | --hex BYTES) "
           "[OPTIONS]\n"
           "       otlv encode --format NAME --tag HEX [--value HEX] "
           "[--output-encoding hex|binary]\n"
           "       otlv encode --format NAME --input JSON_PATH|- "
           "[--output-encoding hex|binary] [--output-file PATH]\n"
           "       otlv query PATH --format NAME (--input PATH|- | --hex BYTES) [--value] "
           "[--output text|json]\n"
           "       otlv tag HEX --profile emv [--output text|json]\n"
           "       otlv tags --profile emv [--search TEXT] [--output text|json]\n"
           "       otlv formats | --help | --version\n"
           "Formats: default, fixed-1byte, ber, der, bluetooth-ltv (when enabled in this build)\n"
           "Options:\n"
           "  --pdol                 Read raw DOL tag/one-byte-length pairs (BER)\n"
           "  --tree                 Print nested BER/DER elements (dump only)\n"
           "  --pretty               Print a graphical UTF-8 tree (implies --tree)\n"
           "  --profile emv          Annotate BER tags (dump, decode) or check EMV data "
           "(validate)\n"
           "  --describe             Include EMV type and length descriptions\n"
           "  --decode               Decode known EMV values (requires --profile emv)\n"
           "  --emv-context NAME     EMV dictionary context of the top-level elements: base "
           "(default), bit, bht, bht-format, bit-group, biometric-counters, "
           "biometric-attempts, biometric-verification\n"
           "  --emv-check NAME       validate: structure (default), dictionary or all\n"
           "  --recover              dump, decode: skip damaged bytes and keep reading; the "
           "output is marked incomplete and the exit code is 4\n"
           "  --output text|json     Print text (default) or a hierarchical JSON document\n"
           "  --diagnostics NAME     Shape of a failure diagnostic: human (default), compact "
           "or json\n"
           "  --input-encoding NAME  binary (default) or hex, for --input\n"
           "  --force-color          Emit ANSI colors even when redirected\n"
           "  --no-color             Disable colors (default: auto for terminals)\n"
           "  --max-input-size N     Maximum input bytes (default 16777216)\n"
           "  --max-depth N          Maximum child depth, 0..64 (default 64)\n"
           "  --max-elements N       Maximum visited elements (default 100000)\n"
           "  --search TEXT          tags: only tags whose name contains TEXT "
           "(case-insensitive)\n"
           "  --value                query: print only the values of the addressed elements\n"
           "  --tag HEX              encode: tag bytes in wire order\n"
           "  --value HEX            encode: value bytes (default: empty)\n"
           "  --output-encoding NAME encode: hex (default, one line) or binary\n"
           "  --output-file PATH     encode: write the result to PATH instead of stdout\n"
           "decode prints the versioned JSON document that encode --input reads.\n"
           "query prints every element addressed by a path of hexadecimal tags such as "
           "6F/A5/50 (a top-level 6F, its child A5, its child 50); nested paths need "
           "--format ber or der. Exit code 5 means nothing matched.\n"
           "tag looks up one BER tag in the EMV dictionary; an unknown tag is a result "
           "(exit 0), not an error; tags lists the dictionary.\n"
           "Input is binary; hex accepts contiguous bytes or whitespace between pairs.\n"
           "Validation accepts empty input and checks all concatenated elements.\n"
           "With --profile emv, validate also checks the EMV schema structure "
           "(mandatory/forbidden/duplicate tags, lengths, and nesting) and reports a "
           "schema-labeled diagnostic distinct from format errors; --pdol skips it.\n"
           "Exit codes: 0 success, 1 invalid TLV (or element rejected by encode), 2 invalid "
           "usage/hex/JSON/format, 3 I/O/resource error, 4 damaged data skipped by --recover.\n";
}

} // namespace cli
