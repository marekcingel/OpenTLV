#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector>
#include "commands.hpp"
#include "encode.hpp"
#include "diagnostics.hpp"
#include "input.hpp"
#include "options.hpp"
#include "tlv/version.h"

using cli::fail;

static int run(int argc, char** argv) {
    if (argc == 2 && !strcmp(argv[1], "--help")) {
        cli::options::usage();
        return cli::flush_stdout();
    }
    if (argc == 2 && !strcmp(argv[1], "--version")) {
        std::cout << "otlv " << tlv_version_string() << "\n";
        return cli::flush_stdout();
    }
    if (argc == 2 && !strcmp(argv[1], "formats")) {
        cli::commands::formats();
        return cli::flush_stdout();
    }
    if (argc < 2) return fail(2, "missing command; use --help");

    cli::options o;
    int          rc = o.parse(argc, argv);
    if (rc) return rc;

    if (!strcmp(o.command, "encode")) return cli::commands::encode(o);

    std::vector<uint8_t> data;
    rc = cli::read_input(o, data);
    if (rc) return rc;
    return cli::commands::execute(o, data.data(), data.size());
}

int main(int argc, char** argv) {
    try {
        return run(argc, argv);
    } catch (const std::bad_alloc&) {
        return fail(3, "cannot allocate CLI memory");
    }
}
