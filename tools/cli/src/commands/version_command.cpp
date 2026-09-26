#include "commands/version_command.hpp"
#include <iostream>
#include "diagnostics.hpp"
#include "tlv/version.h"

namespace cli {

int version_command::run() {
    std::cout << "otlv " << tlv_version_string() << "\n";
    return flush_stdout();
}

} // namespace cli
