#include "commands/formats_command.hpp"
#include <iostream>
#include "diagnostics.hpp"
#include "tlv/config.h"

namespace cli {

std::vector<std::string> enabled_formats() {
    std::vector<std::string> names;
#if OPENTLV_FORMAT_DEFAULT
    names.push_back("default");
#endif
#if OPENTLV_FORMAT_FIXED
    names.push_back("fixed");
#endif
#if OPENTLV_FORMAT_BER
    names.push_back("ber");
#endif
#if OPENTLV_FORMAT_DER
    names.push_back("der");
#endif
#if OPENTLV_FORMAT_BLUETOOTH_LTV
    names.push_back("bluetooth-ltv");
#endif
    return names;
}

int formats_command::run() {
    for (const std::string& name : enabled_formats()) std::cout << name << "\n";
    return flush_stdout();
}

} // namespace cli
