#include "tlv/builtins/asn1/ber.h"
/*
 * Simple example of using the tlv++ layer: writes two TLV items through
 * tlv::writer and reads them back through tlv::reader.
 */
#include <array>
#include <cstddef>
#include <iostream>
#include <string>

#include "tlv++/tlv.hpp"

int main() {
    std::array<tlv::byte, 64> buf{};
    tlv::writer               w(buf.data(), buf.size(), tlv_format_ber);

    auto to_bytes = [](const std::string& s) {
        return tlv::bytes(reinterpret_cast<const tlv::byte*>(s.data()), s.size());
    };

    tlv::expected<void, tlv::error> r = w.write(tlv::tag_bytes<0x01>(), to_bytes("hello"));
    if (!r) {
        std::cerr << "write error: " << r.error().message << "\n";
        return 1;
    }
    r = w.write(tlv::tag_bytes<0x02>(), to_bytes("world"));
    if (!r) {
        std::cerr << "write error: " << r.error().message << "\n";
        return 1;
    }

    std::cout << "Wrote " << w.size() << " bytes\n";

    tlv::reader reader(tlv::bytes(buf.data(), w.size()), tlv_format_ber);
    while (!reader.at_end()) {
        auto element = reader.next();
        if (!element) {
            std::cerr << "read error: " << element.error().message << "\n";
            return 1;
        }
        auto        value_bytes = element->value().as_bytes();
        std::string value(reinterpret_cast<const char*>(value_bytes.data()), value_bytes.size());

        std::cout << "tag=0x" << std::hex << static_cast<int>(element->tag().data()[0]) << std::dec
                  << " value=" << value << "\n";
    }

    return 0;
}
