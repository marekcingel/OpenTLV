/*
 * Simple example of using the tlv++ layer: writes two TLV items through
 * tlv::writer and reads them back through tlv::reader.
 */
#include <array>
#include <cstddef>
#include <iostream>
#include <string_view>

#include "tlv++/tlv.hpp"

int main() {
    std::array<std::byte, 64> buf{};
    tlv::writer w(buf.data(), buf.size());

    auto to_bytes = [](std::string_view s) {
        return tlv::bytes(reinterpret_cast<const std::byte*>(s.data()), s.size());
    };

    if (auto r = w.write(0x01, to_bytes("hello")); !r) {
        std::cerr << "write error: " << r.error().message << "\n";
        return 1;
    }
    if (auto r = w.write(0x02, to_bytes("world")); !r) {
        std::cerr << "write error: " << r.error().message << "\n";
        return 1;
    }

    std::cout << "Wrote " << w.size() << " bytes\n";

    tlv::reader reader(std::span(buf.data(), w.size()));
    while (!reader.at_end()) {
        auto entry = reader.next();
        if (!entry) {
            std::cerr << "read error: " << entry.error().message << "\n";
            return 1;
        }
        std::string_view value(
            reinterpret_cast<const char*>(entry->value.data()),
            entry->value.size());
        std::cout << "tag=0x" << std::hex << static_cast<int>(entry->tag)
                  << std::dec << " value=" << value << "\n";
    }

    return 0;
}
