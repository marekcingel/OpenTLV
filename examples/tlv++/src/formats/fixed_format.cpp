// Defines a fixed-width TLV format at compile time: two tag bytes and a
// two-byte little-endian length, then writes and reads one element.
#include <array>
#include <cstddef>
#include <iostream>

#include "tlv++/formats/fixed_format.hpp"
#include "tlv++/tlv.hpp"

using format = tlv::fixed_format<2, 2, TLV_BYTE_ORDER_LITTLE_ENDIAN>;

int main() {
    std::array<tlv::byte, 16> buf{};
    tlv::writer<format>       writer(buf.data(), buf.size());

    const std::array<tlv::byte, 3> value = {tlv::byte(0xAA), tlv::byte(0xBB), tlv::byte(0xCC)};
    auto                           written = writer.write<0x12, 0x34>(value);
    if (!written) {
        std::cerr << "write error: " << written.error().message << "\n";
        return 1;
    }

    // Wire bytes: 12 34 03 00 AA BB CC. The tag is kept as is; only the length is little-endian.
    tlv::reader<format> reader(tlv::bytes(buf.data(), writer.size()));
    size_t              count = 0;
    try {
        for (auto element : reader) {
            if (element.value().size() != value.size()) return 1;
            std::cout << "wrote " << writer.size() << " bytes, read a " << element.value().size()
                      << "-byte value\n";
            ++count;
        }
    } catch (const tlv::parse_error& failure) {
        std::cerr << "read error: " << failure.what() << "\n";
        return 1;
    }
    return count == 1 ? 0 : 1;
}
