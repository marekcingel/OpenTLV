#include "tlv/formats/default/default.h"

#include <array>
#include <cstddef>
#include <iostream>

#include "tlv++/tlv.hpp"

int main() {
    std::array<tlv::byte, 64> buf{};
    tlv::writer w(buf.data(), buf.size(), tlv_writer_format_default);

    const tlv::expected<void, tlv::error> r =
        w.write(tlv::tag_t{{0x01}, 1}, tlv::bytes(reinterpret_cast<const tlv::byte*>("hi"), 2));
    if (!r) {
        std::cerr << "write error: " << r.error().message << "\n";
        return 1;
    }

    tlv::reader reader(tlv::bytes(buf.data(), w.size()), tlv_reader_format_default);
    const auto entry = reader.next();
    if (!entry) {
        std::cerr << "read error: " << entry.error().message << "\n";
        return 1;
    }

    return entry->tag.data[0] == 0x01 ? 0 : 1;
}
