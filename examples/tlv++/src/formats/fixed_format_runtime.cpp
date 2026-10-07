// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

// Runtime configuration owns its state; cursors borrow the stable owner.
#include <array>
#include <iostream>

#include "tlv++/tlv.hpp"

int main() {
    const tlv::runtime_fixed_format format(2, 1);
    const auto                      selected = format.view();
    if (!selected) return 1;
    const auto format_view = *selected;

    std::array<tlv::byte, 16> buf{};
    tlv::writer<>             writer(buf.data(), buf.size(), format_view);

    const std::array<tlv::byte, 3> value = {tlv::byte(0xAA), tlv::byte(0xBB), tlv::byte(0xCC)};
    auto                           written =
        writer.write(tlv::tag_bytes<0x12, 0x34>(), tlv::bytes(value.data(), value.size()));
    if (!written) {
        std::cerr << "write error: " << written.error().message() << "\n";
        return 1;
    }

    // Wire bytes: 12 34 03 AA BB CC. The tag is kept as is; the length is one byte.
    size_t count = 0;
    try {
        for (auto element : tlv::parse(tlv::bytes(buf.data(), writer.size()), format_view)) {
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
