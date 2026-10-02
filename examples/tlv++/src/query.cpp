// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

// Addresses the Application Label directly by path, `6F/A5/50`, without
// traversing the whole document by hand. See parse.cpp for the document itself.
#include <array>
#include <iomanip>
#include <iostream>

#include "tlv++/tlv.hpp"

// Same bytes as parse.cpp's document.
static const std::array<tlv::byte, 12> document = {
    tlv::byte(0x6F), tlv::byte(0x0A), tlv::byte(0x84), tlv::byte(0x03),
    tlv::byte(0x41), tlv::byte(0x42), tlv::byte(0x43), tlv::byte(0xA5),
    tlv::byte(0x03), tlv::byte(0x50), tlv::byte(0x01), tlv::byte(0x01)};

int main() {
    // Streaming Query borrows both input and the caller-owned traversal frames.
    tlv::tree_frame  frames[2]{};
    tlv::tree_reader reader({document.data(), document.size()}, tlv::ber::format{}, {frames, 2}, 2,
                            16);
    size_t           matches = 0;
    try {
        for (const auto& item : reader.select("6F/A5/50")) {
            std::cout << "6F/A5/50 = ";
            for (auto byte : item.element.value())
                std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
                          << static_cast<unsigned>(byte);
            std::cout << std::dec << " (offset " << item.offset << ")\n";
            if (item.element.value().size() != 1 || item.element.value()[0] != tlv::byte(0x01))
                return 2;
            ++matches;
        }
#if OPENTLV_DOCUMENT
        auto owned = tlv::document::parse({document.data(), document.size()},
                                          tlv::document_format(tlv::ber::format{}));
        if (!owned) return 3;
        auto nodes = owned->select("6F/A5/50");
        if (nodes.size() != matches || nodes.size() != 1 || nodes[0].value()[0] != tlv::byte(0x01))
            return 3;
#endif
    } catch (const tlv::query_error& failure) {
        std::cerr << "Query error at " << failure.offset() << ": " << failure.what() << '\n';
        return 1;
    } catch (const tlv::parse_error& failure) {
        std::cerr << "Parse error at " << failure.offset() << ": " << failure.what() << '\n';
        return 1;
    }
    return matches == 1 ? 0 : 2;
}
