// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

// Builds the same BER document as parse.cpp using scoped, allocation-free writes.
#include "tlv++/builtins/asn1/ber.hpp"
#include <array>
#include <algorithm>
#include <iostream>

// Same bytes as parse.cpp's document.
static const std::array<tlv::byte, 12> expected = {
    tlv::byte(0x6F), tlv::byte(0x0A), tlv::byte(0x84), tlv::byte(0x03),
    tlv::byte(0x41), tlv::byte(0x42), tlv::byte(0x43), tlv::byte(0xA5),
    tlv::byte(0x03), tlv::byte(0x50), tlv::byte(0x01), tlv::byte(0x01)};

int main() {
    std::array<tlv::byte, 12> output{};
    auto result = tlv::ber::encode<12, 2>(output, [](tlv::writer_builder& writer) {
        writer.constructed<0x6F>([](tlv::writer_builder& fci) {
            fci.write<0x84>("ABC");
            fci.constructed<0xA5>([](tlv::writer_builder& proprietary) {
                const uint8_t label[] = {0x01};
                proprietary.write<0x50>(label);
            });
        });
    });
    if (!result) {
        std::cerr << "write error: " << result.error().message() << "\n";
        return 1;
    }

    std::cout << "Wrote " << *result << " bytes\n";
    return *result == expected.size() && std::equal(output.begin(), output.end(), expected.begin())
               ? 0
               : 1;
}
