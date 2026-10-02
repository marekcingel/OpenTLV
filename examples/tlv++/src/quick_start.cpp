// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include <tlv++/tlv.hpp>
#include <array>
#include <iostream>
#include <string>

using Format = tlv::fixed_format<1, 1, TLV_BYTE_ORDER_BIG_ENDIAN>;
using Greeting = tlv::field<tlv::tag_constant<0x01>, std::string>;

int main() {
    std::array<tlv::byte, 64> output{};
    auto written = tlv::encode<Format>(output, [](tlv::writer_builder& writer) {
        writer.write<0x01>("Hello, world!"); // Character arrays omit the trailing NUL.
    });
    if (!written) {
        std::cerr << written.error().message() << '\n';
        return 1;
    }

    // Parse only the written prefix. Decoding Greeting checks the tag and owns its string.
    try {
        for (auto element : tlv::parse<Format>({output.data(), *written})) {
            auto greeting = element.decode<Greeting>();
            if (!greeting) {
                std::cerr << "Greeting decode failed\n";
                return 1;
            }
            std::cout << *greeting << '\n';
        }
    } catch (const tlv::parse_error& failure) {
        std::cerr << "Parse error at " << failure.offset() << ": " << failure.what() << '\n';
        return 1;
    }
}
