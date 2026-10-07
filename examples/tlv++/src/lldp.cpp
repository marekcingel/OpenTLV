// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv++/tlv.hpp"
#include "tlv++/builtins/lldp/lldp.hpp"

int main() {
    const uint8_t    wire[] = {2, 2, 7, 'c', 4, 2, 7, 'p', 6, 2, 0, 120, 0, 0};
    const tlv::bytes input(reinterpret_cast<const tlv::byte*>(wire), sizeof wire);
    if (!tlv::lldp::validate(input, 16)) return 1;
    size_t count = 0;
    try {
        for (auto element :
             tlv::lldp::parse(tlv::bytes(reinterpret_cast<const tlv::byte*>(wire), sizeof(wire)))) {
            if (element.tag() == tlv::tag_bytes<3>()) {
                auto seconds = element.decode<tlv::lldp::ttl_field>();
                if (!seconds || *seconds != 120) return 1;
            }
            ++count;
        }
    } catch (const tlv::parse_error&) {
        return 1;
    }
    return count == 4 ? 0 : 1;
}
