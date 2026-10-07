// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include <tlv++/generator.hpp>
#include <tlv++/formats/fixed_format.hpp>
#include <iostream>

int main() {
    const tlv::byte identifier[] = {static_cast<tlv::byte>(1)};
    const auto      candidate =
        tlv::make_generator_candidate(tlv::tag(tlv::bytes{identifier, 1}), 0, 128);
    tlv::generator_options options{};
    options.seed = 42;
    options.max_elements = 10;
    options.max_depth = 0;
    options.max_value_size = 128;
    options.max_case_size = 512;
    options.candidates = &candidate;
    options.candidate_count = 1;
    tlv::generator generator(tlv::fixed_format<1, 2, tlv::byte_order::big_endian>{}, options);
    for (uint64_t index = 0; index < 3; ++index) {
        auto wire = generator.generate(index);
        if (!wire) {
            std::cerr << wire.error().message() << '\n';
            return 1;
        }
        std::cout << "Case " << index << ": " << wire->size() << " bytes\n";
    }
    return 0;
}
