// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

// Explicit allocation-free typed encoding, incremental Reader, and C interoperability.
#include <tlv++/tlv.hpp>
#include <tlv++/native.hpp>
#include <iostream>

using Counter = tlv::field<tlv::tag_constant<0x9F, 0x36>, uint16_t, tlv::uint16_be_codec>;
using Format = tlv::fixed_format<2, 1, tlv::byte_order::big_endian>;

int main() {
    tlv::byte           output[5]{}, scratch[2]{};
    tlv::writer<Format> writer(output, sizeof(output));
    auto                written = writer.write<Counter>(0x1234, {scratch, sizeof(scratch)});
    if (!written) return 1;

    // Partial input reports NEED_MORE_DATA and consumes no incomplete element.
    tlv::reader<Format> reader({output, 4}, tlv::input_mode::incremental);
    auto                incomplete = reader.next();
    if (incomplete || incomplete.error().code != TLV_NEED_MORE_DATA) return 2;
    if (!reader.set_input({output, writer.size()}, 0, tlv::input_mode::final)) return 3;
    auto element = reader.next();
    if (!element) return 4;
    auto counter = element->decode<Counter>();
    if (!counter || *counter != 0x1234 || !reader.at_end()) return 5;

    // Native views still borrow output; conversion does not transfer ownership.
    const auto native = tlv::native::descriptor(*element);
    if (native.value.size != 2 || native.tag.size != 2) return 6;
    std::cout << "Counter: " << *counter << '\n';
}
