#include "tlv++/tlv.hpp"
#include <algorithm>
#include <iostream>

// One Value type can have several explicit encodings; identifiers are byte sequences.
using Counter = tlv::field<tlv::tag_constant<0x9F, 0x36>, uint16_t, tlv::uint16_be_codec>;
using Format = tlv::fixed_format<2, 1, TLV_BYTE_ORDER_BIG_ENDIAN>;

int main() {
    tlv::byte           output[5]{};
    tlv::byte           scratch[2]{};
    tlv::writer<Format> writer(output, sizeof(output));
    auto                written = writer.write<Counter>(0x1234, {scratch, sizeof(scratch)});
    if (!written) return 1;
    const tlv::byte expected[] = {static_cast<tlv::byte>(0x9F), static_cast<tlv::byte>(0x36),
                                  static_cast<tlv::byte>(2), static_cast<tlv::byte>(0x12),
                                  static_cast<tlv::byte>(0x34)};
    if (writer.size() != sizeof(expected) || !std::equal(expected, expected + 5, output)) return 2;
    tlv::reader<Format> reader(tlv::bytes(output, writer.size()));
    auto                element = reader.next();
    if (!element) return 3;
    auto counter = element->decode<Counter>();
    if (!counter || *counter != 0x1234) return 4;

#if OPENTLV_DOCUMENT
    auto document =
        tlv::document::parse({output, writer.size()}, tlv::document_format(Format::format()));
    if (!document) return 5;
    auto owned_counter = document->get<Counter>();
    if (!owned_counter || *owned_counter != *counter) return 6;
#endif
    std::cout << "Counter: " << *counter << '\n';
    return 0;
}
