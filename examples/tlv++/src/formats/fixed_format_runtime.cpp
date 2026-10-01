// Defines a fixed-width TLV format at runtime from tlv++: two tag bytes and a
// one-byte length, using the raw C tlv_fixed_format_t/tlv_fixed_format_init
// through the explicit tlv::native interoperability boundary. See tlv/formats/fixed.h and
// docs/guides/memory.md#format-context-ownership-and-lifetime for why config
// must outlive every reader and writer built from it.
#include <array>
#include <iostream>

#include "tlv/formats/fixed.h"
#include "tlv++/tlv.hpp"
#include "tlv++/native.hpp"

int main() {
    const tlv_fixed_format_t config = {/* tag_size */ 2, /* length_size */ 1,
                                       TLV_BYTE_ORDER_BIG_ENDIAN, TLV_ELEMENT_ORDER_TLV,
                                       TLV_LENGTH_SCOPE_VALUE};
    /* config must outlive every reader and writer built from format. */
    tlv_format_t format;
    if (tlv_fixed_format_init(&format, &config) != TLV_OK) return 1;
    const auto format_view = tlv::native::borrow_format(format);

    std::array<tlv::byte, 16> buf{};
    tlv::writer<>             writer(buf.data(), buf.size(), format_view);

    const std::array<tlv::byte, 3> value = {tlv::byte(0xAA), tlv::byte(0xBB), tlv::byte(0xCC)};
    auto                           written =
        writer.write(tlv::tag_bytes<0x12, 0x34>(), tlv::bytes(value.data(), value.size()));
    if (!written) {
        std::cerr << "write error: " << written.error().message << "\n";
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
