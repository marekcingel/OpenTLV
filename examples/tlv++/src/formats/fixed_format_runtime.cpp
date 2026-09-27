// Defines a fixed-width TLV format at runtime from tlv++: two tag bytes and a
// one-byte length, using the raw C tlv_fixed_format_t/tlv_fixed_format_init
// directly (no tlv++ wrapper is needed: tlv::writer/tlv::reader already take
// a plain `const tlv_format_t&`). See tlv/formats/fixed.h and
// docs/guides/memory.md#format-context-ownership-and-lifetime for why config
// must outlive every reader and writer built from it.
#include <array>
#include <iostream>

#include "tlv/formats/fixed.h"
#include "tlv++/tlv.hpp"

int main() {
    const tlv_fixed_format_t config = {/* tag_size */ 2, /* length_size */ 1,
                                       TLV_BYTE_ORDER_BIG_ENDIAN};
    /* config must outlive every reader and writer built from format. */
    tlv_format_t format;
    if (tlv_fixed_format_init(&format, &config) != TLV_OK) return 1;

    std::array<tlv::byte, 16> buf{};
    tlv::writer               writer(buf.data(), buf.size(), format);

    const std::array<tlv::byte, 3> value = {tlv::byte(0xAA), tlv::byte(0xBB), tlv::byte(0xCC)};
    auto written = writer.write(TLV_TAG(0x12, 0x34), tlv::bytes(value.data(), value.size()));
    if (!written) {
        std::cerr << "write error: " << written.error().message << "\n";
        return 1;
    }

    // Wire bytes: 12 34 03 AA BB CC. The tag is kept as is; the length is one byte.
    tlv::reader reader(tlv::bytes(buf.data(), writer.size()), format);
    auto        entry = reader.next();
    if (!entry) {
        std::cerr << "read error: " << entry.error().message << "\n";
        return 1;
    }
    std::cout << "wrote " << writer.size() << " bytes, read a " << entry->value.size()
              << "-byte value\n";
    return entry->value.size() == value.size() ? 0 : 1;
}
