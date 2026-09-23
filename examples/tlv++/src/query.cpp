// Addresses the Application Label directly by path, `6F/A5/50`, without
// walking the whole document by hand. See parse.cpp for the document itself.
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
    auto query = tlv::query::parse("6F/A5/50");
    if (!query) {
        std::cerr << "query parse error: " << query.error().message << "\n";
        return 1;
    }

    bool found = false;
    auto result = query->walk(
        tlv::bytes(document.data(), document.size()), tlv_reader_format_ber, tlv_ber_is_constructed,
        TLV_WALK_MAX_DEPTH, 16, [&found](const tlv::entry& entry, size_t /*depth*/, size_t offset) {
            std::cout << "6F/A5/50 = " << std::hex << std::uppercase << std::setw(2)
                      << std::setfill('0') << static_cast<int>(entry.value[0]) << std::dec
                      << " (offset " << offset << ")\n";
            found = entry.value.size() == 1 && entry.value[0] == tlv::byte(0x01);
            return TLV_VISIT_CONTINUE;
        });
    if (!result) {
        std::cerr << "query error: " << result.error().message << "\n";
        return 1;
    }
    return found ? 0 : 1;
}
