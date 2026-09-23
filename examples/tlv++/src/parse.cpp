// Parses a nested BER-TLV document and prints every element in document
// order. See write.cpp for building the same bytes, query.cpp for
// addressing one field directly, and validate.cpp for checking the
// document's structure without decoding it. The C, Rust and JavaScript
// "parse" examples parse the same bytes and report the same fields.
#include <array>
#include <cstddef>
#include <iomanip>
#include <iostream>

#include "tlv++/tlv.hpp"

// An FCI Template (6F) holding a DF Name (84) and an FCI Proprietary
// Template (A5) holding an Application Label (50).
static const std::array<tlv::byte, 12> document = {
    tlv::byte(0x6F), tlv::byte(0x0A), tlv::byte(0x84), tlv::byte(0x03),
    tlv::byte(0x41), tlv::byte(0x42), tlv::byte(0x43), tlv::byte(0xA5),
    tlv::byte(0x03), tlv::byte(0x50), tlv::byte(0x01), tlv::byte(0x01)};

int main() {
    size_t count = 0;
    auto   result = tlv::walk_tree(
        tlv::bytes(document.data(), document.size()), tlv_reader_format_ber, tlv_ber_is_constructed,
        TLV_WALK_MAX_DEPTH, 16, [&count](const tlv::entry& entry, size_t depth, size_t /*offset*/) {
            std::cout << std::string(depth * 2, ' ') << "tag=" << std::hex << std::uppercase
                      << static_cast<int>(entry.tag.data[0]) << " length=" << std::dec
                      << entry.value.size() << " value=" << std::hex << std::uppercase;
            for (size_t i = 0; i < entry.value.size(); ++i)
                std::cout << std::setw(2) << std::setfill('0') << static_cast<int>(entry.value[i]);
            std::cout << std::dec << "\n";
            ++count;
            return TLV_VISIT_CONTINUE;
        });
    if (!result) {
        std::cerr << "parse error: " << result.error().message << "\n";
        return 1;
    }
    // 6F, its two children (84, A5) and A5's child (50).
    return count == 4 ? 0 : 1;
}
