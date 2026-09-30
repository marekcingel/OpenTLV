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
    size_t            count = 0;
    tlv_tree_frame_t  frames[TLV_TREE_DEFAULT_DEPTH];
    tlv_tree_reader_t reader;
    if (tlv_tree_reader_init(&reader, reinterpret_cast<const uint8_t*>(document.data()),
                             document.size(), &tlv_format_ber, frames, TLV_TREE_DEFAULT_DEPTH,
                             TLV_TREE_DEFAULT_DEPTH, 16) != TLV_OK)
        return 1;
    auto result = tlv::visit_tree(
        reader, [&count](const tlv::element& element, size_t depth, size_t /*offset*/) {
            std::cout << std::string(depth * 2, ' ') << "tag=" << std::hex << std::uppercase
                      << static_cast<int>(element.tag.data[0]) << " length=" << std::dec
                      << element.value.size << " value=" << std::hex << std::uppercase;
            for (size_t i = 0; i < element.value.size; ++i)
                std::cout << std::setw(2) << std::setfill('0')
                          << static_cast<int>(element.value.data[i]);
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
