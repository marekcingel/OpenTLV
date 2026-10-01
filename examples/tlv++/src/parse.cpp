// Advanced borrowed Visitor traversal: parses a nested BER-TLV document and prints every element in
// document order. See write.cpp for building the same bytes, query.cpp for addressing one field
// directly, and validate.cpp for checking the document's structure without decoding it. The C, Rust
// and JavaScript "parse" examples parse the same bytes and report the same fields.
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
    // Borrowed traversal uses two caller-owned frames for this tree's depth.
    tlv::tree_frame  frames[2]{};
    tlv::tree_reader reader({document.data(), document.size()}, tlv::ber::format{}, {frames, 2}, 2,
                            16);
    size_t           count = 0;
    auto             result =
        reader.visit([&count](const tlv::element_view& element, size_t depth, size_t /*offset*/) {
            std::cout << std::string(depth * 2, ' ') << "tag=" << std::hex;
            for (auto byte : element.tag())
                std::cout << std::setw(2) << std::setfill('0') << static_cast<unsigned>(byte);
            std::cout << " value=";
            for (auto byte : element.value())
                std::cout << std::setw(2) << std::setfill('0') << static_cast<unsigned>(byte);
            std::cout << std::dec << '\n';
            ++count;
            return TLV_VISIT_CONTINUE;
        });
    if (!result) {
        std::cerr << "Parse error: " << result.error().message << '\n';
        return 1;
    }
    return count == 4 ? 0 : 2;
}
