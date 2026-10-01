#include <tlv++/tlv.hpp>
#include <iostream>

int main() {
    // Elements borrow input; keep it alive while using them.
    const tlv::byte input[] = {tlv::byte(0x04), tlv::byte(0x03), tlv::byte('A'), tlv::byte('B'),
                               tlv::byte('C')};
    try {
        for (auto element : tlv::ber::parse({input, sizeof(input)})) {
            std::cout << "Value bytes: " << element.value().size() << '\n';
        }
    } catch (const tlv::parse_error& failure) {
        std::cerr << "Parse error at " << failure.offset() << ": " << failure.what() << '\n';
        return 1;
    }
}
