// Write two primitive BER elements, then iterate over that sequence.
#include <tlv++/tlv.hpp>
#include <array>
#include <iostream>

int main() {
    std::array<tlv::byte, 14> output{};
    auto                      written = tlv::ber::encode(output, [](tlv::writer_builder& writer) {
        writer.write<0x04>("hello");
        writer.write<0x04>("world");
    });
    if (!written) {
        std::cerr << written.error().message() << '\n';
        return 1;
    }

    // Only the written prefix is input; borrowed Values cannot outlive output.
    size_t count = 0;
    try {
        for (auto element : tlv::ber::parse({output.data(), *written})) {
            std::cout << "Value bytes: " << element.value().size() << '\n';
            if (element.tag() != tlv::tag_bytes<0x04>() || element.value().size() != 5) return 2;
            ++count;
        }
    } catch (const tlv::parse_error& failure) {
        std::cerr << failure.what() << '\n';
        return 1;
    }
    return count == 2 && *written == output.size() ? 0 : 2;
}
