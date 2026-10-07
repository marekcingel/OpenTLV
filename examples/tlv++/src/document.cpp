// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

// Parse an owning Document and traverse roots and their children.
#include <tlv++/tlv.hpp>
#include <iostream>

int main() {
    const tlv::byte input[] = {tlv::byte(0x30), tlv::byte(0x03), tlv::byte(0x04), tlv::byte(0x01),
                               tlv::byte('A'),  tlv::byte(0x04), tlv::byte(0x01), tlv::byte('B')};
    auto            document =
        tlv::document::parse({input, sizeof(input)}, tlv::document_format(tlv::ber::format{}));
    if (!document) {
        std::cerr << document.error().message() << '\n';
        return 1;
    }
    // Document owns its data; Nodes borrow this Document and cannot outlive it.
    size_t roots = 0, children = 0;
    for (auto node : *document) {
        std::cout << "Root Value bytes: " << node.value().size() << '\n';
        ++roots;
        for (auto child : node.children()) {
            std::cout << "  Child Value bytes: " << child.value().size() << '\n';
            ++children;
        }
    }
    return roots == 2 && children == 1 ? 0 : 2;
}
