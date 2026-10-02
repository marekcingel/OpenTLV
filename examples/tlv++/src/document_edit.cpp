// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

// Own, traverse and edit the canonical C Document through the C++ facade.
#include "tlv++/builtins/asn1/ber.hpp"
#include "tlv++/document/document.hpp"

#include <array>
#include <iostream>
#include <utility>
#include <vector>

int main() {
    const std::array<tlv::byte, 8> input = {{tlv::byte(0x30), tlv::byte(0x03), tlv::byte(0x04),
                                             tlv::byte(0x01), tlv::byte(0x41), tlv::byte(0x04),
                                             tlv::byte(0x01), tlv::byte(0x42)}};
    auto parsed = tlv::document::parse(tlv::bytes(input.data(), input.size()),
                                       tlv::document_format(tlv::ber::format{}));
    if (!parsed) return 1;
    auto   document = std::move(*parsed);
    size_t roots = 0;
    size_t children = 0;
    for (auto node : document) {
        ++roots;
        for (auto child : node.children()) {
            ++children;
            if (child.parent() != node) return 2;
        }
    }
    if (roots != 2 || children != 1) return 3;
    auto container = document.find(tlv::tag_bytes<0x30>());
    auto old_child = container.find(tlv::tag_bytes<0x04>());
    auto retained_copy = old_child;
    old_child.erase();
    if (retained_copy) return 4;
    const std::array<tlv::byte, 1> payload = {{tlv::byte(0x43)}};
    auto                           inserted =
        container.insert(tlv::tag_bytes<0x04>(), tlv::bytes(payload.data(), payload.size()));
    if (!inserted || inserted->parent() != container) return 5;
    const std::vector<tlv::byte> expected = {tlv::byte(0x30), tlv::byte(0x03), tlv::byte(0x04),
                                             tlv::byte(0x01), tlv::byte(0x43), tlv::byte(0x04),
                                             tlv::byte(0x01), tlv::byte(0x42)};
    auto                         encoded = document.encode();
    if (!encoded || *encoded != expected) return 6;
    std::cout << "Traversed and edited an owning Document; erased copies are invalid.\n";
}
