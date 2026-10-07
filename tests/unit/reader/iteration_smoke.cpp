// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

// Independent of GoogleTest's minimum C++ standard: exercises C++11 range returns
// with copy elision disabled and observes allocations across successful processing.
#include "tlv++/reader/reader.hpp"
#include "tlv++/query/query.hpp"
#include "tlv++/formats/fixed_format.hpp"
#include "custom_cpp_format.hpp"
#include <cstdlib>
#include <new>

namespace {
bool   observe_allocations = false;
size_t allocation_count = 0;

struct moving_format : custom_cpp_format {
    moving_format() {
        trailer = 0xEE;
    }
    moving_format(moving_format&& other) : custom_cpp_format(other) {
        other.trailer = 0;
    }
    moving_format(const moving_format&) = delete;
};

auto custom_range(tlv::bytes data) -> decltype(tlv::parse(data, moving_format{})) {
    auto range = tlv::parse(data, moving_format{});
    return range;
}
} // namespace

void* operator new(size_t size) {
    if (observe_allocations) ++allocation_count;
    if (auto* result = std::malloc(size ? size : 1)) return result;
    throw std::bad_alloc();
}
void* operator new[](size_t size) {
    return ::operator new(size);
}
void operator delete(void* pointer) noexcept {
    std::free(pointer);
}
void operator delete[](void* pointer) noexcept {
    std::free(pointer);
}
#if __cplusplus >= 201402L
void operator delete(void* pointer, size_t) noexcept {
    std::free(pointer);
}
void operator delete[](void* pointer, size_t) noexcept {
    std::free(pointer);
}
#endif

int main() {
    const uint8_t    data[] = {1, 1, 42, 0xEE, 2, 0, 0xEE};
    const tlv::bytes input(reinterpret_cast<const tlv::byte*>(data), sizeof(data));
    observe_allocations = true;
    size_t count = 0;
    for (auto element : custom_range(input)) {
        if (element.tag() != (count == 0 ? tlv::tag_bytes<1>() : tlv::tag_bytes<2>())) return 1;
        if (element.value().size() != (count == 0 ? 1u : 0u)) return 2;
        if (count == 0 && element.value().data() != input.data() + 2) return 3;
        ++count;
    }
    if (count != 2) return 4;
    auto original = custom_range(input);
    if (original.begin()->tag() != tlv::tag_bytes<1>()) return 5;
    auto moved = std::move(original);
    if (moved.begin()->tag() != tlv::tag_bytes<2>()) return 6;
    if (moved.begin() != moved.end()) return 7;

    const uint8_t    fixed_data[] = {1, 1, 42, 2, 0};
    const tlv::bytes fixed_input(reinterpret_cast<const tlv::byte*>(fixed_data),
                                 sizeof(fixed_data));
    tlv::reader<tlv::fixed_format<1, 1, tlv::byte_order::big_endian>> reader(fixed_input);
    count = 0;
    for (auto element : reader) {
        if (element.tag() != (count == 0 ? tlv::tag_bytes<1>() : tlv::tag_bytes<2>())) return 8;
        ++count;
    }
    if (count != 2) return 9;
    tlv::fixed_format<1, 1, tlv::byte_order::big_endian> config;
    tlv::tree_frame                                      frames[1]{};
    tlv::tree_reader tree(fixed_input, config.view(), {frames, 1}, 1, 10);
    auto             selected = tree.select("02");
    auto             selection = std::move(selected);
    count = 0;
    for (auto item : selection) {
        if (item.element.tag() != tlv::tag_bytes<2>() || item.offset != 3) return 11;
        ++count;
    }
    observe_allocations = false;
    if (count != 1) return 12;
    return allocation_count == 0 ? 0 : 10;
}
