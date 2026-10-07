// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

// Allocation regression and reproducible traversal evidence, independent of GoogleTest.
#include "tlv++/tlv.hpp"
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <new>
#include <vector>

namespace {
size_t allocations = 0;
}
void* operator new(size_t size) {
    ++allocations;
    if (void* pointer = std::malloc(size ? size : 1)) return pointer;
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

int main(int argc, char**) {
    const size_t           count = 10000;
    std::vector<tlv::byte> wire(count * 2);
    for (size_t i = 0; i < count; ++i) wire[2 * i] = tlv::byte(1);
    auto parsed = tlv::document::parse({wire.data(), wire.size()}, tlv::fixed_format<1, 1>{});
    if (!parsed) return 1;
    for (int repeat = 0; repeat < 7; ++repeat) {
        const auto   begin = std::chrono::steady_clock::now();
        const size_t before = allocations;
        size_t       seen = 0;
        const auto&  document = *parsed;
        for (auto item : document) seen += item.tag().size();
        const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
                                 std::chrono::steady_clock::now() - begin)
                                 .count();
        if (argc > 1)
            std::printf("%d,%zu,%zu,%lld\n", repeat, seen, allocations - before,
                        static_cast<long long>(elapsed));
        if (seen != count || allocations != before) return 2;
    }
    auto         first = parsed->first();
    auto         copy = first;
    auto         second = first.next();
    const size_t before = allocations;
    first.erase();
    if (first || copy || !second || allocations != before) return 3;
    // Ordinary failure paths and short typed writes must also avoid C++ allocation.
    tlv::byte                            output[16]{};
    tlv::writer<tlv::fixed_format<1, 1>> writer(output, sizeof output);
    using field = tlv::field<tlv::tag_constant<1>, uint16_t, tlv::uint16_be_codec>;
    if (!writer.write<field>(42) || allocations != before) return 4;
    const tlv::byte                      malformed[] = {tlv::byte(1), tlv::byte(8)};
    tlv::reader<tlv::fixed_format<1, 1>> reader({malformed, sizeof malformed});
    auto                                 failed = reader.next();
    if (failed || failed.error().status() != tlv::errc::buffer_too_short || allocations != before)
        return 5;
    return 0;
}
